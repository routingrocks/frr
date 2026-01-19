// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Conditional Disaggregation
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 */

#include <zebra.h>

#include "prefix.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_conditional_disagg.h"

/*
 * Conditional Disaggregation: Generate SAFI_UNICAST route when SAFI_UNREACH
 * route is received with matching SoO extended community.
 *
 * This allows a leaf to automatically disaggregate specific prefixes when it
 * receives unreachability notifications for prefixes within its own anycast group.
 *
 * Note on silent returns: UNREACH routes are received by all peers in the fabric.
 * Only peers in the same anycast group (matching SoO) should act on them.
 * SoO mismatch is expected for most receivers and would cause excessive logging.
 */
void bgp_conditional_disagg_add(struct bgp *bgp, const struct prefix *p, struct bgp_path_info *pi,
				afi_t afi, safi_t safi, struct peer *peer)
{
	/* Only process SAFI_UNREACH routes */
	if (safi != SAFI_UNREACH)
		return;

	/* peer must be valid */
	if (!peer)
		return;

	/* Skip locally originated UNREACH - only process received routes */
	if (peer == bgp->peer_self)
		return;

	/* Local SoO must be configured */
	if (!bgp->soo_source_ip_set || !bgp->per_source_nhg_soo || !pi->attr) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG ADD: Local SoO not configured for %pFX",
				   p);
		return;
	}

	/* UNREACH route must carry SoO extended community */
	if (!route_has_soo_attr(pi)) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG ADD: UNREACH %pFX from %s has no SoO",
				   p, peer->host);
		return;
	}

	/* SoO mismatch means different anycast group - skip silently (expected, not an error) */
	if (!route_matches_soo(pi, bgp->per_source_nhg_soo))
		return;

	/* Look up the EXACT prefix in SAFI_UNICAST table (exact match, not longest-prefix-match).
	 * The route must already exist (e.g., connected, static, or from aggregate).
	 * We don't create routes - we only mark existing ones to bypass suppression.
	 * No match is expected if this peer doesn't have the prefix - skip silently. */
	if (!bgp->rib[afi][SAFI_UNICAST])
		return;

	struct bgp_dest *dest_unicast = bgp_node_lookup(bgp->rib[afi][SAFI_UNICAST], p);
	if (!dest_unicast)
		return;

	/* Mark all path_info entries with BGP_PATH_CONDITIONAL_DISAGG flag.
	 * This flag bypasses aggregate summary-only suppression. */
	struct bgp_path_info *pi_unicast;
	int marked_count = 0;
	for (pi_unicast = bgp_dest_get_bgp_path_info(dest_unicast); pi_unicast;
	     pi_unicast = pi_unicast->next) {
		if (!CHECK_FLAG(pi_unicast->flags, BGP_PATH_CONDITIONAL_DISAGG)) {
			SET_FLAG(pi_unicast->flags, BGP_PATH_CONDITIONAL_DISAGG);
			SET_FLAG(pi_unicast->flags, BGP_PATH_ATTR_CHANGED);
			marked_count++;
			bgp_process(bgp, dest_unicast, pi_unicast, afi, SAFI_UNICAST);
		}
	}

	if (BGP_DEBUG(update, UPDATE_IN) && marked_count)
		zlog_debug("CONDITIONAL DISAGG ADD: Marked %d paths for %pFX from peer %s",
			   marked_count, p, peer->host);

	bgp_dest_unlock_node(dest_unicast);
}

/*
 * Conditional Disaggregation: Clear BGP_PATH_CONDITIONAL_DISAGG flag when
 * SAFI_UNREACH route is withdrawn.
 *
 * Note: UNREACH withdrawal NLRIs do NOT carry SoO extended community (BGP constraint).
 * We look up matching SAFI_UNICAST routes that have BGP_PATH_CONDITIONAL_DISAGG flag
 * set and clear it, allowing aggregate suppression to take effect again.
 * No SoO matching is needed here - we simply undo any previous disaggregation.
 */
void bgp_conditional_disagg_withdraw(struct bgp *bgp, const struct prefix *p,
				     struct bgp_path_info *pi, afi_t afi, safi_t safi,
				     struct peer *peer)
{
	/* Only process SAFI_UNREACH routes */
	if (safi != SAFI_UNREACH)
		return;

	/* peer must be valid */
	if (!peer)
		return;

	/* Skip locally originated UNREACH - only process received routes */
	if (peer == bgp->peer_self)
		return;

	/* Look up the prefix in SAFI_UNICAST table. No match is expected if
	 * this peer doesn't have the prefix or never disaggregated it - skip silently. */
	if (!bgp->rib[afi][SAFI_UNICAST])
		return;

	struct bgp_dest *dest_unicast = bgp_node_lookup(bgp->rib[afi][SAFI_UNICAST], p);
	if (!dest_unicast)
		return;

	/* Find path_info entries and clear BGP_PATH_CONDITIONAL_DISAGG flag */
	struct bgp_path_info *pi_unicast;
	int cleared_count = 0;
	for (pi_unicast = bgp_dest_get_bgp_path_info(dest_unicast); pi_unicast;
	     pi_unicast = pi_unicast->next) {
		if (CHECK_FLAG(pi_unicast->flags, BGP_PATH_CONDITIONAL_DISAGG)) {
			UNSET_FLAG(pi_unicast->flags, BGP_PATH_CONDITIONAL_DISAGG);
			cleared_count++;

			/* Now that the conditional disagg flag is cleared, we need to re-apply
			 * aggregate suppression. The route was never added to aggr_suppressors
			 * list because aggr_suppress_path() returned early when the flag was set.
			 * Walk the aggregate table to find covering aggregates and add route
			 * to their suppressor lists. This is a surgical operation that only
			 * modifies suppression state without touching aggregate counts/attributes. */
			struct bgp_table *aggregate_table = bgp->aggregate[afi][SAFI_UNICAST];
			if (aggregate_table && bgp_table_top_nolock(aggregate_table)) {
				struct bgp_dest *aggr_dest;
				struct bgp_dest *child = bgp_node_get(aggregate_table, p);

				/* Walk up the aggregate tree to find covering aggregates */
				for (aggr_dest = child; aggr_dest;
				     aggr_dest = bgp_dest_parent_nolock(aggr_dest)) {
					const struct prefix *aggr_p = bgp_dest_get_prefix(aggr_dest);
					struct bgp_aggregate *aggregate =
						bgp_dest_get_bgp_aggregate_info(aggr_dest);

					/* Found an aggregate that covers this prefix */
					if (aggregate && aggr_p->prefixlen < p->prefixlen) {
						/* Check if route should be suppressed by this aggregate.
						 * Note: aggr_suppress_path only adds to suppressors list,
						 * it does NOT modify aggregate counts or attributes. */
						if (aggregate->summary_only &&
						    AGGREGATE_MED_VALID(aggregate)) {
							aggr_suppress_path(aggregate, pi_unicast);
						}

						/* Also check suppress-map if configured */
						if (aggregate->suppress_map_name &&
						    AGGREGATE_MED_VALID(aggregate) &&
						    aggr_suppress_map_test(bgp, aggregate,
									   pi_unicast)) {
							aggr_suppress_path(aggregate, pi_unicast);
						}
					}
				}
				bgp_dest_unlock_node(child);
			}

			/* Now set attr changed and trigger re-processing to withdraw the route */
			SET_FLAG(pi_unicast->flags, BGP_PATH_ATTR_CHANGED);
			bgp_process(bgp, dest_unicast, pi_unicast, afi, SAFI_UNICAST);
		}
	}

	if (BGP_DEBUG(update, UPDATE_IN) && cleared_count)
		zlog_debug("CONDITIONAL DISAGG WITHDRAW: Cleared %d paths for %pFX from peer %s",
			   cleared_count, p, peer->host);

	bgp_dest_unlock_node(dest_unicast);
}

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
 */
void bgp_conditional_disagg_add(struct bgp *bgp, const struct prefix *p, struct bgp_path_info *pi,
				afi_t afi, struct peer *peer)
{
	struct ecommunity *ecom;

	if (BGP_DEBUG(update, UPDATE_IN))
		zlog_debug("CONDITIONAL DISAGG ADD: Called for prefix %pFX from peer %s", p,
			   peer->host);

	/* Only process UNREACH routes received from external peers, not locally originated */
	if (peer == bgp->peer_self) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG ADD: Ignoring locally originated UNREACH route for %pFX",
				   p);
		return;
	}

	/* Verify NLRI parsing succeeded - pi->extra->unreach should exist */
	if (!pi->extra || !pi->extra->unreach) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug(
				"CONDITIONAL DISAGG ADD: NLRI parsing failed or unreach data missing");
		return;
	}

	/* Check prerequisites */
	if (!bgp->soo_source_ip_set || !bgp->per_source_nhg_soo || !pi->attr) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG ADD: Prerequisites not met (soo_source_ip_set=%d, per_source_nhg_soo=%p, attr=%p)",
				   bgp->soo_source_ip_set, bgp->per_source_nhg_soo, pi->attr);
		return;
	}

	ecom = bgp_attr_get_ecommunity(pi->attr);

	/* No extended community present - don't originate */
	if (!ecom) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG ADD: No extended community present");
		return;
	}

	/* Check if SAFI_UNREACH route has SoO matching our local soo-source */
	if (!soo_in_ecom(ecom, bgp->per_source_nhg_soo)) {
		if (BGP_DEBUG(update, UPDATE_IN)) {
			char *ecom_str = ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_COMMUNITY_LIST,
							     0);
			char *local_soo_str = ecommunity_ecom2str(bgp->per_source_nhg_soo,
								  ECOMMUNITY_FORMAT_COMMUNITY_LIST,
								  0);
			zlog_debug("CONDITIONAL DISAGG ADD: SoO does not match. Received ecomm=%s, local soo=%s",
				   ecom_str, local_soo_str);
			XFREE(MTYPE_ECOMMUNITY_STR, ecom_str);
			XFREE(MTYPE_ECOMMUNITY_STR, local_soo_str);
		}
		return;
	}

	if (BGP_DEBUG(update, UPDATE_IN))
		zlog_debug("CONDITIONAL DISAGG ADD: All checks passed, SoO match confirmed");

	/* Look up the EXACT prefix in SAFI_UNICAST table (exact match, not longest-prefix-match).
	 * The route must already exist (e.g., connected, static, or from aggregate).
	 * We don't create routes - we only mark existing ones to bypass suppression. */
	if (BGP_DEBUG(update, UPDATE_IN))
		zlog_debug("CONDITIONAL DISAGG ADD: Looking up EXACT match for UNREACH prefix %pFX in UNICAST table",
			   p);

	struct bgp_dest *dest_unicast = bgp_node_lookup(bgp->rib[afi][SAFI_UNICAST], p);
	if (!dest_unicast) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG ADD: No existing SAFI_UNICAST route for %pFX - cannot disaggregate non-existent route",
				   p);
		return;
	}

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
			if (BGP_DEBUG(update, UPDATE_IN))
				zlog_debug("CONDITIONAL DISAGG ADD: Marked %pFX (path %d, peer %s, origin %d) with BGP_PATH_CONDITIONAL_DISAGG and BGP_PATH_ATTR_CHANGED flags",
					   p, marked_count,
					   pi_unicast->peer ? pi_unicast->peer->host : "NULL",
					   pi_unicast->attr ? pi_unicast->attr->origin : -1);

			/* Trigger BGP decision process to re-evaluate and advertise this route */
			bgp_process(bgp, dest_unicast, pi_unicast, afi, SAFI_UNICAST);
			if (BGP_DEBUG(update, UPDATE_OUT))
				zlog_debug("CONDITIONAL DISAGG ADD: Triggered bgp_process to advertise %pFX",
					   p);
		}
	}

	bgp_dest_unlock_node(dest_unicast);
}

/*
 * Conditional Disaggregation: Clear BGP_PATH_CONDITIONAL_DISAGG flag when
 * SAFI_UNREACH route is withdrawn.
 *
 * Note: UNREACH NLRI withdrawals do NOT carry SoO extended community.
 * We simply clear the BGP_PATH_CONDITIONAL_DISAGG flag from any matching
 * SAFI_UNICAST route, allowing it to be suppressed again by aggregates.
 */
void bgp_conditional_disagg_withdraw(struct bgp *bgp, const struct prefix *p,
				     struct bgp_path_info *pi, afi_t afi, struct peer *peer)
{
	if (BGP_DEBUG(update, UPDATE_IN))
		zlog_debug("CONDITIONAL DISAGG WITHDRAW: Called for prefix %pFX from peer %s", p,
			   peer->host);

	/* Only process UNREACH routes received from external peers, not locally originated */
	if (peer == bgp->peer_self) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG WITHDRAW: Ignoring locally originated UNREACH route for %pFX",
				   p);
		return;
	}

	/* Check basic prerequisites - just verify this is SAFI_UNREACH withdrawal */
	if (!pi->extra || !pi->extra->unreach)
		return;

	/* Look up the prefix in SAFI_UNICAST table */
	struct bgp_dest *dest_unicast = bgp_node_lookup(bgp->rib[afi][SAFI_UNICAST], p);
	if (!dest_unicast) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("CONDITIONAL DISAGG WITHDRAW: No existing SAFI_UNICAST route found for %pFX",
				   p);
		return;
	}

	/* Find path_info entries and clear BGP_PATH_CONDITIONAL_DISAGG flag */
	struct bgp_path_info *pi_unicast;
	int cleared_count = 0;
	for (pi_unicast = bgp_dest_get_bgp_path_info(dest_unicast); pi_unicast;
	     pi_unicast = pi_unicast->next) {
		if (CHECK_FLAG(pi_unicast->flags, BGP_PATH_CONDITIONAL_DISAGG)) {
			UNSET_FLAG(pi_unicast->flags, BGP_PATH_CONDITIONAL_DISAGG);
			SET_FLAG(pi_unicast->flags, BGP_PATH_ATTR_CHANGED);
			cleared_count++;
			if (BGP_DEBUG(update, UPDATE_IN))
				zlog_debug("CONDITIONAL DISAGG WITHDRAW: Cleared BGP_PATH_CONDITIONAL_DISAGG flag from %pFX (path %d, peer %s, origin %d)",
					   p, cleared_count,
					   pi_unicast->peer ? pi_unicast->peer->host : "NULL",
					   pi_unicast->attr ? pi_unicast->attr->origin : -1);

			/* Trigger re-processing to re-suppress and withdraw */
			bgp_process(bgp, dest_unicast, pi_unicast, afi, SAFI_UNICAST);
			if (BGP_DEBUG(update, UPDATE_OUT))
				zlog_debug("CONDITIONAL DISAGG WITHDRAW: Triggered bgp_process for %pFX",
					   p);
		}
	}

	bgp_dest_unlock_node(dest_unicast);
}

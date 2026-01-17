// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information VTY commands
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "json.h"
#include "vty.h"
#include <time.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_unreach.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_zebra.h"

/* Forward declaration */
extern void bgp_unreach_vty_init(void);

#include "bgpd/bgp_unreach_vty_clippy.c"

DEFPY_HIDDEN(
	bgp_inject_unreachability, bgp_inject_unreachability_cmd,
	"bgp inject unreachability <ipv4|ipv6>$afi_str <A.B.C.D/M|X:X::X:X/M>$prefix_str [reason-code <unspecified|policy-blocked|security-filtered|rpki-invalid|no-export-policy|martian-address|bogon-prefix|route-dampening|local-admin-action|local-link-down|(0-65535)>$reason_str]",
	BGP_STR "Inject test data\n"
		"Unreachability information\n"
		"IPv4\n"
		"IPv6\n"
		"IPv4 prefix\n"
		"IPv6 prefix\n"
		"Unreachability Reason Code (Sub-TLV Type 1)\n"
		"Unspecified reason (0)\n"
		"Blocked by policy (1)\n"
		"Filtered for security reasons (2)\n"
		"RPKI validation failed (3)\n"
		"No export policy (4)\n"
		"Martian address (5)\n"
		"Bogon prefix (6)\n"
		"Route dampening (7)\n"
		"Local administrative action (8)\n"
		"Local link down (9)\n"
		"Numeric reason code value\n")
{
	struct bgp *bgp;
	struct bgp_unreach_nlri unreach;
	afi_t afi;

	bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "%% No BGP process configured\n");
		return CMD_WARNING;
	}

	afi = bgp_vty_afi_from_str(afi_str);
	if (afi == AFI_MAX)
		return CMD_WARNING;

	/* Build unreachability NLRI */
	memset(&unreach, 0, sizeof(unreach));
	prefix_copy(&unreach.prefix, prefix_str);

	/* Reporter TLV (Type 1): Contains Reporter ID + Reporter AS + Sub-TLVs
	 * Auto-populated from local BGP instance */
	unreach.reporter = bgp->router_id;
	unreach.has_reporter = true;
	unreach.reporter_as = bgp->as;
	unreach.has_reporter_as = true;

	/* Sub-TLV Type 1: Reason Code (defaults to UNSPECIFIED if not provided) */
	if (reason_str) {
		if (bgp_unreach_reason_str2code(reason_str, &unreach.reason_code) < 0) {
			char *endptr;
			long code = strtol(reason_str, &endptr, 10);
			if (*endptr != '\0' || code < 0 || code > 65535) {
				vty_out(vty, "%% Invalid reason code: %s\n", reason_str);
				return CMD_WARNING;
			}
			unreach.reason_code = (uint16_t)code;
			/* Reserved ranges per draft-tantsura-idr-unreachability-safi:
			 * 0-9: Standard codes, 10-64511: Reserved, 64512-65534: Private-Use, 65535: Reserved
			 */
			if ((unreach.reason_code >= 10 && unreach.reason_code <= 64511) ||
			    unreach.reason_code == 65535) {
				vty_out(vty, "%% Reason code %u is reserved\n", unreach.reason_code);
				return CMD_WARNING;
			}
		}
	} else {
		unreach.reason_code = BGP_UNREACH_REASON_UNSPECIFIED;
	}
	unreach.has_reason_code = true;

	/* Sub-TLV Type 2: Timestamp (ALWAYS attached) */
	unreach.timestamp = time(NULL);
	unreach.has_timestamp = true;

	/* Add to UI-RIB */
	if (bgp_unreach_info_add(bgp, afi, &unreach, NULL) < 0) {
		vty_out(vty, "%% Failed to inject unreachability info\n");
		return CMD_WARNING;
	}

	char reporter_str[INET_ADDRSTRLEN];
	const char *reason_name = bgp_unreach_reason_str(unreach.reason_code);
	inet_ntop(AF_INET, &unreach.reporter, reporter_str, sizeof(reporter_str));
	vty_out(vty, "Injected unreachability for %pFX (reporter: %s, reason-code: %u (%s))\n",
		prefix_str, reporter_str, unreach.reason_code, reason_name);

	zlog_info("Injected unreachability for %pFX (reason: %u - %s)", prefix_str,
		  unreach.reason_code, reason_name);

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(no_bgp_inject_unreachability, no_bgp_inject_unreachability_cmd,
	     "no bgp inject unreachability <ipv4|ipv6>$afi_str <A.B.C.D/M|X:X::X:X/M>$prefix_str",
	     NO_STR BGP_STR "Remove injected data\n"
			    "Unreachability information\n"
			    "IPv4\n"
			    "IPv6\n"
			    "IPv4 prefix\n"
			    "IPv6 prefix\n")
{
	struct bgp *bgp;
	afi_t afi;

	bgp = bgp_get_default();
	if (!bgp) {
		vty_out(vty, "%% No BGP process configured\n");
		return CMD_WARNING;
	}

	afi = bgp_vty_afi_from_str(afi_str);
	if (afi == AFI_MAX)
		return CMD_WARNING;

	zlog_info("Removed injected unreachability for %pFX", prefix_str);

	/* Remove from UI-RIB */
	bgp_unreach_info_delete(bgp, afi, prefix_str);

	vty_out(vty, "Removed unreachability for %pFX\n", prefix_str);

	return CMD_SUCCESS;
}

DEFPY(bgp_unreach_advertise_match, bgp_unreach_advertise_match_cmd,
      "bgp advertise-unreach interfaces-match <A.B.C.D/M|X:X::X:X/M>$prefix",
      BGP_STR "Advertise UNREACH NLRI\n"
	      "Match interface addresses\n"
	      "IPv4 prefix\n"
	      "IPv6 prefix\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	if (safi != SAFI_UNREACH) {
		vty_out(vty, "%% Command only valid in unreachability address-family context\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Verify prefix family matches address-family context */
	if ((afi == AFI_IP && prefix->family != AF_INET) ||
	    (afi == AFI_IP6 && prefix->family != AF_INET6)) {
		vty_out(vty, "%% Prefix family does not match address-family context\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check if already configured */
	if (bgp->unreach_adv_prefix[afi]) {
		if (prefix_same(prefix, bgp->unreach_adv_prefix[afi])) {
			return CMD_SUCCESS;
		}

		vty_out(vty, "%% UNREACH advertisement filter already configured: %pFX\n",
			bgp->unreach_adv_prefix[afi]);
		vty_out(vty,
			"%% Please remove it first with 'no bgp advertise-unreach interfaces-match'\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bgp->unreach_adv_prefix[afi] = prefix_new();
	prefix_copy(bgp->unreach_adv_prefix[afi], prefix);

	if (bgp_debug_zebra(prefix))
		zlog_debug("BGP: Set UNREACH advertisement filter for %s to %pFX",
			   afi == AFI_IP ? "IPv4" : "IPv6", prefix);

	/* Walk BGP interface cache and create UNREACH for matching cached addresses */
	struct vrf *vrf = bgp_vrf_lookup_by_instance_type(bgp);
	if (vrf) {
		struct interface *ifp;
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct bgp_interface *iifp = ifp->info;
			if (iifp && iifp->cached_addresses) {
				struct listnode *addr_node;
				struct prefix *cached_pfx;
				/* coverity[non_const_printf_format_string] - listcount macro is safe */
				for (ALL_LIST_ELEMENTS_RO(iifp->cached_addresses, addr_node,
							  cached_pfx)) {
					if (cached_pfx->family == prefix->family &&
					    prefix_match(prefix, cached_pfx)) {
						bgp_unreach_zebra_announce(bgp, ifp, cached_pfx,
									   false);
						if (bgp_debug_zebra(cached_pfx))
							zlog_debug("BGP: Created UNREACH for cached address %pFX on %s (matches new filter)",
								   cached_pfx, ifp->name);
					}
				}
			}
		}
	}

	/* Trigger announcement of UNREACH routes to peers */
	struct peer *peer;
	struct listnode *node;
	/* coverity[non_const_printf_format_string] - listcount macro is safe */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer))
		bgp_announce_route(peer, afi, SAFI_UNREACH, false);

	return CMD_SUCCESS;
}

DEFPY(no_bgp_unreach_advertise_match, no_bgp_unreach_advertise_match_cmd,
      "no bgp advertise-unreach interfaces-match [<A.B.C.D/M|X:X::X:X/M>$prefix]",
      NO_STR BGP_STR "Advertise UNREACH NLRI\n"
		     "Match interface addresses\n"
		     "IPv4 prefix\n"
		     "IPv6 prefix\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	afi_t afi = bgp_node_afi(vty);
	safi_t safi = bgp_node_safi(vty);

	if (safi != SAFI_UNREACH) {
		vty_out(vty, "%% Command only valid in unreachability address-family context\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Remove configuration - prefix parameter ignored if provided */
	if (!bgp->unreach_adv_prefix[afi]) {
		return CMD_SUCCESS;
	}

	prefix_free(&bgp->unreach_adv_prefix[afi]);
	bgp->unreach_adv_prefix[afi] = NULL;

	if (bgp_debug_zebra(NULL))
		zlog_debug("BGP: Removed UNREACH advertisement filter for %s",
			   afi == AFI_IP ? "IPv4" : "IPv6");

	/* Delete all self-originated UNREACH routes from local RIB */
	struct bgp_table *table = bgp->rib[afi][SAFI_UNREACH];
	if (table) {
		struct bgp_dest *dest, *next_dest;
		struct bgp_path_info *pi, *next;

		for (dest = bgp_table_top(table); dest; dest = next_dest) {
			const struct prefix *dest_p = bgp_dest_get_prefix(dest);
			next_dest = bgp_route_next(dest);

			for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = next) {
				next = pi->next;

				if (pi->peer == bgp->peer_self) {
					if (bgp_debug_zebra(dest_p))
						zlog_debug("BGP: Deleting self-originated UNREACH %pFX (filter removed)",
							   dest_p);

					bgp_rib_remove(dest, pi, bgp->peer_self, afi, SAFI_UNREACH);
					break;
				}
			}
		}
	}

	return CMD_SUCCESS;
}

void bgp_unreach_vty_init(void)
{
	/* Inject commands for testing - available at enable mode like clear bgp */
	install_element(ENABLE_NODE, &bgp_inject_unreachability_cmd);
	install_element(ENABLE_NODE, &no_bgp_inject_unreachability_cmd);

	/* Configuration commands - available in UNREACH address-family nodes */
	install_element(BGP_IPV4U_NODE, &bgp_unreach_advertise_match_cmd);
	install_element(BGP_IPV6U_NODE, &bgp_unreach_advertise_match_cmd);
	install_element(BGP_IPV4U_NODE, &no_bgp_unreach_advertise_match_cmd);
	install_element(BGP_IPV6U_NODE, &no_bgp_unreach_advertise_match_cmd);
}

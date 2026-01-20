// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Conditional Disaggregation
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 */

#ifndef _QUAGGA_BGP_CONDITIONAL_DISAGG_H
#define _QUAGGA_BGP_CONDITIONAL_DISAGG_H

#include "prefix.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

/*
 * Conditional Disaggregation: Automatically generate SAFI_UNICAST routes
 * when SAFI_UNREACH routes are received with matching SoO extended community.
 *
 * This allows anycast groups to automatically disaggregate suppressed prefixes
 * when unreachability is detected, enabling traffic to route around failures.
 */

/* Error codes for conditional disaggregation LTTng traces (range 1-10) */
enum cond_disagg_error_code {
	COND_DISAGG_LOCAL_SOO_NOT_SET = 1,
	COND_DISAGG_UNREACH_NO_SOO = 2,
};

/*
 * Generate SAFI_UNICAST route when SAFI_UNREACH route is received with
 * matching SoO extended community.
 *
 * @param bgp BGP instance
 * @param p Prefix from SAFI_UNREACH route
 * @param pi Path info for SAFI_UNREACH route
 * @param afi Address family
 * @param safi Sub-address family (must be SAFI_UNREACH, silently returns otherwise)
 * @param peer Peer that sent the SAFI_UNREACH route (NULL safely ignored)
 */
extern void bgp_conditional_disagg_add(struct bgp *bgp, const struct prefix *p,
				       struct bgp_path_info *pi, afi_t afi, safi_t safi,
				       struct peer *peer);

/*
 * Withdraw generated SAFI_UNICAST route when SAFI_UNREACH route is withdrawn.
 *
 * @param bgp BGP instance
 * @param p Prefix from SAFI_UNREACH route
 * @param pi Path info for SAFI_UNREACH route
 * @param afi Address family
 * @param safi Sub-address family (must be SAFI_UNREACH, silently returns otherwise)
 * @param peer Peer that withdrew the SAFI_UNREACH route (NULL safely ignored)
 */
extern void bgp_conditional_disagg_withdraw(struct bgp *bgp, const struct prefix *p,
					    struct bgp_path_info *pi, afi_t afi, safi_t safi,
					    struct peer *peer);

#endif /* _QUAGGA_BGP_CONDITIONAL_DISAGG_H */

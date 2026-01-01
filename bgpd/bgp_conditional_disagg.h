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

/*
 * Generate SAFI_UNICAST route when SAFI_UNREACH route is received with
 * matching SoO extended community.
 *
 * @param bgp BGP instance
 * @param p Prefix from SAFI_UNREACH route
 * @param pi Path info for SAFI_UNREACH route
 * @param afi Address family
 * @param peer Peer that sent the SAFI_UNREACH route
 */
extern void bgp_conditional_disagg_add(struct bgp *bgp, const struct prefix *p,
				       struct bgp_path_info *pi, afi_t afi, struct peer *peer);

/*
 * Withdraw generated SAFI_UNICAST route when SAFI_UNREACH route is withdrawn.
 *
 * @param bgp BGP instance
 * @param p Prefix from SAFI_UNREACH route
 * @param pi Path info for SAFI_UNREACH route
 * @param afi Address family
 * @param peer Peer that withdrew the SAFI_UNREACH route
 */
extern void bgp_conditional_disagg_withdraw(struct bgp *bgp, const struct prefix *p,
					    struct bgp_path_info *pi, afi_t afi, struct peer *peer);

#endif /* _QUAGGA_BGP_CONDITIONAL_DISAGG_H */

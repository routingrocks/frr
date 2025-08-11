#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_high_ecmp.py
#
# Copyright (c) 2024 by
# Nvidia Corporation
# Donald Sharp
#
# Copyright (c) 2025 by Soumya Roy, <souroy@nvidia.com>

"""
test_high_ecmp.py: Testing two routers with 256 interfaces and BGP setup
                   on it.

"""

import os
import re
import sys
import pytest
import json

pytestmark = [pytest.mark.bgpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Let's create 257 interfaces between the two switches
    for switch in range(1, 516):
        switch = tgen.add_switch("sw{}".format(switch))
        switch.add_link(r1)
        switch.add_link(r2)


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, "-s 180000000"),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_SHARP, None),
            ],
        )
 
    tgen.start_router()
    
    for rname, router in router_list.items():
       router.cmd("vtysh -f {}/{}/frr_unnumbered_bgp.conf".format(CWD, rname))

def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def test_bgp_route_cleanup():
    failures = 0
    net = get_topogen().net
    expected_route_count = 2000

    # First, extract IPv4 and IPv6 loopback addresses from r1
    lo_output = net["r1"].cmd("vtysh -c 'show interface lo'")

    # Extract IPv4 and IPv6 addresses from the output
    ipv4_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", lo_output)
    ipv6_match = re.search(r"inet6 ([0-9a-f:]+)/\d+", lo_output)

    if not ipv4_match or not ipv6_match:
        assert False, "Could not find IPv4 or IPv6 address on loopback interface"

    ipv4_nexthop = ipv4_match.group(1)
    ipv6_nexthop = ipv6_match.group(1)

    logger.info(f"\nUsing nexthops: IPv4={ipv4_nexthop}, IPv6={ipv6_nexthop}")

    # Install IPv4 routes
    ipv4_cmd = f"vtysh -c 'sharp install routes 39.99.0.0 nexthop {ipv4_nexthop} {expected_route_count}'"
    net["r1"].cmd(ipv4_cmd)

    # Install IPv6 routes
    ipv6_cmd = f"vtysh -c 'sharp install routes 2100:cafe:: nexthop {ipv6_nexthop} {expected_route_count}'"
    net["r1"].cmd(ipv6_cmd)

    # Initialize actual counts
    ipv4_actual_count = 0
    ipv6_actual_count = 0
    max_attempts = 12  # 60 seconds max (12 * 5)
    attempt = 0

    # Wait until both IPv4 and IPv6 routes are installed
    while (
        ipv4_actual_count != expected_route_count
        or ipv6_actual_count != expected_route_count
    ) and attempt < max_attempts:
        sleep(5)
        attempt += 1

        # Get current IPv4 route count
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )

        # Get current IPv6 route count
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )

        try:
            ipv4_actual_count = int(ipv4_count_str)
        except ValueError:
            ipv4_actual_count = 0

        try:
            ipv6_actual_count = int(ipv6_count_str)
        except ValueError:
            ipv6_actual_count = 0

        logger.info(f"Attempt {attempt}")
        logger.info(f"IPv4 Routes found: {ipv4_actual_count} / {expected_route_count}")
        logger.info(f"IPv6 Routes found: {ipv6_actual_count} / {expected_route_count}")

    # Verify we have the expected number of routes
    if ipv4_actual_count != expected_route_count:
        sys.stderr.write(
            f"Failed to install expected IPv4 routes: got {ipv4_actual_count}, expected {expected_route_count}\n"
        )
        failures += 1
    else:
        logger.info("IPv4 routes successfully installed")

    if ipv6_actual_count != expected_route_count:
        sys.stderr.write(
            f"Failed to install expected IPv6 routes: got {ipv6_actual_count}, expected {expected_route_count}\n"
        )
        failures += 1
    else:
        logger.info("IPv6 routes successfully installed")

        # Configure BGP timers for faster convergence
        # Configure BGP timers for faster convergence
    logger.info("\n=== Configuring BGP Timers ===")
    logger.info("Setting BGP keepalive=3, hold=10 for faster convergence...")
    
    # Configure BGP timers on both routers
    for router_name in ["r1", "r2"]:
        router = net[router_name]
        
        # Configure BGP timers
        timer_config = [
            "conf",
            "router bgp",  # Will use the existing AS number
            "timers bgp 3 10",
            "exit",
            "exit"
        ]
        
        cmd = "vtysh"
        for config_line in timer_config:
            cmd += f' -c "{config_line}"'
        
        result = router.cmd(cmd)
        logger.info(f"Configured BGP timers on {router_name}")
    
    # Clear BGP sessions on r2 to make timer changes effective
    logger.info("Clearing BGP sessions to apply new timers...")
    net["r2"].cmd('vtysh -c "clear bgp *"')
    logger.info("BGP sessions cleared on r2")
    
    logger.info("BGP timers configured. Waiting for new timers to take effect...")
    
    # Wait a moment for the new timers to take effect
    def check_bgp_timers_applied():
        try:
            # Check if BGP sessions are still established
            bgp_summary = net["r1"].cmd('vtysh -c "show bgp summary json"')
            import json
            summary_data = json.loads(bgp_summary)
        
            # Get IPv4 unicast peers (matches your actual JSON structure)
            ipv4_peers = summary_data.get("ipv4Unicast", {}).get("peers", {})
        
            # Look for any established peers
            established_count = 0
            for peer_intf, peer_info in ipv4_peers.items():
                if peer_info.get("state") == "Established":
                    established_count += 1
        
            if established_count > 0:
                logger.info(f"BGP sessions established: {established_count} peers (e.g., {list(ipv4_peers.keys())[:3]}...)")
                return True
            else:
                logger.info("Waiting for BGP sessions to re-establish with new timers...")
                return False
        except (json.JSONDecodeError, KeyError) as e:
            logger.info(f"Error parsing BGP summary: {e}")
            return False
    
    # Wait for BGP sessions to stabilize with new timers
    success_timers, _ = topotest.run_and_expect(
        check_bgp_timers_applied,
        True,
        count=20,  # 20 attemptsf
        wait=2,    # 2 seconds between attempts (40 seconds total)
    )
    
    if success_timers:
        logger.info("✓ BGP timers successfully applied and sessions stable")
    else:
        logger.info("⚠ Warning: BGP sessions may still be converging after timer change")

    # Test interface shutdown/restoration
    logger.info("\n=== Testing Interface Shutdown/Restoration ===")
    
    # Known interfaces: r1-eth0 to r1-eth512 (513 interfaces total)
    interfaces = [f"r1-eth{i}" for i in range(515)]
    logger.info(f"Testing {len(interfaces)} interfaces: r1-eth0 to r1-eth514")
    
    # Phase 1: Shutdown all interfaces
    logger.info("\nPhase 1: Shutting down all interfaces...")
    for interface in interfaces:
        net["r1"].cmd(f"ip link set {interface} down")
    
    logger.info("All interfaces shut down, waiting for route removal...")
    # Define test functions for route checking
    def check_ipv4_routes_removed():
        """Check if IPv4 routes are removed from r2"""
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        try:
            count = int(ipv4_count_str)
            logger.info(f"IPv4 routes remaining: {count}")
            return count == 0
        except ValueError:
            return True  # If we can't parse, assume 0
    
    def check_ipv6_routes_removed():
        """Check if IPv6 routes are removed from r2"""
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )
        try:
            count = int(ipv6_count_str)
            logger.info(f"IPv6 routes remaining: {count}")
            return count == 0
        except ValueError:
            return True  # If we can't parse, assume 0
    
    # Wait for IPv4 routes to be removed using topotest.run_and_expect
    # With faster BGP timers (hold=10), convergence should be much faster
    success_ipv4, result_ipv4 = topotest.run_and_expect(
        check_ipv4_routes_removed,
        True,
        count=15,  # Reduced from 30 due to faster timers
        wait=2,    # 2 seconds between attempts (30 seconds total)
    )
    
    if not success_ipv4:
        sys.stderr.write("Interface down test failed - IPv4 routes not removed\n")
        failures += 1
    else:
        logger.info("✓ IPv4 routes successfully removed after interface down")
    
    # Wait for IPv6 routes to be removed using topotest.run_and_expect
    success_ipv6, result_ipv6 = topotest.run_and_expect(
        check_ipv6_routes_removed,
        True,
        count=15,  # Reduced from 30 due to faster timers 
        wait=2,    # 2 seconds between attempts (30 seconds total)
    )
    
    if not success_ipv6:
        sys.stderr.write("Interface down test failed - IPv6 routes not removed\n")
        failures += 1
    else:
        logger.info("✓ IPv6 routes successfully removed after interface down")
    
    # Phase 2: Bring interfaces back up
    logger.info("\nPhase 2: Bringing interfaces back up...")
    for interface in interfaces:
        net["r1"].cmd(f"ip link set {interface} up")
    
    logger.info("All interfaces brought up, waiting for route restoration...")
    
    # Define test functions for route restoration checking
    def check_ipv4_routes_restored():
        """Check if IPv4 routes are restored in r2"""
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )
        try:
            count = int(ipv4_count_str)
            logger.info(f"IPv4 routes restored: {count} / {expected_route_count}")
            return count == expected_route_count
        except ValueError:
            return False
    
    def check_ipv6_routes_restored():
        """Check if IPv6 routes are restored in r2"""
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )
        try:
            count = int(ipv6_count_str)
            logger.info(f"IPv6 routes restored: {count} / {expected_route_count}")
            return count == expected_route_count
        except ValueError:
            return False
    
    # Wait for IPv4 routes to be restored using topotest.run_and_expect
    success_ipv4_restore, result_ipv4_restore = topotest.run_and_expect(
        check_ipv4_routes_restored,
        True,
        count=30,  # Reduced from 40 due to faster timers
        wait=3,    # 3 seconds between attempts (90 seconds total)
    )
    
    if not success_ipv4_restore:
        sys.stderr.write(f"Interface restore test failed - IPv4 routes not restored\n")
        failures += 1
    else:
        logger.info("✓ IPv4 routes successfully restored after interface up")
    
    # Wait for IPv6 routes to be restored using topotest.run_and_expect
    success_ipv6_restore, result_ipv6_restore = topotest.run_and_expect(
        check_ipv6_routes_restored,
        True,
        count=30,  # Reduced from 40 due to faster timers
        wait=3,    # 3 seconds between attempts (90 seconds total)
    )
    
    if not success_ipv6_restore:
        sys.stderr.write(f"Interface restore test failed - IPv6 routes not restored\n")
        failures += 1
    else:
        logger.info("✓ IPv6 routes successfully restored after interface up")
    
    logger.info("=== Interface Shutdown/Restoration Test Complete ===\n")


    # New test: BGP Graceful Restart with interface down on r2
    logger.info("\n=== BGP Graceful Restart Test (r2 interfaces) ===")
    
    # Enable BGP Graceful Restart on r2 only
    logger.info("Enabling BGP Graceful Restart on r2...")
    gr_config_commands = [
        "conf",
        "router bgp",
        "bgp graceful-restart",
        "exit",
        "exit"
    ]
    
    gr_cmd = "vtysh"
    for config_line in gr_config_commands:
        gr_cmd += f' -c "{config_line}"'
    
    result = net["r2"].cmd(gr_cmd)
    logger.info("BGP Graceful Restart configured on r2")
    # Clear BGP sessions on r2 to enable GR
    logger.info("Clearing BGP sessions on r2 to enable GR...")
    net["r2"].cmd('vtysh -c "clear bgp *"')

    # Verify GR is enabled on r2
    def check_gr_enabled_r2():

        try:
            # Check specific neighbor r2-eth200 for GR status
            neighbor_output = net["r2"].cmd('vtysh -c "show bgp neighbors r2-eth200"')
            if "Local GR Mode: Restart*" in neighbor_output:
                logger.info("✓ BGP Graceful Restart verified as enabled on r2 (Local GR Mode: Restart*)")
                return True
            else:
                logger.info("⚠ BGP Graceful Restart not yet active on r2")
                return False
        except Exception as e:
            logger.info(f"Warning: Could not verify GR status: {e}")
            return False
    
    # Wait for GR configuration to take effect using topotest.run_and_expect
    gr_enabled, _ = topotest.run_and_expect(
        check_gr_enabled_r2,
        True,
        count=5,   # 5 attempts
        wait=1,    # 1 second between attempts
    )
    
    # Get list of interfaces on r2 (r2-eth0 to r2-eth514)
    r2_interfaces = [f"r2-eth{i}" for i in range(515)]
    logger.info(f"Testing {len(r2_interfaces)} interfaces on r2: r2-eth0 to r2-eth514")
    
    # Phase 1: Shutdown interfaces on r2 (even with GR, routes should be deleted)
    logger.info("\nPhase 1: Shutting down interfaces on r2...")
    logger.info("Note: Even with GR enabled, routes should be DELETED when interfaces go down")
    
    for interface in r2_interfaces:
        net["r2"].cmd(f"ip link set {interface} down")
    
    logger.info("All r2 interfaces shut down, waiting for route deletion on r2...")
    
    # Reuse existing functions - they already check routes on r2
    # Routes should be DELETED (not staled) when interfaces go down, even with GR
    success_ipv4_deleted, _ = topotest.run_and_expect(
        check_ipv4_routes_removed,
        True,
        count=10,  # 10 attempts  
        wait=1,    # 1 second between attempts (10 seconds total)
    )
    
    if not success_ipv4_deleted:
        sys.stderr.write("GR interface down test failed - IPv4 routes not deleted from r2\n")
        failures += 1
    else:
        logger.info("✓ IPv4 routes successfully deleted from r2 after r2 interface down (even with GR)")
    
    # Wait for IPv6 routes to be deleted using existing function
    success_ipv6_deleted, _ = topotest.run_and_expect(
        check_ipv6_routes_removed,
        True,
        count=10,  # 10 attempts
        wait=1,    # 1 second between attempts (10 seconds total)
    )
    
    if not success_ipv6_deleted:
        sys.stderr.write("GR interface down test failed - IPv6 routes not deleted from r2\n")
        failures += 1
    else:
        logger.info("✓ IPv6 routes successfully deleted from r2 after r2 interface down (even with GR)")
    
    # Phase 2: Bring r2 interfaces back up
    logger.info("\nPhase 2: Bringing r2 interfaces back up...")
    for interface in r2_interfaces:
        net["r2"].cmd(f"ip link set {interface} up")
    
    logger.info("All r2 interfaces brought up, waiting for route restoration on r2...")
    
    # Reuse existing route restoration functions - they already check routes on r2
    success_ipv4_restore, _ = topotest.run_and_expect(
        check_ipv4_routes_restored,
        True,
        count=30,  # 30 attempts
        wait=3,    # 3 seconds between attempts (90 seconds total)
    )
    
    if not success_ipv4_restore:
        sys.stderr.write(f"GR interface recovery test failed - IPv4 routes not restored on r2\n")
        failures += 1
    else:
        logger.info("✓ IPv4 routes successfully restored on r2 after r2 interface recovery")
    
    success_ipv6_restore, _ = topotest.run_and_expect(
        check_ipv6_routes_restored,
        True,
        count=30,  # 30 attempts  
        wait=3,    # 3 seconds between attempts (90 seconds total)
    )
    
    if not success_ipv6_restore:
        sys.stderr.write(f"GR interface recovery test failed - IPv6 routes not restored on r2\n")
        failures += 1
    else:
        logger.info("✓ IPv6 routes successfully restored on r2 after r2 interface recovery")
    
    logger.info("=== BGP Graceful Restart Test Complete ===\n")
    logger.info("Note: This test shows that GR does NOT prevent route deletion during interface failures.")
    logger.info("GR only provides stale route preservation during BGP process restarts, not interface down events.")


    # Stop bgpd in r1 to trigger deletion of routes in r2
    kill_router_daemons(get_topogen(), "r1", ["bgpd"])

    # Initialize variables for post-removal check
    # Start with the original count
    ipv4_final_count = expected_route_count
    ipv6_final_count = expected_route_count
    expected_final_count = 0
    attempt = 0
    max_removal_attempts = 12

    # Wait until both IPv4 and IPv6 routes are fully removed
    while (
        ipv4_final_count != expected_final_count
        or ipv6_final_count != expected_final_count
    ) and attempt < max_removal_attempts:
        sleep(5)
        attempt += 1

        # Get current IPv4 route count
        ipv4_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv4 unicast" | grep "39.99" | wc -l')
            .rstrip()
        )

        # Get current IPv6 route count
        ipv6_count_str = (
            net["r2"]
            .cmd('vtysh -c "show bgp ipv6 unicast" | grep "cafe" | wc -l')
            .rstrip()
        )

        try:
            ipv4_final_count = int(ipv4_count_str)
        except ValueError:
            ipv4_final_count = 0

        try:
            ipv6_final_count = int(ipv6_count_str)
        except ValueError:
            ipv6_final_count = 0

        logger.info(f"Route Removal Attempt {attempt}")
        logger.info(f"IPv4 Routes remaining: {ipv4_final_count} / {expected_final_count}")
        logger.info(f"IPv6 Routes remaining: {ipv6_final_count} / {expected_final_count}")

        # If both are already at expected count, break early
        if (
            ipv4_final_count == expected_final_count
            and ipv6_final_count == expected_final_count
        ):
            logger.info("All routes successfully removed")
            break

    # Final verification
    if ipv4_final_count != expected_final_count:
        sys.stderr.write(
            f"Failed to remove IPv4 routes after {max_removal_attempts} attempts: "
            f"{ipv4_final_count} routes still present\n"
        )
        failures += 1
    else:
        logger.info("IPv4 routes successfully removed")

    if ipv6_final_count != expected_final_count:
        sys.stderr.write(
            f"Failed to remove IPv6 routes after {max_removal_attempts} attempts: "
            f"{ipv6_final_count} routes still present\n"
        )
        failures += 1
    else:
        logger.info("IPv6 routes successfully removed")

    start_router_daemons(get_topogen(), "r1", ["bgpd"])
    assert failures == 0, f"Test failed with {failures} failures"


def test_nothing():
    "Do Nothing"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

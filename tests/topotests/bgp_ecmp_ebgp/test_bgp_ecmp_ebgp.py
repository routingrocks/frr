#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025
#
"""
Test BGP ECMP with eBGP - Equal Cost Multi-Path routing
"""

import os
import sys
import pytest
import json
import tempfile
from lib import topotest
from lib.topogen import get_topogen, Topogen, TopoRouter
from lib.topolog import logger
from lib.common_config import retry, step
from lib.bgp import verify_bgp_convergence_from_running_config

pytestmark = [pytest.mark.bgpd]


def setup_module(module):
    """Build and start topology, load daemon configs, start routers."""
    # ECMP topology: r1(AS100) <-> r2(AS200) <-> r3(AS100)
    # r2 will receive the same route from both r1 and r3 with same AS path
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r2", "r3"),
    }

    tgen = Topogen(topodef, module.__name__)

    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        try:
            router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
            router.load_config(TopoRouter.RD_BGP, "bgpd.conf")
        except Exception as e:
            logger.error(f"Failed to load config for {rname}: {e}")
            raise

    tgen.start_router()


def teardown_module(module):
    """Stop topology."""
    tgen = get_topogen()
    tgen.stop_topology()


# No pytest fixture is used; tests obtain the running topology via
# get_topogen() in each test, matching most upstream topotests.


def test_basic_topology():
    "Test that basic topology is working"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing basic topology")

    # Check if we can access the routers
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Simple test - check if routers are responding
    for router in [r1, r2, r3]:
        try:
            output = router.vtysh_cmd("show version")
            logger.info(f"Router {router.name} is responding")
        except Exception as e:
            logger.error(f"Router {router.name} failed: {e}")
            raise

    logger.info("Basic topology test passed")


def test_wait_for_bgp_convergence():
    "Wait for BGP to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for BGP to converge")

    # Check if routers are running
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Check if BGP daemons are running
    for router in [r1, r2, r3]:
        bgp_status = router.vtysh_cmd("show bgp summary")
        logger.info(f"BGP status on {router.name}:\n{bgp_status}")

    step("Waiting for BGP convergence")
    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, (
        "BGP convergence failed: {}".format(result)
    )

    # Add wait timer for route advertisement
    step("Waiting 5 seconds for route advertisement")
    topotest.sleep(5, "Waiting for route advertisement")


def test_ecmp_route_advertisement():
    """
    Test that ECMP routes are properly advertised, received, and
    installed as multipath
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Checking ECMP route advertisement and multipath installation")

    # Check that r1 and r3 are originating the route
    r1_bgp = r1.vtysh_cmd("show bgp ipv4 unicast")
    logger.info("R1 BGP table:\n%s", r1_bgp)
    assert "192.168.1.0/24" in r1_bgp, (
        "Route 192.168.1.0/24 not in R1 BGP table"
    )

    r3_bgp = r3.vtysh_cmd("show bgp ipv4 unicast")
    logger.info("R3 BGP table:\n%s", r3_bgp)
    assert "192.168.1.0/24" in r3_bgp, (
        "Route 192.168.1.0/24 not in R3 BGP table"
    )

    # Enhanced verification using JSON output to check route reception
    # from both neighbors
    step("Verifying route reception using JSON output")

    # Get non-JSON output of BGP table on R2 for comparison
    r2_bgp_regular = r2.vtysh_cmd("show bgp ipv4 unicast")
    logger.info("R2 BGP table (Regular):\n%s", r2_bgp_regular)

    # Get JSON output of BGP table on R2
    r2_bgp_json = r2.vtysh_cmd("show bgp ipv4 unicast json")
    logger.info("R2 BGP table (JSON):\n%s", r2_bgp_json)

    # Parse JSON to verify route reception from both R1 and R3
    import json
    bgp_data = json.loads(r2_bgp_json)

    # Check if routes exist in the JSON structure
    assert "routes" in bgp_data, "No 'routes' key found in JSON output"
    routes = bgp_data["routes"]

    # Check if the specific route exists
    assert "192.168.1.0/24" in routes, (
        "Route 192.168.1.0/24 not found in JSON routes"
    )

    route_paths = routes["192.168.1.0/24"]
    logger.info(
        "Route paths from JSON:\n%s",
        json.dumps(route_paths, indent=2),
    )

    # Check path count
    assert len(route_paths) == 2, (
        f"Expected 2 paths, found {len(route_paths)}"
    )

    # Extract next-hop information from paths
    next_hops = []
    peer_ids = []
    multipath_count = 0
    best_path_count = 0

    for path in route_paths:
        # Check multipath status
        if path.get("multipath", False):
            multipath_count += 1

        # Check if this is a best path
        if path.get("bestpath", False):
            best_path_count += 1
            logger.info(f"Found best path: {path}")

        # Extract peer ID
        if "peerId" in path:
            peer_ids.append(path["peerId"])

        # Extract next-hop information
        if "nexthops" in path and path["nexthops"]:
            for nexthop in path["nexthops"]:
                if "ip" in nexthop:
                    next_hops.append(nexthop["ip"])

    # Remove duplicates and get unique next-hops
    unique_next_hops = list(set(next_hops))
    unique_peer_ids = list(set(peer_ids))

    logger.info(f"Unique next-hops found: {unique_next_hops}")
    logger.info(f"Unique peer IDs found: {unique_peer_ids}")
    logger.info(f"Multipath paths found: {multipath_count}")
    logger.info(f"Best paths found: {best_path_count}")

    # Verify both expected next-hops are present
    assert "10.0.1.1" in unique_next_hops, (
        "Next-hop 10.0.1.1 (R1) not found in JSON"
    )
    assert "10.0.2.3" in unique_next_hops, (
        "Next-hop 10.0.2.3 (R3) not found in JSON"
    )

    # Verify both peer IDs are present
    assert "10.0.1.1" in unique_peer_ids, (
        "Peer ID 10.0.1.1 (R1) not found in JSON"
    )
    assert "10.0.2.3" in unique_peer_ids, (
        "Peer ID 10.0.2.3 (R3) not found in JSON"
    )

    # Check multipath status
    assert multipath_count >= 1, "No multipath routes found in JSON"

    # Critical verification: Exactly one route must be marked as best path
    assert best_path_count == 1, (
        f"Expected exactly 1 best path, found {best_path_count}"
    )

    logger.info(f"Found {multipath_count} multipath routes")
    logger.info(
        "JSON verification successful - both R1 and R3 routes confirmed"
    )

    # Additional verification: Check BGP summary for route counts
    bgp_summary = r2.vtysh_cmd("show bgp summary")
    logger.info("BGP summary on R2:\n%s", bgp_summary)

    # Verify both neighbors show received routes
    assert "10.0.1.1" in bgp_summary, "R1 neighbor not found in BGP summary"
    assert "10.0.2.3" in bgp_summary, "R3 neighbor not found in BGP summary"

    # Check IP routing table installation (merged from
    # test_ecmp_multipath_installation)
    step("Verifying IP routing table installation")

    # Check routing table for ECMP routes
    ip_route = r2.vtysh_cmd("show ip route")
    logger.info("IP routing table on R2:\n%s", ip_route)

    # Verify ECMP routes are installed
    assert "192.168.1.0/24" in ip_route, (
        "Route 192.168.1.0/24 not in routing table"
    )

    # Check detailed route information for both paths
    route_details = r2.vtysh_cmd("show ip route 192.168.1.0")
    logger.info("Detailed route info:\n%s", route_details)

    # Verify both nexthop IPs are present (avoid interface-name matching)
    assert "10.0.1.1" in route_details, (
        "Path via r1 nexthop 10.0.1.1 not in routing table"
    )
    assert "10.0.2.3" in route_details, (
        "Path via r3 nexthop 10.0.2.3 not in routing table"
    )

    logger.info(
        "ECMP route advertisement and multipath installation test "
        "passed"
    )


def test_ecmp_route_counting():
    "Test that ECMP routes are correctly counted"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    step("Checking ECMP route counting")

    # Check installed routes in the kernel routing table
    ip_route = r2.vtysh_cmd("show ip route")
    logger.info("IP routing table on r2:\n%s", ip_route)

    # Verify the route is counted correctly
    # Should count as 1 installed route, not 2 separate routes
    route_count = ip_route.count("192.168.1.0/24")
    assert route_count == 1, f"Expected 1 route entry, found {route_count}"

    logger.info("ECMP route counting test passed")


def test_bgp_neighbor_prefix_counts_json():
    "Test BGP neighbor prefix counts using JSON output and verify best "
    "route selection"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    step("Verifying BGP neighbor prefix counts using JSON output")

    # Test the command for both neighbors
    neighbors = ["10.0.1.1", "10.0.2.3"]
    best_selected_count = 0
    total_prefixes = 0

    for neighbor in neighbors:
        logger.info(f"Checking prefix counts for neighbor {neighbor}")

        # Execute the command
        cmd = (
            "show ip bgp vrf default ipv4 unicast neighbors "
            f"{neighbor} prefix-counts json"
        )
        prefix_counts_json = r2.vtysh_cmd(cmd)
        logger.info(
            f"Prefix counts JSON for {neighbor}:\n{prefix_counts_json}"
        )

        # Parse JSON output
        import json
        try:
            prefix_data = json.loads(prefix_counts_json)
            logger.info(
                f"Parsed JSON data for {neighbor}:\n"
                f"{json.dumps(prefix_data, indent=2)}"
            )
        except json.JSONDecodeError as e:
            logger.error(
                f"Failed to parse JSON for {neighbor}: {e}"
            )
            logger.error(
                f"Raw output: {prefix_counts_json}"
            )
            raise

        # Verify JSON structure
        assert isinstance(prefix_data, dict), (
            f"Expected dict, got {type(prefix_data)}"
        )

        # Check for expected keys in the JSON response
        assert len(prefix_data) > 0, f"Empty JSON response for {neighbor}"

        # Log the structure for analysis
        logger.info(f"JSON keys for {neighbor}: {list(prefix_data.keys())}")

        # Verify that the neighbor is present in the response
        neighbor_found = False
        for key, value in prefix_data.items():
            if neighbor in str(value) or neighbor in str(key):
                neighbor_found = True
                break

        if not neighbor_found:
            logger.warning(
                f"Neighbor {neighbor} not explicitly found in JSON response"
            )
            logger.info(f"Full response for {neighbor}: {prefix_data}")

        # Extract prefix count and best selected count
        if "pfxCounter" in prefix_data:
            total_prefixes += prefix_data["pfxCounter"]
            logger.info(
                f"Total prefixes from {neighbor}: {prefix_data['pfxCounter']}"
            )

        if "ribTableWalkCounters" in prefix_data:
            rib_counters = prefix_data["ribTableWalkCounters"]
            if "PfxCt Best Selected" in rib_counters:
                best_selected = rib_counters["PfxCt Best Selected"]
                best_selected_count += best_selected
                logger.info(
                    f"Best selected prefixes from {neighbor}: "
                    f"{best_selected}"
                )

                # Verify that this neighbor has valid routes
                if "Valid" in rib_counters:
                    valid_count = rib_counters["Valid"]
                    assert valid_count > 0, f"No valid routes from {neighbor}"

                # Verify that routes are useable
                if "Useable" in rib_counters:
                    useable_count = rib_counters["Useable"]
                    assert useable_count > 0, (
                        f"No useable routes from {neighbor}"
                    )

    # Critical verification: Exactly one route must be marked as best selected
    step("Verifying exactly one route is marked as best selected")
    assert best_selected_count == 1, (
        f"Expected exactly 1 best selected route, "
        f"found {best_selected_count}"
    )
    logger.info(f"Total best selected routes: {best_selected_count}")

    # Verify total prefixes received
    assert total_prefixes == 2, (
        "Expected exactly 2 total prefixes (one from each neighbor), "
        f"found {total_prefixes}"
    )
    logger.info(f"Total prefixes received: {total_prefixes}")

    logger.info(
        "BGP neighbor prefix counts JSON test passed - best route "
        "verification successful"
    )


def test_multipath_count_accuracy():
    "Test that multipath count is accurate in JSON output "
    "(verifies commit a7f7c5e564)"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    step("Verifying multipath count accuracy using multiple JSON commands")

    # Test prefix for verification
    test_prefix = "192.168.1.0/24"

    # 1. Get output for - show bgp ipv4 unicast json
    step("Getting general BGP table JSON output")
    bgp_table_json = r2.vtysh_cmd("show bgp ipv4 unicast json")
    logger.info("BGP table JSON output:\n%s", bgp_table_json)

    # Parse output
    import json
    bgp_data = json.loads(bgp_table_json)
    assert "routes" in bgp_data, "No 'routes' key found in BGP table JSON"
    assert test_prefix in bgp_data["routes"], (
        f"Route {test_prefix} not found in BGP table"
    )

    # Extract multipath count from output
    route_data = bgp_data["routes"][test_prefix]
    bgp_table_multipath_count = sum(
        1 for path in route_data if path.get("multipath", False)
    )
    bgp_table_path_count = len(route_data)
    logger.info(
        "BGP table - multipath count: %s, path count: %s",
        bgp_table_multipath_count,
        bgp_table_path_count,
    )

    # 2. Get specific prefix multipath JSON output
    step("Getting specific prefix multipath JSON output")
    multipath_cmd = (
        f"show bgp vrf default ipv4 unicast {test_prefix} multipath json"
    )
    multipath_json_output = r2.vtysh_cmd(multipath_cmd)
    logger.info(f"Multipath JSON output:\n{multipath_json_output}")

    # Parse multipath JSON
    multipath_data = json.loads(multipath_json_output)
    logger.info(
        "Parsed multipath data:\n%s",
        json.dumps(multipath_data, indent=2),
    )

    # Extract multipath count from specific command
    multipath_count = multipath_data.get("multiPathCount", 0)
    path_count = multipath_data.get("pathCount", 0)
    paths = multipath_data.get("paths", [])
    logger.info(
        "Multipath command - multipath count: %s, path count: %s",
        multipath_count,
        path_count,
    )

    # Verify multipath count is exactly 2 (not 3 or 4 as the bug would show)
    assert multipath_count == 2, (
        f"Expected multipath count 2, got {multipath_count}"
    )
    assert bgp_table_multipath_count == 2, (
        f"Expected BGP table multipath count 2, got "
        f"{bgp_table_multipath_count}"
    )

    # Verify path count is exactly 2
    assert path_count == 2, f"Expected path count 2, got {path_count}"
    assert bgp_table_path_count == 2, (
        f"Expected BGP table path count 2, got {bgp_table_path_count}"
    )
    assert len(paths) == 2, (
        f"Expected 2 paths in multipath output, got {len(paths)}"
    )

    logger.info(
        "Multipath count accuracy test passed - commit a7f7c5e564 fix "
        "verified"
    )
    logger.info(
        "Final verification - multipath count: %s, path count: %s",
        multipath_count,
        path_count,
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()

#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

import os
import re
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_peer_group_remote_as_ra_validation():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Add BGP peer group with remote-as external
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
          neighbor TEST_PG peer-group
          neighbor TEST_PG remote-as external
          neighbor r1-eth0 interface peer-group TEST_PG
        """
    )

    # Verify interface configuration shows BGP RA
    def _check_interface_bgp_ra():
        output = r1.vtysh_cmd("do sh int r1-eth0 | include BGP")
        return "BGP has configured RA" in output

    test_func = functools.partial(_check_interface_bgp_ra)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result is True, "Interface r1-eth0 should have BGP RA configured"

    # Remove remote-as external from peer group
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
          no neighbor TEST_PG remote-as external
        """
    )

    # Verify interface configuration is empty
    def _check_interface_empty():
        output = r1.vtysh_cmd("do sh int r1-eth0 | include BGP")
        return output.strip() == ""

    test_func = functools.partial(_check_interface_empty)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result is True, "Interface r1-eth0 should not have BGP RA configured"

    # Re-add remote-as external to peer group
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
          neighbor TEST_PG remote-as external
        """
    )

    # Verify interface configuration shows BGP RA again
    test_func = functools.partial(_check_interface_bgp_ra)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result is True, "Interface r1-eth0 should have BGP RA configured back"

    # Clean up - remove the peer group configuration
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
          no neighbor r1-eth0 interface peer-group TEST_PG
          no neighbor TEST_PG peer-group
        """
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

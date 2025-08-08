#!/usr/bin/env python3

import os
import sys
import pytest
import json
from time import sleep
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    check_address_types,
    required_linux_kernel_version,
)

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

#pytestmark = [pytest.mark.bgpd, pytest.mark.zebra]

# Required to instantiate the topology builder class.
#from mininet.topo import Topo

def build_topo(tgen):
    # Create 2 routers
    for routern in range(1, 3):
        tgen.add_router('r{}'.format(routern))

    # Add a switch for router 1
    switch = tgen.add_switch('s1')
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r2'])

def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )

    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()

def test_zebra_csm_startup_mode():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing zebra csm startup mode")
    # Verify static route on r1
    r1 = tgen.gears['r1']
    output = r1.vtysh_cmd("show ip route")
    assert "199.199.199.99/32" in output

    sleep(5)
    # Verify BGP advertisement on r2
    r2 = tgen.gears['r2']
    output = r2.vtysh_cmd("show ip bgp")
    assert "199.199.199.99/32" in output
    assert "10.0.1.1" in output

    # Test setting startup mode to COLD_START (1)
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "zebra csm startup-mode 1"'
    )
    output = r1.vtysh_cmd("show zebra csm")
    assert "CSM start mode cold" in output
    # Verify BGP advertisement on r2
    r2 = tgen.gears['r2']
    output = r2.vtysh_cmd("show ip bgp")
    assert "199.199.199.99/32" in output
    assert "10.0.1.1" in output

    # Test setting startup mode to FAST_START (2)
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "zebra csm startup-mode 2"'
    )
    output = r1.vtysh_cmd("show zebra csm")
    assert "CSM start mode fast" in output

    # Test setting startup mode to WARM_START (4)
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "zebra csm startup-mode 4"'
    )
    output = r1.vtysh_cmd("show zebra csm")
    assert "CSM start mode warm" in output

    # Test setting startup mode to MAINT (8)
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "zebra csm startup-mode 8"'
    )
    output = r1.vtysh_cmd("show zebra csm")
    assert "CSM start mode maintenance" in output
    sleep(5)

    # Verify bgpInMaintenanceMode in JSON output
    output = r1.vtysh_cmd("show bgp router json")
    json_output = json.loads(output)
    assert json_output["bgpInMaintenanceMode"] == "Yes"

    # Verify BGP advertisement on r2
    output = r2.vtysh_cmd("show ip bgp")
    assert "199.199.199.99/32" in output
    assert "10.0.1.1" in output

    # Test setting both WARM_START and MAINT modes (4 + 8 = 12)
    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "zebra csm startup-mode 12"'
    )

    # Verify bgpInMaintenanceMode in JSON output
    output = r1.vtysh_cmd("show bgp router json")
    json_output = json.loads(output)
    assert json_output["bgpInMaintenanceMode"] == "Yes"
    assert json_output["bgpStartedGracefully"] == "Yes"

    logger.info("Test completed successfully")

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

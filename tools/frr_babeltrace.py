#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Usage: frr_babeltrace.py trace_path

FRR pushes data into lttng tracepoints in the least overhead way possible
i.e. as binary-data/ctf_arrays. These traces need to be converted into pretty
strings for easy greping etc. This script is a babeltrace python plugin for
that pretty printing.

Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
Anuradha Karuppiah
"""

import ipaddress
import socket
import sys

import babeltrace
import datetime

########################### common parsers - start ############################
def dplane_op2str(field_val):
    dplane_ops = {
        0: "DPLANE_OP_NONE",
        1: "DPLANE_OP_ROUTE_INSTALL",
        2: "DPLANE_OP_ROUTE_UPDATE",
        3: "DPLANE_OP_ROUTE_DELETE",
        4: "DPLANE_OP_ROUTE_NOTIFY",
        5: "DPLANE_OP_NH_INSTALL",
        6: "DPLANE_OP_NH_UPDATE",
        7: "DPLANE_OP_NH_DELETE",
        8: "DPLANE_OP_LSP_INSTALL",
        9: "DPLANE_OP_LSP_UPDATE",
        10: "DPLANE_OP_LSP_DELETE",
        11: "DPLANE_OP_LSP_NOTIFY",
        12: "DPLANE_OP_PW_INSTALL",
        13: "DPLANE_OP_PW_UNINSTALL",
        14: "DPLANE_OP_SYS_ROUTE_ADD",
        15: "DPLANE_OP_SYS_ROUTE_DELETE",
        16: "DPLANE_OP_ADDR_INSTALL",
        17: "DPLANE_OP_ADDR_UNINSTALL",
        18: "DPLANE_OP_MAC_INSTALL",
        19: "DPLANE_OP_MAC_DELETE",
        20: "DPLANE_OP_NEIGH_INSTALL",
        21: "DPLANE_OP_NEIGH_UPDATE",
        22: "DPLANE_OP_NEIGH_DELETE",
        23: "DPLANE_OP_VTEP_ADD",
        24: "DPLANE_OP_VTEP_DELETE",
        25: "DPLANE_OP_RULE_ADD",
        26: "DPLANE_OP_RULE_DELETE",
        27: "DPLANE_OP_RULE_UPDATE",
        28: "DPLANE_OP_NEIGH_DISCOVER",
        29: "DPLANE_OP_BR_PORT_UPDATE",
        30: "DPLANE_OP_IPTABLE_ADD",
        31: "DPLANE_OP_IPTABLE_DELETE",
        32: "DPLANE_OP_IPSET_ADD",
        33: "DPLANE_OP_IPSET_DELETE",
        34: "DPLANE_OP_IPSET_ENTRY_ADD",
        35: "DPLANE_OP_IPSET_ENTRY_DELETE",
        36: "DPLANE_OP_NEIGH_IP_INSTALL",
        37: "DPLANE_OP_NEIGH_IP_DELETE",
        38: "DPLANE_OP_NEIGH_TABLE_UPDATE",
        39: "DPLANE_OP_GRE_SET",
        40: "DPLANE_OP_INTF_ADDR_ADD",
        41: "DPLANE_OP_INTF_ADDR_DEL",
        42: "DPLANE_OP_INTF_NETCONFIG",
        43: "DPLANE_OP_INTF_INSTALL",
        44: "DPLANE_OP_INTF_UPDATE",
        45: "DPLANE_OP_INTF_DELETE",
        46: "DPLANE_OP_TC_QDISC_INSTALL",
        47: "DPLANE_OP_TC_QDISC_UNINSTALL",
        48: "DPLANE_OP_TC_CLASS_ADD",
        49: "DPLANE_OP_TC_CLASS_DELETE",
        50: "DPLANE_OP_TC_CLASS_UPDATE",
        51: "DPLANE_OP_TC_FILTER_ADD",
        52: "DPLANE_OP_TC_FILTER_DELETE",
        53: "DPLANE_OP_TC_FILTER_UPDATE",
        54: "DPLANE_OP_VLAN_INSTALL"
    }
    return dplane_ops.get(field_val, f"UNKNOWN_OP_{field_val}")

def dplane_res2str(field_val):
    dplane_results = {
        0: "ZEBRA_DPLANE_REQUEST_QUEUED",
        1: "ZEBRA_DPLANE_REQUEST_SUCCESS",
        2: "ZEBRA_DPLANE_REQUEST_FAILURE"
    }
    return dplane_results.get(field_val, f"UNKNOWN_RES_{field_val}")

def location_interface_nhg_reinstall(field_val):
    if field_val == 1:
        return ("Interface dependent NHE")
    elif field_val == 2:
        return ("Dependents of NHE")

def location_nhg_install(field_val):
    if field_val == 1:
        return ("Queuing NH ADD changing the type to Zebra")
    elif field_val == 2:
        return ("Queuing NH ADD")

def location_if_oper_zrecv(field_val):
    if field_val == 1:
        return ("Rx Intf address Add")
    elif field_val == 2:
        return ("Rx Intf address Delete")
    elif field_val == 3:
        return ("Rx Intf Neighbor Add")
    elif field_val == 4:
        return ("Rx Intf Neighbor Delete")

def location_netlink_nexthop_msg_encode_err(field_val):
    if field_val == 1:
        return "kernel nexthops not supported, ignoring"
    elif field_val == 2:
        return "proto-based nexthops only, ignoring"
    elif field_val == 3:
        return "labeled NHGs not supported, ignoring"


def location_netlink_vrf_change(field_val):
    if field_val == 1:
        return "IFLA_INFO_DATA missing from VRF message"
    elif field_val == 2:
        return "IFLA_VRF_TABLE missing from VRF message"


def location_get_iflink_speed(field_val):
    if field_val == 1:
        return "Failure to read interface"
    elif field_val == 2:
        return "IOCTL failure to read interface"


def location_zebra_err_string(field_val):
    if field_val == 1:
        return "IFLA_VLAN_ID missing from VLAN IF message"
    elif field_val == 2:
        return "IFLA_GRE_LOCAL missing from GRE IF message"
    elif field_val == 3:
        return "IFLA_GRE_REMOTE missing from GRE IF message"
    elif field_val == 4:
        return "IFLA_GRE_LINK missing from GRE IF message"
    elif field_val == 5:
        return "IFLA_VXLAN_ID missing from VXLAN IF message"
    elif field_val == 6:
        return "IFLA_VXLAN_LOCAL missing from VXLAN IF message"
    elif field_val == 7:
        return "IFLA_VXLAN_LINK missing from VXLAN IF message"
    elif field_val == 8:
        return "ignoring IFLA_WIRELESS message"
    elif field_val == 9:
        return "invalid Intf Name"


def location_netlink_msg_err(field_val):
    if field_val == 1:
        return "Invalid address family"
    elif field_val == 2:
        return "netlink msg bad size"
    elif field_val == 3:
        return "Invalid prefix length-V4"
    elif field_val == 4:
        return "Invalid prefix length-V6"
    elif field_val == 5:
        return "Invalid/tentative addr"
    elif field_val == 6:
        return "No local interface address"
    elif field_val == 7:
        return "wrong kernel message"


def location_netlink_intf_err(field_val):
    if field_val == 1:
        return "Local Interface Address is NULL"
    elif field_val == 2:
        return "RTM_NEWLINK for interface without MTU set"
    elif field_val == 3:
        return "Cannot find VNI for VID and IF for vlan state update"
    elif field_val == 4:
        return "Cannot find bridge-vlan IF for vlan update"
    elif field_val == 5:
        return "Ignoring non-vxlan IF for vlan update"


def location_if_add_del_upd(field_val):
    if field_val == 0:
        return ("Interface Delete")
    elif field_val == 1:
        return ("Interface Index Add")
    elif field_val == 2:
        return ("Interface Index is Shutdown. Wont Wake it up")

def location_if_protodown(field_val):
    if field_val == 1:
        return ("Intf Update Protodown")
    elif field_val == 2:
        return ("Early return if already down & reason bitfield matches")
    elif field_val == 3:
        return ("Early return if already set queued to dplane & reason bitfield matches")
    elif field_val == 4:
        return ("Early return if already unset queued to dplane & reason bitfield matches")
    elif field_val == 5:
        return ("Intf protodown dplane change")
    elif field_val == 6:
        return ("Bond Mbr Protodown on Rcvd but already sent to dplane")
    elif field_val == 7:
        return ("Bond Mbr Protodown off  Rcvd but already sent to dplane")
    elif field_val == 8:
        return ("Bond Mbr reinstate protodown in the dplane")
    elif field_val == 9:
        return ("Intf Sweeping Protodown")
    elif field_val == 10:
        return ("clear external protodown")


def location_if_upd_ctx_dplane_res(field_val):
    if field_val == 0:
        return ("Zebra Inf Upd Success")
    elif field_val == 1:
        return ("Int Zebra INFO Ptr is NULL")
    elif field_val == 2:
        return ("Int Zebra Upd Failed")

def location_if_vrf_change(field_val):
    if field_val == 0:
        return ("DPLANE_OP_INTF_DELETE")
    elif field_val == 1:
        return ("DPLANE_OP_INTF_UPDATE")

def location_if_dplane_ifp_handling(field_val):
    if field_val == 0:
        return ("RTM_DELLINK")
    elif field_val == 1:
        return ("RTM_NEWLINK UPD: Intf has gone Down-1")
    elif field_val == 2:
        return ("RTM_NEWLINK UPD: Intf PTM up, Notifying clients")
    elif field_val == 3:
        return ("RTM_NEWLINK UPD: Intf Br changed MAC Addr")
    elif field_val == 4:
        return ("RTM_NEWLINK UPD: Intf has come Up")
    elif field_val == 5:
        return ("RTM_NEWLINK UPD: Intf has gone Down-2")
    elif field_val == 6:
        return "RTM_NEWLINK UPD: ignoring PROMISCUITY change"


def location_if_dplane_ifp_handling_new(field_val):
    if field_val == 0:
        return ("RTM_NEWLINK ADD")
    elif field_val == 1:
        return ("RTM_NEWLINK UPD")

def location_if_ip_addr_add_del(field_val):
    if field_val == 0:
        return "RTM_NEWADDR IPv4"
    elif field_val == 1:
        return "RTM_DELADDR IPv4"
    elif field_val == 2:
        return "RTM_NEWADDR IPv6"
    elif field_val == 3:
        return "RTM_DELADDR IPv6"

def print_location_gr_deferral_timer_start(field_val):
    if field_val == 1:
        return ("Tier 1 deferral timer start")
    elif field_val == 2:
        return ("Tier 2 deferral timer start")

def print_location_gr_eors(field_val):
    if field_val == 1:
        return "Check all EORs"
    elif field_val == 2:
        return "All dir conn EORs rcvd"
    elif field_val == 3:
        return "All multihop EORs NOT rcvd"
    elif field_val == 4:
        return "All EORs rcvd"
    elif field_val == 5:
        return "No multihop EORs pending"
    elif field_val == 6:
        return "EOR rcvd,check path select"
    elif field_val == 7:
        return "Do deferred path selection"


def print_location_gr_eor_peer(field_val):
    if field_val == 1:
        return "EOR awaited from"
    elif field_val == 2:
        return "EOR ignore"
    elif field_val == 3:
        return "Multihop EOR awaited"
    elif field_val == 4:
        return "Ignore EOR rcvd after tier1 expiry"
    elif field_val == 5:
        return "Dir conn EOR awaited"


def print_afi_string(field_val):
    if field_val == 0:
        return "UNSPEC"
    elif field_val == 1:
        return "IPV4"
    elif field_val == 2:
        return "IPV6"
    elif field_val == 3:
        return "L2VPN"
    elif field_val == 4:
        return "MAX"


def print_safi_string(field_val):
    if field_val == 0:
        return "UNSPEC"
    elif field_val == 1:
        return "UNICAST"
    elif field_val == 2:
        return "MULTICAST"
    elif field_val == 3:
        return "MPLS_VPN"
    elif field_val == 4:
        return "ENCAP"
    elif field_val == 5:
        return "EVPN"
    elif field_val == 6:
        return "LABELED_UNICAST"
    elif field_val == 7:
        return "FLOWSPEC"
    elif field_val == 8:
        return "MAX"


def location_prefix_filter_reason(field_val):
    if field_val == 1:
        return ("Originator-id same as remote router id")
    elif field_val == 2:
        return ("Filtered via ORF")
    elif field_val == 3:
        return ("Outbound policy")


def location_attr_type_unsupported(field_val):
    if field_val == 1:
        return ("SRv6 sub sub TLV")
    elif field_val == 2:
        return ("SRv6 sub TLV")
    elif field_val == 3:
        return ("Prefix SID")


def location_bgp_err_str(field_val):
    if field_val == 1:
        return "failed in bgp_accept"
    elif field_val == 2:
        return "failed in bgp_connect"


def location_vni_transition(field_val):
    if field_val == 1:
        return "Del L2-VNI - transition to L3-VNI"
    elif field_val == 2:
        return "Adding L2-VNI - transition from L3-VNI"


def location_zevpn_build_vni_hash(field_val):
    if field_val == 1:
        return "Create l3vni hash"
    elif field_val == 2:
        return "EVPN hash already present"
    elif field_val == 3:
        return "EVPN instance does not exist"


def location_l3vni_remote_rmac(field_val):
    if field_val == 1:
        return "Add"
    elif field_val == 2:
        return "Del"

def print_location_gr_eors(field_val):
    if field_val == 1:
        return ("Check all EORs")
    elif field_val == 2:
        return ("All dir conn EORs rcvd")
    elif field_val == 3:
        return ("All multihop EORs NOT rcvd")
    elif field_val == 4:
        return ("All EORs rcvd")
    elif field_val == 5:
        return ("No multihop EORs pending")
    elif field_val == 6:
        return ("EOR rcvd,check path select")
    elif field_val == 7:
        return ("Do deferred path selection")

def print_location_gr_eor_peer(field_val):
    if field_val == 1:
        return ("EOR awaited from")
    elif field_val == 2:
        return ("EOR ignore")
    elif field_val == 3:
        return ("Multihop EOR awaited")
    elif field_val == 4:
        return ("Ignore EOR rcvd after tier1 expiry")
    elif field_val == 5:
        return ("Dir conn EOR awaited")

def print_afi_string(field_val):
    if field_val == 0:
        return ("UNSPEC")
    elif field_val == 1:
        return ("IPV4")
    elif field_val == 2:
        return ("IPV6")
    elif field_val == 3:
        return ("L2VPN")
    elif field_val == 4:
        return ("MAX")

def print_safi_string(field_val):
    if field_val == 0:
        return ("UNSPEC")
    elif field_val == 1:
        return ("UNICAST")
    elif field_val == 2:
        return ("MULTICAST")
    elif field_val == 3:
        return ("MPLS_VPN")
    elif field_val == 4:
        return ("ENCAP")
    elif field_val == 5:
        return ("EVPN")
    elif field_val == 6:
        return ("LABELED_UNICAST")
    elif field_val == 7:
        return ("FLOWSPEC")
    elif field_val == 8:
        return ("MAX")

def location_last_route_re(field_val):
    if field_val == 1:
        return ("RE updated")
    elif field_val == 2:
        return ("RE not installed")

def location_gr_client_not_found(field_val):
    if field_val == 1:
        return ("Process from GR queue")
    elif field_val == 2:
        return ("Stale route delete from table")

def print_prefix_addr(field_val):
    """
    pretty print "struct prefix"
    """
    if field_val[0] == socket.AF_INET:
        addr = [str(fv) for fv in field_val[8:12]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if field_val[0] == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val[8:24])
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not field_val[0]:
        return ""

    return field_val


def print_ip_addr(field_val):
    """
    pretty print "struct ipaddr"
    """
    if field_val[0] == socket.AF_INET:
        addr = [str(fv) for fv in field_val[4:8]]
        return str(ipaddress.IPv4Address(".".join(addr)))

    if field_val[0] == socket.AF_INET6:
        tmp = "".join("%02x" % fb for fb in field_val[4:])
        addr = []
        while tmp:
            addr.append(tmp[:4])
            tmp = tmp[4:]
        addr = ":".join(addr)
        return str(ipaddress.IPv6Address(addr))

    if not field_val[0]:
        return ""

    return field_val


def print_mac(field_val):
    """
    pretty print "u8 mac[6]"
    """
    return ":".join("%02x" % fb for fb in field_val)

def print_net_ipv4_addr(field_val):
    """
    pretty print ctf_integer_network ipv4
    """
    return str(ipaddress.IPv4Address(field_val))

def print_esi(field_val):
    """
    pretty print ethernet segment id, esi_t
    """
    return ":".join("%02x" % fb for fb in field_val)

def print_kernel_cmd(field_val):
    """
    pretty print kernel opcode to string
    """
    if field_val == 24:
        cmd_str = "RTM_NEWROUTE"
    elif field_val == 25:
        cmd_str = "RTM_DELROUTE"
    elif field_val == 26:
        cmd_str = "RTM_GETROUTE"
    else:
        cmd_str = str(field_val)

    return cmd_str


def print_family_str(field_val):
    """
    pretty print kernel family to string
    """
    if field_val == socket.AF_INET:
        cmd_str = "ipv4"
    elif field_val == socket.AF_INET6:
        cmd_str = "ipv6"
    elif field_val == socket.AF_BRIDGE:
        cmd_str = "bridge"
    elif field_val == 128: # RTNL_FAMILY_IPMR:
        cmd_str = "ipv4MR"
    elif field_val == 129: # RTNL_FAMILY_IP6MR:
        cmd_str = "ipv6MR"
    else:
        cmd_str = "Invalid family"

    return cmd_str


def print_operation_ug_create_delete(field_val):
    if field_val == 1:
        return "BGP update-group create"
    elif field_val == 2:
        return "BGP update-group delete"


def print_operation_ug_subgroup_create_delete(field_val):
    if field_val == 1:
        return "BGP update-group subgroup create"
    elif field_val == 2:
        return "BGP update-group subgroup delete"


def print_operation_ug_subgroup_add_remove_peer(field_val):
    if field_val == 1:
        return "BGP update-group subgroup add peer"
    elif field_val == 2:
        return "BGP update-group subgroup remove peer"


def get_field_list(event):
    """
    only fetch fields added via the TP, skip metadata etc.
    """
    return event.field_list_with_scope(babeltrace.CTFScope.EVENT_FIELDS)

def parse_event(event, field_parsers):
    """
    Wild card event parser; doesn"t make things any prettier
    """
    field_list = get_field_list(event)
    field_info = {}
    for field in field_list:
        if field in field_parsers:
            field_parser = field_parsers.get(field)
            field_info[field] = field_parser(event.get(field))
        else:
            field_info[field] = event.get(field)
    dt = datetime.datetime.fromtimestamp(event.timestamp/1000000000)
    dt_format = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]
    print(dt_format, event.name, field_info)


def parse_frr_bgp_router_id_update_zrecv(event):
    """
    bgp router-id update parser
    """
    field_parsers = {"router_id": print_prefix_addr}

    parse_event(event, field_parsers)


def parse_frr_interface_addr_oper_zrecv(event):
    """
    bgp interface (or nbr) address add/del parser
    """
    field_parsers = {"location" : location_if_oper_zrecv,
                     "address": print_prefix_addr}
    parse_event(event, field_parsers)


def parse_bgp_redistribute_zrecv(event):
    """
    bgp redistribute add/del parser
    """
    field_parsers = {"prefix": print_prefix_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_interface_nhg_reinstall(event):
    field_parsers = {"location" : location_interface_nhg_reinstall}

    parse_event(event, field_parsers)

def parse_frr_zebra_nhg_install(event):
    field_parsers = {"location" : location_nhg_install}

    parse_event(event, field_parsers)

def zebra_route_string(proto_val):
    zebra_routes = {
        0: "system",
        1: "kernel",
        2: "connect",
        3: "local",
        4: "static",
        5: "rip",
        6: "ripng",
        7: "ospf",
        8: "ospf6",
        9: "isis",
        10: "bgp",
        11: "pim",
        12: "eigrp",
        13: "nhrp",
        14: "hsls",
        15: "olsr",
        16: "table",
        17: "ldp",
        18: "vnc",
        19: "vnc_direct",
        20: "vnc_direct_rh",
        21: "bgp_direct",
        22: "bgp_direct_ext",
        23: "babel",
        24: "sharp",
        25: "pbr",
        26: "bfd",
        27: "openfabric",
        28: "vrrp",
        29: "nhg",
        30: "srte",
        31: "table_direct",
        32: "frr",
        33: "all",
        34: "max"
    }
    return zebra_routes.get(proto_val, f"unknown_proto_{proto_val}")
############################ common parsers - end #############################

############################ evpn parsers - start #############################
def parse_frr_bgp_evpn_mac_ip_zsend(event):
    """
    bgp evpn mac-ip parser; raw format -
    ctf_array(unsigned char, mac, &pfx->prefix.macip_addr.mac,
            sizeof(struct ethaddr))
    ctf_array(unsigned char, ip, &pfx->prefix.macip_addr.ip,
            sizeof(struct ipaddr))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "esi": print_esi,
                     "vtep": print_net_ipv4_addr,
                     "action": evpn_action_to_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_bum_vtep_zsend(event):
    """
    bgp evpn bum-vtep parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep,
            pfx->prefix.imet_addr.ip.ipaddr_v4.s_addr)

    """
    field_parsers = {"vtep": print_net_ipv4_addr,
                     "action": evpn_action_to_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_nh_rmac_zsend(event):
    """
    bgp evpn nh-rmac parser; raw format -
    ctf_array(unsigned char, rmac, &nh->rmac, sizeof(struct ethaddr))
    """
    field_parsers = {"rmac": print_mac,
                     "action": evpn_action_to_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_add_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_del_zrecv(event):
    """
    bgp evpn local-es parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv(event):
    """
    bgp evpn local-es-evi parser; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_es_evi_vtep_add(event):
    """
    bgp evpn remote ead evi remote vtep add; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_es_evi_vtep_del(event):
    """
    bgp evpn remote ead evi remote vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd(event):
    """
    bgp evpn local ead evi vtep; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del(event):
    """
    bgp evpn local ead evi vtep del; raw format -
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_vni_add_zrecv(event):
    """
    bgp evpn local-vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_integer_network_hex(unsigned int, mc_grp, mc_grp.s_addr)
    """
    field_parsers = {"vtep": print_net_ipv4_addr,
                     "mc_grp": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_l3vni_add_zrecv(event):
    """
    bgp evpn local-l3vni parser; raw format -
    ctf_integer_network_hex(unsigned int, vtep, vtep.s_addr)
    ctf_array(unsigned char, svi_rmac, svi_rmac, sizeof(struct ethaddr))
    ctf_array(unsigned char, vrr_rmac, vrr_rmac, sizeof(struct ethaddr))
    """
    field_parsers = {"vtep": print_net_ipv4_addr,
                     "svi_rmac": print_mac,
                     "vrr_rmac": print_mac,
                     "anycast_mac": lambda x: "yes" if x else "no"}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_macip_add_zrecv(event):
    """
    bgp evpn local-mac-ip parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "esi": print_esi}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_local_macip_del_zrecv(event):
    """
    bgp evpn local-mac-ip del parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_advertise_type5(event):
    """
    local originated type-5 route
    """
    field_parsers = {"ip": print_ip_addr,
                     "rmac": print_mac,
                     "vtep": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_withdraw_type5(event):
    """
    local originated type-5 route withdraw
    """
    field_parsers = {"ip": print_ip_addr}

def parse_frr_zebra_netlink_route_multipath_msg_encode(event):
    """
    bgp evpn local-mac-ip del parser; raw format -
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"pfx": print_prefix_addr,
                     "cmd": print_kernel_cmd}

    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_ipneigh_change(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_macfdb_change(event):
    """
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"mac": print_mac,
                     "vtep_ip": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_netlink_neigh_update_msg_encode(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "family": print_family_str}

    parse_event(event, field_parsers)

def parse_frr_zebra_process_remote_macip_add(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac,
                     "vtep_ip": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_process_remote_macip_del(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac,
                     "vtep_ip": print_net_ipv4_addr,
                     "location": lambda x: {
                         1: "Invalid interface state",
                         2: "VNI not in interface",
                         3: "MAC not found for neighbor",
                         4: "MAC and neighbor not found",
                         5: "Gateway MAC ignore",
                         6: "DAD freeze duplicate"
                     }.get(x, f"Unknown location {x}")}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_macip_send_msg_to_client(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac,
                     "is_add": lambda x: "Add" if x == 1 else "Del"}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_process_sync_macip_add(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_vxlan_remote_macip_add(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "esi": print_esi,
                     "mac": print_mac,
                     "vtep_ip": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_vxlan_remote_macip_del(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac,
                     "vtep_ip": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_proc_remote_nh(event):
    """
    ctf_array(unsigned char, ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, mac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"ip": print_ip_addr,
                     "mac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_nh_add(event):
    """
    dplane enqued zebra evpn remote nh (neigh) add entry
    """
    field_parsers = {"nh_ip": print_ip_addr,
                     "rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_nh_del(event):
    """
    dplane enqued zebra evpn remote nh (neigh) del entry
    """
    field_parsers = {"nh_ip": print_ip_addr,
                     "rmac": print_mac}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_rmac_add(event):
    """
    dplane enqued zebra evpn remote rmac (FDB) entry
    """
    field_parsers = {"rmac": print_mac,
                     "vtep_ip": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_dplane_remote_rmac_del(event):
    """
    dplane enqued zebra evpn remote rmac (FDB) entry
    """
    field_parsers = {"rmac": print_mac,
                     "vtep_ip": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_gr_last_rn_lookup_failed(event):
    field_parsers = {"prefix": print_prefix_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_gr_last_rn_lookup_success(event):
    field_parsers = {"prefix": print_prefix_addr}

    parse_event(event, field_parsers)


def parse_frr_zebra_gr_reinstalled_last_route(event):
    field_parsers = {"last_route": print_prefix_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_gr_last_route_info(event):
    field_parsers = {"route_type": zebra_route_string}

    parse_event(event, field_parsers)


def parse_frr_zebra_zebra_evpn_proc_remote_es(event):
    """
    ctf_array(unsigned char, esi, esi, sizeof(esi_t))
    """
    field_parsers = {"esi": print_esi,
                     "vtep_ip": print_net_ipv4_addr}

    parse_event(event, field_parsers)

def parse_frr_zebra_if_add_del_update(event):
    field_parsers = {"location" : location_if_add_del_upd}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_protodown(event):
    field_parsers = {"location" : location_if_protodown}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_upd_ctx_dplane_result(event):
    field_parsers = {"oper" : dplane_op2str,
                     "location" : location_if_upd_ctx_dplane_res}
    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_nhg_dplane_result(event):
    field_parsers = {"op" : dplane_op2str,
                     "status" : dplane_res2str}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_dplane_result(event):
    field_parsers = {"oper" : dplane_op2str,
                     "dplane_result" : dplane_res2str}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_vrf_change(event):
    field_parsers = {"location" : location_if_vrf_change}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_dplane_ifp_handling(event):
    field_parsers = {"location" : location_if_dplane_ifp_handling}
    parse_event(event, field_parsers)

def parse_frr_zebra_if_dplane_ifp_handling_new(event):
    field_parsers = {"location" : location_if_dplane_ifp_handling_new}
    parse_event(event, field_parsers)
    
def parse_frr_bgp_gr_deferral_timer_start(event):
    field_parsers = {"location": print_location_gr_deferral_timer_start,
                     "afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_deferral_timer_expiry(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string,
                     "gr_tier": lambda x: "2" if x else "1"}

    parse_event(event, field_parsers)
                    
def parse_frr_bgp_gr_eors(event):
    field_parsers = {"location": print_location_gr_eors,
                     "afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_eor_peer(event):
    field_parsers = {"location": print_location_gr_eor_peer,
                     "afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_start_deferred_path_selection(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_send_fbit_capability(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_continue_deferred_path_selection(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)

def parse_frr_bgp_gr_zebra_update(event):
    field_parsers = {"afi": print_afi_string,
                     "safi": print_safi_string}

    parse_event(event, field_parsers)



def parse_frr_zebra_if_ip_addr_add_del(event):
    field_parsers = {"location": location_if_ip_addr_add_del,
                     "address": print_prefix_addr}
    parse_event(event, field_parsers)


def parse_frr_update_prefix_filter(event):
    field_parsers = {"location" : location_prefix_filter_reason}

    parse_event(event, field_parsers)


def parse_frr_bgp_attr_type_unsupported(event):
    field_parsers = {"attr" : location_attr_type_unsupported}

    parse_event(event, field_parsers)


def parse_frr_zebra_netlink_vrf_change(event):
    field_parsers = {"location" : location_netlink_vrf_change}
    parse_event(event, field_parsers)


def parse_frr_zebra_netlink_nexthop_msg_encode_err(event):
    field_parsers = {"location" : location_netlink_nexthop_msg_encode_err}
    parse_event(event, field_parsers)


def parse_frr_zebra_get_iflink_speed(event):
    field_parsers = {"location" : location_get_iflink_speed}
    parse_event(event, field_parsers)


def parse_frr_zebra_zebra_err_string(event):
    field_parsers = {"location" : location_zebra_err_string}
    parse_event(event, field_parsers)


def parse_frr_zebra_netlink_msg_err(event):
    field_parsers = {"location" : location_netlink_msg_err}
    parse_event(event, field_parsers)


def parse_frr_zebra_netlink_intf_err(event):
    field_parsers = {"location" : location_netlink_intf_err}
    parse_event(event, field_parsers)


def parse_frr_bgp_err_str(event):
    field_parsers = {"location" : location_bgp_err_str}
    parse_event(event, field_parsers)


def parse_frr_zebra_zebra_vxlan_handle_vni_transition(event):
    field_parsers = {"location": location_vni_transition}

    parse_event(event, field_parsers)


def parse_frr_bgp_ug_create_delete(event):
    field_parsers = {"operation": print_operation_ug_create_delete}
    parse_event(event, field_parsers)


def parse_frr_bgp_ug_subgroup_create_delete(event):
    field_parsers = {"operation": print_operation_ug_subgroup_create_delete}
    parse_event(event, field_parsers)


def parse_frr_bgp_ug_subgroup_add_remove_peer(event):
    field_parsers = {"operation": print_operation_ug_subgroup_add_remove_peer}
    parse_event(event, field_parsers)


def parse_frr_bgp_ug_bgp_aggregate_install(event):
    field_parsers = {"prefix": print_prefix_addr,
                     "afi": print_afi_string,
                     "safi": print_safi_string}
    parse_event(event, field_parsers)


def parse_frr_zebra_gr_client_not_found(event):
    field_parsers = {"location" : location_gr_client_not_found}
    parse_event(event, field_parsers)


def parse_frr_zebra_zevpn_build_vni_hash(event):
    field_parsers = {"location": location_zevpn_build_vni_hash}
    parse_event(event, field_parsers)

def parse_frr_zebra_l3vni_remote_rmac_update(event):
    field_parsers = {"new_vtep": print_ip_addr,
                     "rmac": print_mac,
                     "old_vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)


def parse_frr_zebra_l3vni_remote_rmac(event):
    """
    ctf_array(unsigned char, vtep_ip, ip, sizeof(struct ipaddr))
    ctf_array(unsigned char, rmac, mac, sizeof(struct ethaddr))
    """
    field_parsers = {"vtep_ip": print_ip_addr,
                     "rmac": print_mac,
                     "location": location_l3vni_remote_rmac}

    parse_event(event, field_parsers)


def parse_frr_zebra_l3vni_remote_vtep_nh_upd(event):
    field_parsers = {"old_vtep": print_ip_addr,
                     "rmac": print_mac,
                     "new_vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)


def parse_frr_zebra_remote_nh_add_rmac_change(event):
    field_parsers = {"oldmac": print_mac,
                     "newmac": print_mac,
                     "vtep_ip": print_ip_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_last_route_re(event):
    field_parsers = {"location" : location_last_route_re,
                     "prefix": print_prefix_addr}

    parse_event(event, field_parsers)

############################ evpn parsers - end *#############################

############################ bgp per src nhg - start *#############################

soo_nhg_flag_descriptions = {
    0: "valid",
    1: "install pending",
    2: "del pending",
}

soo_rt_flag_descriptions = {
    3: "installed",
    4: "use soo nhg",
    5: "wecmp",
    6: "clear",
    7: "soo attr del",
}

rt_with_soo_flag_descriptions = {
    0: "use soo nhg",
    1: "del pending",
    2: "soo attr del",
}

def print_soo_nhg_flags(flags):
    parts = []
    for bit_position, description in soo_nhg_flag_descriptions.items():
        if flags & (1 << bit_position):
            parts.append(description)
    return ", ".join(parts)

def print_soo_rt_flags(flags):
    parts = []
    for bit_position, description in soo_rt_flag_descriptions.items():
        if flags & (1 << bit_position):
            parts.append(description)
    return ", ".join(parts)

def print_rt_with_soo_flags(flags):
    parts = []
    for bit_position, description in rt_with_soo_flag_descriptions.items():
        if flags & (1 << bit_position):
            parts.append(description)
    return ", ".join(parts)

def location_per_src_nhg_soo_timer_slot_run(field_val):
    if field_val == 1:
        return ("soo selected is subset of all route with soo, converged")

def parse_frr_bgp_per_src_nhg_soo_timer_slot_run(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags,
                     "loc": location_per_src_nhg_soo_timer_slot_run}

    parse_event(event, field_parsers)

def parse_frr_bgp_per_src_nhg_soo_timer_start(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags}

    parse_event(event, field_parsers)

def parse_frr_bgp_per_src_nhg_soo_timer_stop(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags}

    parse_event(event, field_parsers)

def parse_frr_bgp_per_src_nhg_add_send(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags}

    parse_event(event, field_parsers)

def parse_frr_bgp_per_src_nhg_del_send(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags}

    parse_event(event, field_parsers)

def location_per_src_nhg_soo_rt_dest_ecmp_check(field_val):
    if field_val == 1:
        return ("soo selected is subset of installed, ecmp shrink/lbw change, nhg replace")
    elif field_val == 2:
        return ("soo selected is superset/disjoint/overlap of installed, nhg replace after timer")

def parse_frr_bgp_per_src_nhg_soo_rt_dest_ecmp_check(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags,
                    "loc": location_per_src_nhg_soo_rt_dest_ecmp_check}

    parse_event(event, field_parsers)

def location_per_src_nhg_soo_rt_use_nhgid(field_val):
    if field_val == 1:
        return ("use soo nhgid")
    elif field_val == 2:
        return ("do not use soo nhgid")

def parse_frr_bgp_per_src_nhg_soo_rt_use_nhgid(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags,
                     "loc": location_per_src_nhg_soo_rt_use_nhgid}

    parse_event(event, field_parsers)

def location_per_src_nhg_rt_with_soo_use_nhgid(field_val):
    if field_val == 1:
        return ("do not use soo nhgid")
    elif field_val == 2:
        return ("use soo nhgid")

def parse_frr_bgp_per_src_nhg_rt_with_soo_use_nhgid(event):
    field_parsers = {"soo_rt": print_ip_addr,
                    "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags,
                     "rt_with_soo" : print_prefix_addr,
                     "rt_with_soo_flags": print_rt_with_soo_flags,
                     "loc": location_per_src_nhg_rt_with_soo_use_nhgid}

    parse_event(event, field_parsers)

def parse_frr_bgp_per_src_nhg_peer_clear_route(event):
    field_parsers = {"soo_rt": print_ip_addr,
                     "afi": print_afi_string,
                     "safi": print_safi_string,
                     "soo_nhg_flags": print_soo_nhg_flags,
                     "soo_rt_flags": print_soo_rt_flags}

    parse_event(event, field_parsers)

############################ bgp per src nhg - end *#############################

def bytes_to_ipv6(byte_list):
    """
    Converts a list of 16 bytes into a compressed IPv6 address string.

    Args:
        byte_list (list of int): A list of 16 integers between 0 and 255.

    Returns:
        str: IPv6 address in compressed string format.

    Raises:
        ValueError: If input is not 16 bytes or contains invalid values.
    """
    if len(byte_list) != 16:
        raise ValueError("Input must be a list of 16 bytes.")
    if not all(0 <= b <= 255 for b in byte_list):
        raise ValueError("Each byte must be between 0 and 255.")

    ipv6_bytes = bytes(byte_list)
    ipv6_addr = ipaddress.IPv6Address(ipv6_bytes)
    return str(ipv6_addr)

def parse_frr_zebra_release_srv6_sid(event):
    """
    Parse the release_srv6_sid trace event
    """
    field_parsers = {"sid_value": bytes_to_ipv6}
    parse_event(event, field_parsers)

def parse_frr_zebra_release_srv6_sid_func_explicit(event):
    """
    Parse the release_srv6_sid_func_explicit trace event
    """
    field_parsers = {"block_prefix": print_prefix_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_srv6_manager_get_sid_internal(event):
    """
    Parse the srv6_manager_get_sid_internal trace event
    """
    field_parsers = {"sid_value": bytes_to_ipv6}
    parse_event(event, field_parsers)

def parse_frr_zebra_get_srv6_sid(event):
    """
    Parse the get_srv6_sid trace event
    """
    field_parsers = {"sid_value": bytes_to_ipv6}
    parse_event(event, field_parsers)

def parse_frr_zebra_get_srv6_sid_explicit(event):
    """
    Parse the get_srv6_sid_explicit trace event
    """
    field_parsers = {"sid_value": bytes_to_ipv6}
    parse_event(event, field_parsers)

def location_bgp_session_state_change(field_val):
    locations = {
        1: "START_TIMER_EXPIRE",
        2: "CONNECT_TIMER_EXPIRE",
        3: "HOLDTIME_EXPIRE",
        4: "ROUTEADV_TIMER_EXPIRE",
        5: "DELAY_OPEN_TIMER_EXPIRE",
        6: "BGP_OPEN_MSG_DELAYED",
        7: "Unable to get Nbr's IP Addr, waiting..",
        8: "Waiting for NHT, no path to Nbr present",
        9: "FSM_HOLDTIME_EXPIRE",
    }
    return locations.get(field_val, f"UNKNOWN({field_val})")

def bgp_status_to_string(field_val):
    statuses = {
        1: "Idle",
        2: "Connect",
        3: "Active",
        4: "OpenSent",
        5: "OpenConfirm",
        6: "Established",
        7: "Clearing",
        8: "Deleted"
    }
    return statuses.get(field_val, f"UNKNOWN({field_val})")

def bgp_event_to_string(field_val):
    events = {
        1: "BGP_Start",
        2: "BGP_Stop",
        3: "TCP_connection_open",
        4: "TCP_connection_open_w_delay",
        5: "TCP_connection_closed",
        6: "TCP_connection_open_failed",
        7: "TCP_fatal_error",
        8: "ConnectRetry_timer_expired",
        9: "Hold_Timer_expired",
        10: "KeepAlive_timer_expired",
        11: "DelayOpen_timer_expired",
        12: "Receive_OPEN_message",
        13: "Receive_KEEPALIVE_message",
        14: "Receive_UPDATE_message",
        15: "Receive_NOTIFICATION_message",
        16: "Clearing_Completed"
    }
    return events.get(field_val, f"UNKNOWN({field_val})")

def parse_frr_bgp_session_state_change(event):
    field_parsers = {
        "location": location_bgp_session_state_change,
        "old_status": bgp_status_to_string,
        "new_status": bgp_status_to_string,
        "event": bgp_event_to_string
    }
    parse_event(event, field_parsers)

def connection_status_to_string(field_val):
    statuses = {
        0: "connect_error",
        1: "connect_success",
        2: "connect_in_progress"
    }
    return statuses.get(field_val, f"UNKNOWN({field_val})")

def parse_frr_bgp_connection_attempt(event):
    field_parsers = {
        "status": connection_status_to_string,
        "current_status": bgp_status_to_string
    }
    parse_event(event, field_parsers)

def parse_frr_bgp_fsm_event(event):
    field_parsers = {
        "event": bgp_event_to_string,
        "current_status": bgp_status_to_string,
        "next_status": bgp_status_to_string
    }
    parse_event(event, field_parsers)

def location_bgp_ifp_oper(field_val):
    if field_val == 1:
        return ("Intf UP")
    elif field_val == 2:
        return ("Intf DOWN")

def parse_frr_bgp_ifp_oper(event):
    field_parsers = {"location" : location_bgp_ifp_oper}
    parse_event(event, field_parsers)

def zapi_route_note_to_string(note_val):
    """
    Convert ZAPI route notification enum to human-readable string
    """
    notes = {
        1: "ROUTE_INSTALLED",
        2: "ROUTE_REMOVED",
        3: "ROUTE_CHANGED",
        4: "ROUTE_ADDED",
        5: "ROUTE_DELETED"
    }
    return notes.get(note_val, f"UNKNOWN({note_val})")

def parse_bgp_dest_flags(flags_val):
    """
    Parse BGP destination flags into minimal human-readable strings
    """
    flags = int(flags_val)
    flag_strings = []

    # BGP destination flags with minimal naming
    if flags & 0x00000001:  # BGP_NODE_SCHEDULE_FOR_INSTALL
        flag_strings.append("install")
    if flags & 0x00000002:  # BGP_NODE_SCHEDULE_FOR_DELETE
        flag_strings.append("delete")
    if flags & 0x00000004:  # BGP_NODE_SCHEDULE_FOR_UPDATE
        flag_strings.append("update")
    if flags & 0x00000008:  # BGP_NODE_SCHEDULE_FOR_ANNOUNCEMENT
        flag_strings.append("announce")
    if flags & 0x00000010:  # BGP_NODE_SCHEDULE_FOR_WITHDRAWAL
        flag_strings.append("withdraw")
    if flags & 0x00000020:  # BGP_NODE_SCHEDULE_FOR_IMPORT
        flag_strings.append("import")
    if flags & 0x00000040:  # BGP_NODE_SCHEDULE_FOR_EXPORT
        flag_strings.append("export")
    if flags & 0x00000080:  # BGP_NODE_SCHEDULE_FOR_AGGREGATION
        flag_strings.append("aggregate")
    if flags & 0x00000100:  # BGP_NODE_SCHEDULE_FOR_ORIGINATION
        flag_strings.append("originate")
    if flags & 0x00000200:  # BGP_NODE_SCHEDULE_FOR_ANNOUNCEMENT_TO_ZEBRA
        flag_strings.append("zebra_announce")
    if flags & 0x00000400:  # BGP_NODE_SCHEDULE_FOR_WITHDRAWAL_FROM_ZEBRA
        flag_strings.append("zebra_withdraw")

    if not flag_strings:
        return "none"

    return " | ".join(flag_strings)

def parse_frr_bgp_bgp_zebra_route_notify_owner(event):
    field_parsers = {
        "route_status": zapi_route_note_to_string,
        "dest_flags": parse_bgp_dest_flags,
        "prefix": print_prefix_addr
    }
    parse_event(event, field_parsers)

def parse_frr_bgp_bgp_zebra_process_local_ip_prefix_zrecv(event):
    field_parsers = {"prefix": print_prefix_addr}
    parse_event(event, field_parsers)

def location_bgp_zebra_radv_operation(field_val):
    locations = {
        1: "Initiating",
        2: "Terminating"
    }
    return locations.get(field_val, f"UNKNOWN({field_val})")

def parse_frr_bgp_bgp_zebra_radv_operation(event):
    field_parsers = {"location": location_bgp_zebra_radv_operation}
    parse_event(event, field_parsers)

def location_bgp_zebra_evpn_advertise_type(field_val):
    if field_val == 1:
        return "Subnet advertisement"
    elif field_val == 2:
        return "SVI MAC-IP advertisement"
    elif field_val == 3:
        return "Gateway MAC-IP advertisement"
    elif field_val == 4:
        return "All VNI advertisement"
    else:
        return f"Unknown location ({field_val})"

def parse_frr_bgp_bgp_zebra_evpn_advertise_type(event):
    """
    bgp zebra advertise unified parser with location
    Location values:
    1 - Subnet advertisement
    2 - SVI MAC-IP advertisement
    3 - Gateway MAC-IP advertisement
    4 - All VNI advertisement
    """
    field_parsers = {"location": location_bgp_zebra_evpn_advertise_type}
    parse_event(event, field_parsers)

def parse_frr_bgp_bgp_zebra_vxlan_flood_control(event):
    field_parsers = {"flood_enabled": lambda x: "Flooding Enabled" if x else "Flooding Disabled"}
    parse_event(event, field_parsers)

def evpn_action_to_string(action_val):
    return "add" if action_val else "del"

def evpn_type_to_string(type_val):
    return "v4" if type_val else "v6"

def parse_frr_bgp_evpn_mh_vtep_zsend(event):
    field_parsers = {
        "action": evpn_action_to_string,
        "vtep": print_net_ipv4_addr,
        "esi": print_esi
    }
    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_nhg_zsend(event):
    field_parsers = {
        "action": evpn_action_to_string,
        "type": evpn_type_to_string,
        "esi": print_esi
    }
    parse_event(event, field_parsers)

def parse_frr_bgp_evpn_mh_nh_zsend(event):
    field_parsers = {"vtep": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_bgp_upd_rmac_is_self_mac(event):
    field_parsers = {"rmac": print_mac}
    parse_event(event, field_parsers)

def parse_frr_zebra_zsend_redistribute_route(event):
    field_parsers = {"client_proto": zebra_route_string,
                     "api_type": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_send_add_to_client(event):
    field_parsers = {"client_proto": zebra_route_string,
                     "vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_send_del_to_client(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_zread_nhg_add(event):
    field_parsers = {"proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_zread_nhg_del(event):
    field_parsers = {"proto": zebra_route_string}
    parse_event(event, field_parsers)


def parse_frr_zebra_zebra_evpn_svi_macip_del_for_evpn_hash(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_dplane_vtep_add(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_dplane_vtep_delete(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_evpn_gw_macip_del_for_evpn_hash(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_vxlan_remote_vtep_add(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_zevpn_build_l2vni_hash(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_arp_nd_failover_enable(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_evpn_arp_nd_udp_sock_create(event):
    field_parsers = {"vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_stale_client_cleanup(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_client_info_delete(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_client_disconnect_stale_exists(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_client_disconnect_stale_timer(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_delete_stale_client(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_free_stale_client(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_client_reconnect(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_client_cap_decode_err(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_gr_process_client_stale_routes(event):
    field_parsers = {"client_proto": zebra_route_string}
    parse_event(event, field_parsers)

def parse_frr_zebra_zebra_vxlan_remote_vtep_del(event):
    field_parsers = {"client_proto": zebra_route_string,
                     "vtep_ip": print_net_ipv4_addr}
    parse_event(event, field_parsers)

def main():
    """
    FRR lttng trace output parser; babel trace plugin
    """
    event_parsers = {"frr_bgp:evpn_mac_ip_zsend":
                     parse_frr_bgp_evpn_mac_ip_zsend,
                     "frr_bgp:evpn_bum_vtep_zsend":
                     parse_frr_bgp_evpn_bum_vtep_zsend,
                     "frr_bgp:evpn_mh_nh_rmac_zsend":
                     parse_frr_bgp_evpn_mh_nh_rmac_zsend,
                     "frr_bgp:evpn_mh_vtep_zsend":
                     parse_frr_bgp_evpn_mh_vtep_zsend,
                     "frr_bgp:evpn_mh_nh_zsend":
                     parse_frr_bgp_evpn_mh_nh_zsend,
                     "frr_bgp:evpn_mh_nhg_zsend":
                     parse_frr_bgp_evpn_mh_nhg_zsend,
                     "frr_bgp:evpn_mh_local_es_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_del_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_add_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_add_zrecv,
                     "frr_bgp:evpn_mh_local_es_evi_del_zrecv":
                     parse_frr_bgp_evpn_mh_local_es_evi_del_zrecv,
                     "frr_bgp:evpn_mh_es_evi_vtep_add":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_add,
                     "frr_bgp:evpn_mh_es_evi_vtep_del":
                     parse_frr_bgp_evpn_mh_es_evi_vtep_del,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_upd":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_upd,
                     "frr_bgp:evpn_mh_local_ead_es_evi_route_del":
                     parse_frr_bgp_evpn_mh_local_ead_es_evi_route_del,
                     "frr_bgp:evpn_local_vni_add_zrecv":
                     parse_frr_bgp_evpn_local_vni_add_zrecv,
                     "frr_bgp:evpn_local_l3vni_add_zrecv":
                     parse_frr_bgp_evpn_local_l3vni_add_zrecv,
                     "frr_bgp:evpn_local_macip_add_zrecv":
                     parse_frr_bgp_evpn_local_macip_add_zrecv,
                     "frr_bgp:evpn_local_macip_del_zrecv":
                     parse_frr_bgp_evpn_local_macip_del_zrecv,
                     "frr_bgp:evpn_advertise_type5":
                     parse_frr_bgp_evpn_advertise_type5,
                     "frr_bgp:evpn_withdraw_type5":
                     parse_frr_bgp_evpn_withdraw_type5,
                     "frr_zebra:netlink_route_multipath_msg_encode":
                     parse_frr_zebra_netlink_route_multipath_msg_encode,
                     "frr_zebra:netlink_ipneigh_change":
                     parse_frr_zebra_netlink_ipneigh_change,
                     "frr_zebra:netlink_macfdb_change":
                     parse_frr_zebra_netlink_macfdb_change,
                     "frr_zebra:netlink_neigh_update_msg_encode":
                     parse_frr_zebra_netlink_neigh_update_msg_encode,
                     "frr_zebra:process_remote_macip_add":
                     parse_frr_zebra_process_remote_macip_add,
                     "frr_zebra:process_remote_macip_del":
                     parse_frr_zebra_process_remote_macip_del,
                     "frr_zebra:zebra_evpn_macip_send_msg_to_client":
                     parse_frr_zebra_zebra_evpn_macip_send_msg_to_client,
                     "frr_zebra:zebra_evpn_process_sync_macip_add":
                     parse_frr_zebra_zebra_evpn_process_sync_macip_add,
                     "frr_zebra:zebra_vxlan_remote_macip_add":
                     parse_frr_zebra_zebra_vxlan_remote_macip_add,
                     "frr_zebra:zebra_vxlan_remote_macip_del":
                     parse_frr_zebra_zebra_vxlan_remote_macip_del,
                     "frr_zebra:zebra_evpn_proc_remote_nh":
                     parse_frr_zebra_zebra_evpn_proc_remote_nh,
                     "frr_zebra:evpn_dplane_remote_nh_add":
                     parse_frr_zebra_evpn_dplane_remote_nh_add,
                     "frr_zebra:evpn_dplane_remote_nh_del":
                     parse_frr_zebra_evpn_dplane_remote_nh_del,
                     "frr_zebra:evpn_dplane_remote_rmac_add":
                     parse_frr_zebra_evpn_dplane_remote_rmac_add,
                     "frr_zebra:evpn_dplane_remote_rmac_del":
                     parse_frr_zebra_evpn_dplane_remote_rmac_del,
                     "frr_zebra:zebra_evpn_proc_remote_es":
                     parse_frr_zebra_zebra_evpn_proc_remote_es,
                     "frr_zebra:zebra_evpn_svi_macip_del_for_evpn_hash":
                     parse_frr_zebra_zebra_evpn_svi_macip_del_for_evpn_hash,
                     "frr_zebra:dplane_vtep_add":
                     parse_frr_zebra_dplane_vtep_add,
                     "frr_zebra:dplane_vtep_delete":
                     parse_frr_zebra_dplane_vtep_delete,
                     "frr_zebra:zebra_evpn_gw_macip_del_for_evpn_hash":
                     parse_frr_zebra_zebra_evpn_gw_macip_del_for_evpn_hash,
                     "frr_zebra:zebra_vxlan_remote_vtep_add":
                     parse_frr_zebra_zebra_vxlan_remote_vtep_add,
                     "frr_zebra:zevpn_build_l2vni_hash":
                     parse_frr_zebra_zevpn_build_l2vni_hash,
                     "frr_zebra:evpn_arp_nd_failover_enable":
                     parse_frr_zebra_evpn_arp_nd_failover_enable,
                     "frr_zebra:evpn_arp_nd_udp_sock_create":
                     parse_frr_zebra_evpn_arp_nd_udp_sock_create,
                     "frr_zebra:if_add_del_update":
                     parse_frr_zebra_if_add_del_update,
                     "frr_zebra:if_protodown":
                     parse_frr_zebra_if_protodown,
                     "frr_zebra:if_upd_ctx_dplane_result":
                     parse_frr_zebra_if_upd_ctx_dplane_result,
                     "frr_zebra:zebra_nhg_dplane_result":
                     parse_frr_zebra_zebra_nhg_dplane_result,
                     "frr_zebra:if_dplane_result":
                     parse_frr_zebra_if_dplane_result,
                     "frr_zebra:if_vrf_change":
                     parse_frr_zebra_if_vrf_change,
                     "frr_zebra:if_dplane_ifp_handling":
                     parse_frr_zebra_if_dplane_ifp_handling,
                     "frr_zebra:if_dplane_ifp_handling_new":
                     parse_frr_zebra_if_dplane_ifp_handling_new,
                     "frr_zebra:if_ip_addr_add_del":
                     parse_frr_zebra_if_ip_addr_add_del,
                     "frr_bgp:gr_deferral_timer_start":
                     parse_frr_bgp_gr_deferral_timer_start,
                     "frr_bgp:gr_deferral_timer_expiry":
                     parse_frr_bgp_gr_deferral_timer_expiry,
                     "frr_bgp:gr_eors":
                     parse_frr_bgp_gr_eors,
                     "frr_bgp:gr_eor_peer":
                     parse_frr_bgp_gr_eor_peer,
                     "frr_bgp:gr_start_deferred_path_selection":
                     parse_frr_bgp_gr_start_deferred_path_selection,
                     "frr_bgp:gr_send_fbit_capability":
                     parse_frr_bgp_gr_send_fbit_capability,
                     "frr_bgp:gr_continue_deferred_path_selection":
                     parse_frr_bgp_gr_continue_deferred_path_selection,
                     "frr_bgp:gr_zebra_update":
                     parse_frr_bgp_gr_zebra_update,
                     "frr_bgp:router_id_update_zrecv":
                     parse_frr_bgp_router_id_update_zrecv,
                     "frr_bgp:interface_address_oper_zrecv":
                     parse_frr_interface_addr_oper_zrecv,
                     "frr_bgp:bgp_redistribute_add_zrecv":
                     parse_bgp_redistribute_zrecv,
                     "frr_bgp:bgp_redistribute_delete_zrecv":
                     parse_bgp_redistribute_zrecv,
                     "frr_bgp:upd_prefix_filtered_due_to":
                     parse_frr_update_prefix_filter,
                     "frr_bgp:upd_attr_type_unsupported":
                     parse_frr_bgp_attr_type_unsupported,
                     "frr_bgp:upd_rmac_is_self_mac":
                     parse_frr_bgp_upd_rmac_is_self_mac,
                     "frr_bgp:per_src_nhg_soo_timer_slot_run":
                     parse_frr_bgp_per_src_nhg_soo_timer_slot_run,
                     "frr_bgp:per_src_nhg_soo_timer_start":
                     parse_frr_bgp_per_src_nhg_soo_timer_start,
                     "frr_bgp:per_src_nhg_soo_timer_stop":
                     parse_frr_bgp_per_src_nhg_soo_timer_stop,
                     "frr_bgp:per_src_nhg_add_send":
                     parse_frr_bgp_per_src_nhg_add_send,
                     "frr_bgp:per_src_nhg_del_send":
                     parse_frr_bgp_per_src_nhg_del_send,
                     "frr_bgp:per_src_nhg_soo_rt_dest_ecmp_check":
                     parse_frr_bgp_per_src_nhg_soo_rt_dest_ecmp_check,
                     "frr_bgp:per_src_nhg_soo_rt_use_nhgid":
                     parse_frr_bgp_per_src_nhg_soo_rt_use_nhgid,
                     "frr_bgp:per_src_nhg_rt_with_soo_use_nhgid":
                     parse_frr_bgp_per_src_nhg_rt_with_soo_use_nhgid,
                     "frr_bgp:per_src_nhg_peer_clear_route":
                     parse_frr_bgp_per_src_nhg_peer_clear_route,
                     "frr_bgp:session_state_change":
                     parse_frr_bgp_session_state_change,
                     "frr_bgp:connection_attempt":
                     parse_frr_bgp_connection_attempt,
                     "frr_bgp:fsm_event":
                     parse_frr_bgp_fsm_event,
                     "frr_bgp:bgp_ifp_oper":
                     parse_frr_bgp_ifp_oper,
                     "frr_bgp:bgp_zebra_process_local_ip_prefix_zrecv":
                     parse_frr_bgp_bgp_zebra_process_local_ip_prefix_zrecv,
                     "frr_bgp:bgp_zebra_radv_operation":
                     parse_frr_bgp_bgp_zebra_radv_operation,
                     "frr_bgp:bgp_zebra_evpn_advertise_type":
                     parse_frr_bgp_bgp_zebra_evpn_advertise_type,
                     "frr_bgp:bgp_zebra_vxlan_flood_control":
                     parse_frr_bgp_bgp_zebra_vxlan_flood_control,
                     "frr_bgp:bgp_zebra_route_notify_owner":
                     parse_frr_bgp_bgp_zebra_route_notify_owner,
                     "frr_zebra:gr_last_route_re":
                     parse_frr_zebra_gr_last_route_re,
                     "frr_zebra:netlink_vrf_change":
                     parse_frr_zebra_netlink_vrf_change,
                     "frr_zebra:netlink_nexthop_msg_encode_err":
                     parse_frr_zebra_netlink_nexthop_msg_encode_err,
                     "frr_zebra:get_iflink_speed":
                     parse_frr_zebra_get_iflink_speed,
                     "frr_zebra:z_err_string":
                     parse_frr_zebra_zebra_err_string,
                     "frr_zebra:netlink_msg_err":
                     parse_frr_zebra_netlink_msg_err,
                     "frr_zebra:netlink_intf_err":
                     parse_frr_zebra_netlink_intf_err,
                     "frr_bgp:bgp_err_str":
                     parse_frr_bgp_err_str,
                     "frr_bgp:ug_create_delete":
                     parse_frr_bgp_ug_create_delete,
                     "frr_bgp:ug_subgroup_create_delete":
                     parse_frr_bgp_ug_subgroup_create_delete,
                     "frr_bgp:ug_subgroup_add_remove_peer":
                     parse_frr_bgp_ug_subgroup_add_remove_peer,
                     "frr_bgp:ug_bgp_aggregate_install":
                     parse_frr_bgp_ug_bgp_aggregate_install,
                     "frr_zebra:zebra_vxlan_handle_vni_transition":
                     parse_frr_zebra_zebra_vxlan_handle_vni_transition,
                     "frr_zebra:gr_client_not_found":
                     parse_frr_zebra_gr_client_not_found,
                     "frr_zebra:gr_stale_client_cleanup":
                     parse_frr_zebra_gr_stale_client_cleanup,
                     "frr_zebra:gr_client_info_delete":
                     parse_frr_zebra_gr_client_info_delete,
                     "frr_zebra:gr_client_disconnect_stale_exists":
                     parse_frr_zebra_gr_client_disconnect_stale_exists,
                     "frr_zebra:gr_client_disconnect_stale_timer":
                     parse_frr_zebra_gr_client_disconnect_stale_timer,
                     "frr_zebra:gr_delete_stale_client":
                     parse_frr_zebra_gr_delete_stale_client,
                     "frr_zebra:gr_free_stale_client":
                     parse_frr_zebra_gr_free_stale_client,
                     "frr_zebra:gr_client_reconnect":
                     parse_frr_zebra_gr_client_reconnect,
                     "frr_zebra:gr_client_cap_decode_err":
                     parse_frr_zebra_gr_client_cap_decode_err,
                     "frr_zebra:gr_process_client_stale_routes":
                     parse_frr_zebra_gr_process_client_stale_routes,
                     "frr_zebra:gr_last_rn_lookup_failed":
                     parse_frr_zebra_gr_last_rn_lookup_failed,
                     "frr_zebra:gr_last_rn_lookup_success":
                     parse_frr_zebra_gr_last_rn_lookup_success,
                     "frr_zebra:gr_reinstalled_last_route":
                     parse_frr_zebra_gr_reinstalled_last_route,
                     "frr_zebra:gr_last_route_info":
                     parse_frr_zebra_gr_last_route_info,
                     "frr_zebra:zevpn_build_vni_hash":
                     parse_frr_zebra_zevpn_build_vni_hash,
                     "frr_zebra:l3vni_remote_rmac_update":
                     parse_frr_zebra_l3vni_remote_rmac_update,
                     "frr_zebra:l3vni_remote_rmac":
                     parse_frr_zebra_l3vni_remote_rmac,
                     "frr_zebra:l3vni_remote_vtep_nh_upd":
                     parse_frr_zebra_l3vni_remote_vtep_nh_upd,
                     "frr_zebra:remote_nh_add_rmac_change":
                     parse_frr_zebra_remote_nh_add_rmac_change,
                     "frr_zebra:zebra_interface_nhg_reinstall":
                     parse_frr_zebra_interface_nhg_reinstall,
                     "frr_zebra:zebra_nhg_install_kernel":
                     parse_frr_zebra_nhg_install,
                     "frr_zebra:release_srv6_sid":
                     parse_frr_zebra_release_srv6_sid,
                     "frr_zebra:release_srv6_sid_func_explicit":
                     parse_frr_zebra_release_srv6_sid_func_explicit,
                     "frr_zebra:srv6_manager_get_sid_internal":
                     parse_frr_zebra_srv6_manager_get_sid_internal,
                     "frr_zebra:get_srv6_sid":
                     parse_frr_zebra_get_srv6_sid,
                     "frr_zebra:get_srv6_sid_explicit":
                     parse_frr_zebra_get_srv6_sid_explicit,
                     "frr_zebra:zebra_vxlan_remote_vtep_del":
                     parse_frr_zebra_zebra_vxlan_remote_vtep_del,
                     "frr_zebra:zsend_redistribute_route":
                     parse_frr_zebra_zsend_redistribute_route,
                     "frr_zebra:zebra_evpn_send_add_to_client":
                     parse_frr_zebra_zebra_evpn_send_add_to_client,
                     "frr_zebra:zebra_evpn_send_del_to_client":
                     parse_frr_zebra_zebra_evpn_send_del_to_client,
                     "frr_zebra:zread_nhg_add":
                     parse_frr_zebra_zread_nhg_add,
                     "frr_zebra:zread_nhg_del":
                     parse_frr_zebra_zread_nhg_del,

}

    # get the trace path from the first command line argument
    trace_path = sys.argv[1]

    # grab events
    trace_collection = babeltrace.TraceCollection()
    trace_collection.add_traces_recursive(trace_path, "ctf")

    for event in trace_collection.events:
        if event.name in event_parsers:
            event_parser = event_parsers.get(event.name)
            event_parser(event)
        else:
            parse_event(event, {})

if __name__ == "__main__":
    main()

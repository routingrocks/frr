# BGP ECMP eBGP Test

## Overview

This test validates Equal Cost Multi-Path (ECMP) functionality with eBGP routing. The test ensures that routes are properly advertised, received from multiple sources, and installed as multipath routes.

## Topology

```
AS 100 (r1) ---- r2 (AS 200) ---- AS 100 (r3)
```

## Test Objectives

- Verify BGP route advertisement from multiple sources
- Validate ECMP route reception and installation
- Test multipath load balancing functionality
- Ensure proper route counting and statistics

## Key Features

- **Same AS Path**: r1 and r3 are both in AS 100, creating equal-cost paths
- **eBGP Multipath**: r2 is configured with `maximum-paths ebgp 2`
- **Route Origination**: Both r1 and r3 originate the test route `192.168.1.0/24`

## Test Scenarios

### 1. Basic Topology Test
- Verify all routers are accessible
- Check BGP daemon status

### 2. BGP Convergence Test
- Wait for BGP sessions to establish
- Verify all neighbors are in Established state

### 3. ECMP Route Advertisement and Installation Test
- Verify r1 and r3 originate the route
- Check r2 receives the route from both r1 and r3
- Validate multipath indicators and path counts
- **JSON-based verification** for precise route reception validation
- **IP routing table installation** verification
- **Detailed route path verification** in routing table (load balancing validation)

### 4. ECMP Route Counting Test
- Validate route statistics and counts
- Check BGP summary information

## Route Reception Verification Methods

The enhanced test uses multiple methods to verify that R2 receives the route from both R1 and R3:

### Method 1: JSON-Based Verification (Primary)
```bash
# Get JSON output of BGP table
show bgp ipv4 unicast json
```

**Expected JSON Structure:**
```json
{
  "vrfId": 0,
  "vrfName": "default",
  "tableVersion": 2,
  "routerId": "10.0.1.2",
  "defaultLocPrf": 100,
  "localAS": 200,
  "routes": {
    "192.168.1.0/24": [
      {
        "valid": true,
        "bestpath": true,
        "selectionReason": "Older Path",
        "multipath": true,
        "pathFrom": "external",
        "prefix": "192.168.1.0",
        "prefixLen": 24,
        "network": "192.168.1.0/24",
        "version": 2,
        "metric": 0,
        "weight": 0,
        "peerId": "10.0.1.1",
        "path": "100",
        "origin": "IGP",
        "nexthops": [
          {
            "ip": "10.0.1.1",
            "hostname": "r1",
            "afi": "ipv4",
            "used": true
          }
        ]
      },
      {
        "valid": true,
        "multipath": true,
        "pathFrom": "external",
        "prefix": "192.168.1.0",
        "prefixLen": 24,
        "network": "192.168.1.0/24",
        "version": 2,
        "metric": 0,
        "weight": 0,
        "peerId": "10.0.2.3",
        "path": "100",
        "origin": "IGP",
        "nexthops": [
          {
            "ip": "10.0.2.3",
            "hostname": "r3",
            "afi": "ipv4",
            "used": true
          }
        ]
      }
    ]
  },
  "numPrefixes": 1
}
```

**JSON Verification Points:**
- ✅ Route exists in `routes["192.168.1.0/24"]`
- ✅ Exactly 2 paths in the array
- ✅ Both next-hops: `10.0.1.1` and `10.0.2.3` in `nexthops[].ip`
- ✅ Both peer IDs: `10.0.1.1` and `10.0.2.3` in `peerId`
- ✅ Multipath flag set to `true`
- ✅ Both paths marked as `valid`

### Method 2: BGP Table Analysis
```bash
# Check for both next-hops in BGP table
show bgp ipv4 unicast
```
**Expected Output:**
```
Network          Next Hop            Metric LocPrf Weight Path
*> 192.168.1.0/24   10.0.1.1                 0             0 100 i
*=                  10.0.2.3                 0             0 100 i
```

### Method 3: Detailed Route Information
```bash
# Check detailed route information
show bgp ipv4 unicast 192.168.1.0
```
**Expected Output:**
```
BGP routing table entry for 192.168.1.0/24, version 2
Paths: (2 available, best #1, table default)
  100
    10.0.1.1 from 10.0.1.1 (10.0.1.1)
      Origin IGP, metric 0, valid, external, multipath, best (Older Path)
  100
    10.0.2.3 from 10.0.2.3 (10.0.2.3)
      Origin IGP, metric 0, valid, external, multipath
```

### Method 4: BGP Summary Verification
```bash
# Check BGP summary for route counts
show bgp summary
```
**Expected Output:**
```
Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt
10.0.1.1        4        100         4         5        2    0    0 00:00:08            1        1
10.0.2.3        4        100         4         5        2    0    0 00:00:07            1        1
```

### Method 5: Neighbor-Specific Route Verification
```bash
# Check routes received from specific neighbors
show bgp neighbor 10.0.1.1 received-routes
show bgp neighbor 10.0.2.3 received-routes
```

### Method 6: Routing Table Verification
```bash
# Check routing table for ECMP installation
show ip route 192.168.1.0
```
**Expected Output:**
```
Routing entry for 192.168.1.0/24
  Known via "bgp", distance 20, metric 0, best
  * 10.0.1.1, via r2-eth0, weight 1
  * 10.0.2.3, via r2-eth1, weight 1
```

## JSON Verification Advantages

### **Precision:**
- **Exact Path Count**: JSON provides exact number of paths
- **Next-Hop Validation**: Direct access to next-hop information
- **Multipath Status**: Boolean flag for multipath indication
- **Path Details**: Complete path information in structured format

### **Programmatic Parsing:**
- **No String Parsing**: No need to parse text output
- **Structured Data**: Direct access to route properties
- **Mandatory JSON**: Test fails immediately if JSON parsing fails
- **Extensible**: Easy to add new verification criteria

### **Reliability:**
- **Consistent Format**: JSON structure is stable across FRR versions
- **No Regex**: Avoids complex regular expressions
- **Type Safety**: JSON parsing provides data type validation
- **Debugging**: Easy to log and inspect JSON structure
- **No Fallback**: Ensures JSON output is always used for verification

## Configuration Highlights

### r2 (ECMP Router)
```bash
router bgp 200
 maximum-paths ebgp 2  # Enable eBGP multipath
```

### r1 and r3 (Route Originators)
```bash
router bgp 100
 address-family ipv4 unicast
  network 192.168.1.0/24  # Originate test route
```

## Running the Test

```bash
cd /work/penta-01/vaideeshr/docker-home/frr_topotest_v2
pytest frr/tests/topotests/bgp_ecmp_ebgp/test_bgp_ecmp_ebgp.py -v
```

## Expected Results

- All 4 tests should pass
- R2 should show 2 total paths for 192.168.1.0/24
- Both paths should be marked as multipath
- Routing table should show both next-hops
- BGP summary should show PfxRcd > 0 for both neighbors
- JSON verification should confirm both next-hops present
- IP routing table should show both paths installed
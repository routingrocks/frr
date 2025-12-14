# BFD LTTng Tracing Support

This document describes how to use the LTTng tracing support in FRR BFD.

## Overview

BFD LTTng support provides comprehensive production-optimized tracing of BFD protocol events including:
- Session lifecycle (creation/deletion/enable/disable/labeling)
- State transitions and operational changes
- Packet validation errors and session lookup failures
- Remote peer events (discriminator changes)
- Timer negotiation and configuration
- Authentication events (success/failure)
- Profile and echo mode configuration changes
- Control socket client management
- Data plane interactions (session updates, echo, socket errors)

**Key Features:**
- Binary field format for minimal overhead (no string serialization)
- Consolidated paired events using boolean flags
- Production-safe tracing with no high-frequency events
- Numeric error codes for efficient filtering

## Building with LTTng Support

To build FRR with BFD LTTng support, configure with:

```bash
./configure --enable-bfd-lttng
make
```

This requires the `lttng-ust` development package to be installed on your system.

## Available Tracepoints

### Session Lifecycle (4 tracepoints)
- `session_lifecycle`: BFD session created or deleted (consolidated with is_create flag)
- `session_enable_event`: BFD session enabled or disabled (consolidated with is_enable flag)
- `session_label_update`: Session assigned a human-readable label
- `state_change`: BFD state machine transition (UP/DOWN/INIT/ADM_DOWN)

### Packet Events (6 tracepoints)
- `packet_validation_error`: Invalid packet received (TTL, version, discriminator, etc.)
  - Error codes: 1=PACKET_TOO_SMALL, 2=INVALID_TTL, 3=BAD_VERSION, 4=ZERO_DETECT_MULT, 5=INVALID_LENGTH, 6=MULTIPOINT_SET, 7=ZERO_DISCRIMINATOR, 8=WRONG_VRF
  - Includes packet context (mhop, peer_addr, local_addr) and error_value/expected_value
- `packet_session_not_found`: Control packet received for non-existent session
  - Includes packet context (mhop, peer_addr, local_addr, remote_discr)
- `packet_remote_discr_zero`: Remote discriminator is zero but session not DOWN/ADM_DOWN
  - Includes packet context and session_state
- `packet_ttl_exceeded`: TTL less than session's mh_ttl (multihop only)
  - Includes actual_ttl and expected_min_ttl
- `remote_discriminator_change`: Remote peer discriminator changed (peer restarted)
  - Includes packet context (mhop, peer_addr, local_addr)
- `echo_packet_error`: Echo packet validation errors
  - Error codes: 1=PACKET_TOO_SMALL, 2=ZERO_DISCRIMINATOR

### Authentication (1 tracepoint)
- `auth_event`: BFD packet authentication result (consolidated with is_success flag)
  - Includes packet context (mhop, peer_addr, local_addr)

### Configuration & Timers (3 tracepoints)
- `profile_apply`: BFD profile applied to session
- `echo_mode_change`: Echo mode enabled/disabled
- `timer_negotiation`: Timer values negotiated after poll/final sequence

### Control Socket (2 tracepoints)
- `control_notify`: Notification sent to clients (zebra, PIM, OSPF, BGP)
- `control_client_event`: Control socket client connect/disconnect (consolidated with is_connect flag)

### Data Plane (4 tracepoints)
- `dplane_session_not_found`: Data plane session lookup failure
- `dplane_session_update`: Session add/delete/update to data plane (consolidated with is_add flag)
- `dplane_echo`: Echo request/reply between data plane and bfdd (consolidated with is_request flag)
- `dplane_init_error`: Data plane socket errors
  - Operation codes: 1=socket, 2=bind, 3=listen, 4=accept, 5=connect, 6=setsockopt_reuseaddr

## Using LTTng

### Starting a tracing session

```bash
# Create a session
lttng create bfd_session

# Enable BFD tracepoints
lttng enable-event -u frr_bfd:*

# Start tracing
lttng start

# Run your BFD operations
# ...

# Stop tracing
lttng stop

# View traces
lttng view

# Destroy session
lttng destroy
```

### Viewing traces with babeltrace

```bash
# Convert to text format (raw values)
babeltrace ~/lttng-traces/bfd_session-*/

# Use FRR's pretty-printer for human-readable output (recommended)
/usr/lib/frr/frr_babeltrace.py ~/lttng-traces/bfd_session-*/

# Convert to CTF format for analysis
babeltrace --output-format=ctf ~/lttng-traces/bfd_session-*/
```

**Note:** The `frr_babeltrace.py` script includes custom parsers for all 23 BFD events:

**Session Lifecycle & State:**
- `session_lifecycle` - Converts is_create to "CREATE"/"DELETE", family to "IPv4"/"IPv6"
- `session_enable_event` - Converts to "ENABLE"/"DISABLE" and state names
- `state_change` - Converts state codes to "UP"/"DOWN"/"INIT"/"ADM_DOWN" and diagnostic codes
- `control_notify` - Converts notification state to readable format

**Packet & Authentication:**
- `packet_validation_error` - Converts error codes to strings (e.g., "PACKET_TOO_SMALL")
- `packet_session_not_found` - Converts family to "IPv4"/"IPv6"
- `auth_event` - Converts to "SUCCESS"/"FAILURE" and authentication type names

**Configuration & Timers:**
- `echo_mode_change` - Converts echo_enabled to "ENABLED"/"DISABLED"

**Control Socket:**
- `control_client_event` - Converts is_connect to "CONNECT"/"DISCONNECT"
- `control_protocol_error` - Converts error_type to descriptive strings

**Data Plane:**
- `dplane_init_error` - Converts operation codes to names (e.g., "socket", "connect") and errno to messages
- `dplane_session_update` - Converts is_add to "ADD"/"DELETE"
- `dplane_echo` - Converts is_request to "REQUEST"/"REPLY"

**Zebra Integration:**
- `vrf_lifecycle` - Converts action codes to "CREATE"/"DELETE"/"ENABLE"/"DISABLE"
- `zebra_interface_event` - Converts action codes to "ADD"/"DELETE"/"UP"/"DOWN"
- `zebra_address_event` - Converts action to "ADD"/"DELETE" and family to "IPv4"/"IPv6"

**PTM Events:**
- `ptm_session_event` - Session operations with full session info (addresses, refcount, diag)
- `ptm_client_event` - Client operations (register/deregister with pid)
- `ptm_config_refcount_error` - CLI session with refcount=0 bug (with session addresses)
- `ptm_error` - PTM errors with error codes (1-9)
- `packet_send_error` - Converts error_type to "SEND_FAILURE"/"PARTIAL_SEND" with full session info and errno messages
- `stats_error` - Converts error_type to descriptive strings with errno messages

**Packet & Echo Events (with full packet context):**
- `packet_validation_error` - Error codes with actual/expected values, mhop, peer/local addresses
- `packet_session_not_found` - Session not found with full packet context
- `packet_remote_discr_zero` - Remote discriminator zero with session state
- `packet_ttl_exceeded` - TTL exceeded with actual/expected values
- `remote_discriminator_change` - Discriminator change with full packet context
- `echo_packet_error` - Echo packet errors with packet context

**Events without custom parsers (raw values are meaningful as-is):**
- `session_label_update` - Label string and discriminator
- `profile_apply` - Profile name and discriminator
- `timer_negotiation` - Timer values in milliseconds
- `dplane_session_not_found` - Local discriminator only

## Tracepoint Fields

### Session Lifecycle Tracepoints
- `local_discr`: Local discriminator (unique session identifier)
- `remote_discr`: Remote discriminator (peer identifier)
- `vrf_id`: VRF ID (numeric)
- `ifindex`: Interface index (numeric)
- `family`: Address family (2=AF_INET, 10=AF_INET6)
- `mhop`: Multi-hop flag (boolean)
- `state`: Current BFD state (0=ADM_DOWN, 1=DOWN, 2=INIT, 3=UP)
- `passive`: Passive mode flag (boolean)
- `detect_mult`: Detection multiplier
- `desired_min_tx_ms`, `required_min_rx_ms`: Timer values (milliseconds)
- `is_create`: Boolean (true=create, false=delete) for session_lifecycle
- `is_enable`: Boolean (true=enable, false=disable) for session_enable_event
- `label`: Session label string (for session_label_update)

### State Change Tracepoints
- `local_discr`: Local discriminator (session identifier)
- `remote_discr`: Remote discriminator
- `vrf_id`: VRF ID
- `ifindex`: Interface index
- `mhop`: Multi-hop flag (boolean) - matches bs_to_string output
- `vrfname`: VRF name (string) - matches bs_to_string output
- `ifname`: Interface name (string) - matches bs_to_string output
- `old_state`: Previous BFD state (0=ADM_DOWN, 1=DOWN, 2=INIT, 3=UP)
- `new_state`: New BFD state
- `diag`: Diagnostic code (reason for state change)
- `family`: Address family (2=AF_INET, 10=AF_INET6)
- `local_addr`: Local address (16 bytes, IPv4 in first 4 bytes or full IPv6)
- `peer_addr`: Peer address (16 bytes)

### Packet Event Tracepoints

#### packet_validation_error
- `error_code`: Validation error code (1-8)
- `mhop`: Multi-hop flag (from packet context)
- `family`: Address family
- `peer_addr`: Peer address (16 bytes)
- `local_addr`: Local address (16 bytes)
- `ifindex`: Interface index
- `vrf_id`: VRF ID
- `error_value`: Actual value that caused error (e.g., actual TTL, version)
- `expected_value`: Expected value (e.g., expected TTL=255, version=1)

#### packet_session_not_found
- `mhop`: Multi-hop flag
- `family`: Address family
- `peer_addr`: Peer address (16 bytes)
- `local_addr`: Local address (16 bytes)
- `ifindex`: Interface index
- `vrf_id`: VRF ID
- `remote_discr`: Remote discriminator from packet

#### packet_remote_discr_zero
- `mhop`: Multi-hop flag
- `family`: Address family
- `peer_addr`: Peer address (16 bytes)
- `local_addr`: Local address (16 bytes)
- `ifindex`: Interface index
- `vrf_id`: VRF ID
- `session_state`: Current session state

#### packet_ttl_exceeded
- `mhop`: Multi-hop flag
- `family`: Address family
- `peer_addr`: Peer address (16 bytes)
- `local_addr`: Local address (16 bytes)
- `ifindex`: Interface index
- `vrf_id`: VRF ID
- `actual_ttl`: TTL value from packet
- `expected_min_ttl`: Session's mh_ttl value

#### remote_discriminator_change
- `local_discr`: Local discriminator
- `old_remote_discr`: Previous remote discriminator
- `new_remote_discr`: New remote discriminator
- `mhop`: Multi-hop flag
- `family`: Address family
- `peer_addr`: Peer address (16 bytes)
- `local_addr`: Local address (16 bytes)
- `ifindex`: Interface index
- `vrf_id`: VRF ID

#### echo_packet_error
- `error_type`: 1=PACKET_TOO_SMALL, 2=ZERO_DISCRIMINATOR
- `family`: Address family
- `peer_addr`: Peer address (16 bytes)
- `local_addr`: Local address (16 bytes)
- `ifindex`: Interface index
- `vrf_id`: VRF ID
- `pkt_len`: Packet length

### Authentication Tracepoints
- `is_success`: Boolean (true=success, false=failure)
- `local_discr`: Session identifier
- `auth_type`: Authentication type (0=NULL, 1=SIMPLE, 2=CRYPTOGRAPHIC)
- `mhop`: Multi-hop flag (from packet context)
- `family`: Address family
- `peer_addr`: Peer address (16 bytes)
- `local_addr`: Local address (16 bytes)
- `ifindex`: Interface index
- `vrf_id`: VRF ID

### Configuration Tracepoints
- `local_discr`: Session identifier
- `profile_name`: BFD profile name (for profile_apply)
- `echo_enabled`: Echo mode status (boolean)
- `xmt_TO_ms`: Transmit interval (milliseconds)
- `required_min_rx_ms`: Required minimum RX interval (milliseconds)
- `detect_TO_ms`: Detection timeout (milliseconds)
- `echo_xmt_TO_ms`: Echo transmit interval (milliseconds)
- `echo_detect_TO_ms`: Echo detection timeout (milliseconds)

### Control Socket Tracepoints
- `local_discr`: Session identifier (for control_notify)
- `notify_state`: State being notified to clients
- `is_connect`: Boolean (true=connect, false=disconnect) for control_client_event
- `client_fd`: Client socket file descriptor

### Data Plane Tracepoints
- `local_discr`: Local discriminator for session lookup
- `is_add`: Boolean (true=add, false=delete) for session_update
- `flags`: Session flags
- `detect_mult`: Detection multiplier
- `ttl`: Time-to-live value
- `is_request`: Boolean (true=request, false=reply) for dplane_echo
- `dp_time`: Data plane timestamp
- `bfdd_time`: BFD daemon timestamp
- `op_code`: Socket operation code (1-6, see Available Tracepoints section)
- `errno_val`: System error code (errno)

## Example Use Cases

### Debugging Session Issues
Enable all BFD tracepoints to get complete visibility into session behavior:

```bash
lttng enable-event -u frr_bfd:*
```

### Monitoring State Changes
Focus on state transitions to track session stability:

```bash
lttng enable-event -u 'frr_bfd:state_change,frr_bfd:control_notify'
```

### Tracking Session Lifecycle
Monitor session creation, deletion, and enable/disable events:

```bash
lttng enable-event -u 'frr_bfd:session_lifecycle,frr_bfd:session_enable_event,frr_bfd:session_label_update'
```

### Debugging Packet Validation Issues
Track invalid packets and configuration mismatches:

```bash
lttng enable-event -u 'frr_bfd:packet_validation_error,frr_bfd:packet_session_not_found,frr_bfd:remote_discriminator_change'
```

### Debugging Timer Negotiation
Monitor timer negotiation and configuration changes:

```bash
lttng enable-event -u 'frr_bfd:timer_negotiation,frr_bfd:profile_apply,frr_bfd:echo_mode_change'
```

### Debugging Data Plane Issues
Track data plane interactions and socket errors:

```bash
lttng enable-event -u 'frr_bfd:dplane_*'
```

### Monitoring Client Connections
Track control socket client connect/disconnect events:

```bash
lttng enable-event -u 'frr_bfd:control_client_event'
```

### Debugging Authentication Problems
Monitor authentication success and failures:

```bash
lttng enable-event -u 'frr_bfd:auth_event'
```

## Integration with Other FRR Components

BFD LTTng tracing integrates with the overall FRR tracing framework and can be used alongside:
- BGP LTTng tracing
- Zebra LTTng tracing
- General LTTng tracing

## Troubleshooting

### No tracepoints visible
- Ensure BFD LTTng support was enabled during build with `--enable-bfd-lttng`
- Check that `lttng-ust` is properly installed
- Verify tracepoints are enabled with `lttng list -u`
- Ensure `bfdd` is running as the correct user (root, frr, or cumulus)

### Performance impact
- LTTng tracing has minimal overhead when not actively tracing
- All BFD tracepoints are designed for production use (no high-frequency events)
- Tracepoints fire only on significant events, not on every packet or timer
- Safe to enable all tracepoints (`frr_bfd:*`) in production environments

### Trace output considerations
- Use rotating buffers to prevent disk space issues
- Configure appropriate trace file sizes in LTTng session
- Use `frr_babeltrace.py` script for formatted output: `/usr/lib/frr/frr_babeltrace.py /var/log/lttng-traces/session-name`

## Production Recommendations

For production deployments, the following tracepoints are recommended:

**Critical Events (always enable)**:
```bash
lttng enable-event -u 'frr_bfd:state_change,frr_bfd:packet_validation_error,frr_bfd:dplane_init_error,frr_bfd:auth_event,frr_bfd:packet_send_error'
```

**Session Management (enable for troubleshooting)**:
```bash
lttng enable-event -u 'frr_bfd:session_lifecycle,frr_bfd:session_enable_event,frr_bfd:remote_discriminator_change,frr_bfd:packet_session_not_found'
```

**Packet Validation (enable for packet issues)**:
```bash
lttng enable-event -u 'frr_bfd:packet_validation_error,frr_bfd:packet_session_not_found,frr_bfd:packet_remote_discr_zero,frr_bfd:packet_ttl_exceeded,frr_bfd:echo_packet_error'
```

**Configuration Tracking (enable during config changes)**:
```bash
lttng enable-event -u 'frr_bfd:profile_apply,frr_bfd:timer_negotiation,frr_bfd:echo_mode_change'
```

## Summary

The BFD LTTng tracing implementation provides **30+ production-optimized tracepoints** covering:
- 4 session lifecycle events (with address info, mhop, vrfname, ifname)
- 6 packet validation and peer events (with full packet context)
- 1 authentication event (with packet context)
- 3 configuration and timer events
- 2 control socket events (consolidated)
- 4 data plane events
- 4 PTM events (session, client, config_refcount_error, error)
- 2 Zebra integration events (interface, address)
- 1 packet send error event (with full session details)

**Key Design Principles:**
- **Match debug output**: All tracepoints include the same information as corresponding `cp_debug` and `zlog_debug` calls
- **Full context**: Packet context (mhop, peer_addr, local_addr, ifindex, vrf_id) included where applicable
- **Specific error values**: Error tracepoints include actual and expected values for easy diagnosis
- **No dummy values**: Separate tracepoints for different contexts instead of using zero/null placeholders
- **Binary fields**: Minimal overhead with no string serialization
- **Production-safe**: All tracepoints fire only on significant events

This design makes the implementation suitable for continuous production monitoring without performance impact, while providing the same diagnostic information as debug logs.

## References

- [LTTng Documentation](https://lttng.org/docs/)
- [FRR Tracing Framework](../lib/trace.h)
- [BFD Protocol RFC 5880](https://tools.ietf.org/html/rfc5880)
- [BFD Trace Header](bfdd/bfd_trace.h)

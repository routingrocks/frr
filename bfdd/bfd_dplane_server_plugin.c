// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD data plane server plugin implementation.
 *
 * Copyright (C) 2025 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 * Based on original BFD data plane implementation
 */

#include <zebra.h>

#ifdef HAVE_SX_SDK_SX_API_H

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>

#ifdef __FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif /* __FreeBSD__ */

#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "lib/hook.h"
#include "lib/network.h"
#include "lib/printfrr.h"
#include "lib/stream.h"
#include "lib/frrevent.h"
#include "lib/hash.h"
#include "lib/memory.h"
#include "lib/libfrr.h"

#include "bfd.h"
#include "bfddp_packet.h"

#include "lib/openbsd-queue.h"
#include <sx/sdk/sx_api_bfd.h>
#include <sx/sdk/sx_lib_host_ifc.h>
#include <sx/sdk/sx_trap_id.h>
#include <sx/sxd/sx_bfd_ctrl_cmds.h>
#include <sx/sdk/auto_headers/sx_host_auto.h>

DEFINE_MTYPE_STATIC(BFDD, BFDD_DPLANE_SERVER_PLUGIN_CTX,
		    "BFD data plane server plugin context");
DEFINE_MTYPE_STATIC(BFDD, BFDD_DPLANE_SERVER_PLUGIN_SESSION,
		    "BFD data plane server plugin session");
DEFINE_MTYPE_STATIC(BFDD, BFDD_DPLANE_SESSION_PACKET,
		    "BFD data plane session packet");

int num_sessions = 0;
/** Data plane server socket buffer size. */
#define BFD_DPLANE_SERVER_BUF_SIZE 32768

/** Default Unix socket path for BFD data plane server. */
#define BFD_DPLANE_SERVER_SOCK_PATH "/var/run/frr/bfdd_dplane.sock"

static int bfd_dplane_server_plugin_start(void);

/** BFD session state values. */
enum bfd_session_state {
	BFD_SESSION_ADMIN_DOWN = 0,
	BFD_SESSION_DOWN = 1,
	BFD_SESSION_INIT = 2,
	BFD_SESSION_UP = 3,
};

/** BFD session flags. */
#define BFD_SESSION_FLAG_IPV6     (1 << 4)
#define BFD_SESSION_FLAG_ECHO     (1 << 3)
#define BFD_SESSION_FLAG_CBIT     (1 << 2)
#define BFD_SESSION_FLAG_PASSIVE  (1 << 5)
#define BFD_SESSION_FLAG_MULTIHOP (1 << 0)
#define BFD_SESSION_FLAG_SHUTDOWN (1 << 7)
#define BFD_SESSION_FLAG_DEMAND   (1 << 1)
#define BFD_SINGLEHOP_DESTPORT    3784
#define BFD_MULTIHOP_DESTPORT     4784
#define BFD_UDP_SRCPORTMAX        65535
#define BFD_UDP_SRCPORTINIT       49152

enum bfd_dplane_diagnosticis {
        BFD_DPLANE_OK = 0,
        /* Control Detection Time Expired. */
        BFD_DPLANE_CONTROL_EXPIRED = 1,
        /* Echo Function Failed. */
        BFD_DPLANE_ECHO_FAILED = 2,
        /* Neighbor Signaled Session Down. */
        BFD_DPLANE_NEIGHBOR_DOWN = 3,
        /* Forwarding Plane Reset. */
        BFD_DPLANE_FORWARDING_RESET = 4,
        /* Path Down. */
        BFD_DPLANE_PATH_DOWN = 5,
        /* Concatenated Path Down. */
        BFD_DPLANE_CONCATPATH_DOWN = 6,
        /* Administratively Down. */
        BFD_DPLANE_ADMIN_DOWN = 7,
        /* Reverse Concatenated Path Down. */
        BFD_DPLANE_REVCONCATPATH_DOWN = 8,
        /* 9..31: reserved. */
};

/** BFD session structure for server-side tracking. */
struct bfd_dplane_server_session {
	/** Session local discriminator. */
	uint32_t lid;
	/** Session remote discriminator. */
	uint32_t rid;
	/** Source address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} src;
	/** Destination address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} dst;
	/** Session flags. */
	uint32_t flags;
	/** Time-to-live for multihop sessions. */
	uint8_t ttl;
	/** Detection multiplier. */
	uint8_t detect_mult;
	/** Interface index. */
	uint32_t ifindex;
	/** Interface name. */
	char ifname[IFNAMSIZ];

	/** Current session state. */
	enum bfd_session_state state;
	/** Remote session state. */
	enum bfd_session_state remote_state;

	/** Remote flags. */
	uint32_t remote_flags;
	/** Remote detection multiplier. */
	uint8_t remote_detect_mult;

	/**Transmit interval of the session*/
	uint32_t transmit_interval;
	/** Receive timeout */
	uint64_t detect_TO;

	/** Remote desired TX interval. */
	uint32_t remote_desired_tx;
	/** Remote required RX interval. */
	uint32_t remote_required_rx;
	/** Remote required echo RX interval. */
	uint32_t remote_required_echo_rx;

	/** Configured desired TX interval. */
	uint32_t config_desired_tx;
	/** Configured required RX interval. */
	uint32_t config_required_rx;
	/** Configured required echo RX interval. */
	uint32_t config_required_echo_rx;

	uint32_t cur_timers_desired_min_tx;
	uint32_t cur_timers_required_min_rx;

        /* Minimum desired echo transmission interval (in microseconds)*/
        uint32_t min_echo_tx;
        /* Minimum desired echo transmission interval (in microseconds)*/
        uint32_t min_echo_rx;

	/** Session diagnostics. */
	uint8_t diagnostics;
	/** Remote diagnostics. */
	uint8_t remote_diagnostics;

	/** Session statistics. */
	struct {
		uint64_t control_input_bytes;
		uint64_t control_input_packets;
		uint64_t control_output_bytes;
		uint64_t control_output_packets;
		uint64_t echo_input_bytes;
		uint64_t echo_input_packets;
		uint64_t echo_output_bytes;
		uint64_t echo_output_packets;
	} stats;
	/** Hash table entry. */
	struct hash_bucket *hb;
	/** Offloaded session RX ID*/
	uint32_t offloaded_tx_session_id;
	/** Offloaded session TX ID*/
	uint32_t offloaded_rx_session_id;
	/** Polling */
	bool polling;
	/** Send final flag */
	bool send_final;
	/* Vrf ID */
	uint32_t vrf_id;
	/* VRF name */
	char vrfname[36];
	/* Opaque data */
	uint64_t opaque_data;

	/* Src Port */
	int src_port;

	/** Session up timestamp. */
	struct timeval uptime;
	/** Session down timestamp. */
	struct timeval downtime;
	/** Session up count. */
	uint64_t session_up;
	/** Session down count. */
	uint64_t session_down;

	/** List entry for cleanup. */
	TAILQ_ENTRY(bfd_dplane_server_session) entry;
};

/** Data plane server client context. */
struct bfd_dplane_server_client {
	/** Client file descriptor. */
	int sock;
	/** Client address. */
	union {
		struct sockaddr sa;
		struct sockaddr_un sun;
	} addr;
	/** Address length. */
	socklen_t addrlen;
	/** Input buffer data. */
	struct stream *inbuf;
	/** Output buffer data. */
	struct stream *outbuf;
	/** Input event data. */
	struct event *inbufev;
	/** Output event data. */
	struct event *outbufev;
	/** Amount of bytes read. */
	uint64_t in_bytes;
	/** Amount of bytes written. */
	uint64_t out_bytes;
	/** Amount of messages read. */
	uint64_t in_msgs;
	/** Amount of messages sent. */
	uint64_t out_msgs;
	/** List entry. */
	TAILQ_ENTRY(bfd_dplane_server_client) entry;
};

/** Data plane server context. */
struct bfd_dplane_server_ctx {
	/** Server listening socket. */
	int listen_sock;
	/** Accept event. */
	struct event *accept_ev;
	/** Session hash table. */
	struct hash *sessions;
	/** Client list. */
	TAILQ_HEAD(, bfd_dplane_server_client) clients;
	/** Session list for cleanup. */
	TAILQ_HEAD(, bfd_dplane_server_session) session_list;
	/** Socket path. */
	char socket_path[256];
	/** Server statistics. */
	struct {
		uint64_t total_sessions;
		uint64_t active_sessions;
		uint64_t total_clients;
		uint64_t active_clients;
		uint64_t messages_processed;
		uint64_t echo_requests;
		uint64_t echo_replies;
	} stats;
	uint16_t last_id;
};

/** Global server context. */
static struct bfd_dplane_server_ctx *server_ctx = NULL;

/** Plugin state. */
static bool plugin_initialized = false;
static bool plugin_running = false;

/* SDK handles */
static sx_api_handle_t sx_handle = 0;
static sx_user_channel_t packet_notif_channel;
static sx_user_channel_t timeout_notif_channel;

/** Forward declarations. */
static int bfd_dplane_server_plugin_sdk_init();
static void bfd_dplane_server_accept(struct event *t);
static void bfd_dplane_server_client_read(struct event *t);
static void bfd_dplane_server_client_write(struct event *t);
static void bfd_dplane_server_client_free(struct bfd_dplane_server_client *client);
static void bfd_dplane_server_session_free(struct bfd_dplane_server_session *session);
static int bfd_dplane_server_handle_message(struct bfd_dplane_server_client *client,
					    const struct bfddp_message *msg);
static void bfd_dplane_server_send_message(struct bfd_dplane_server_client *client,
					   const struct bfddp_message *msg);
static uint32_t bfd_dplane_server_session_hash(const void *arg);
static bool bfd_dplane_server_session_hash_equal(const void *arg1, const void *arg2);

static sx_status_t initialize_sx_sdk(void);
static sx_status_t initialize_sx_bfd_module(void);
static sx_status_t deinitialize_sx_sdk_bfd(void);
static sx_status_t bfd_register_sdk_packet_traps(void);
static sx_status_t bfd_register_sdk_timeout_traps(void);
static void bfd_dplane_server_handle_init_sdk(struct bfd_dplane_server_client *client, const struct bfddp_message *msg);
static void bfd_dplane_server_handle_deinit_sdk(struct bfd_dplane_server_client *client, const struct bfddp_message *msg);

/* Forward declarations for session offload APIs */
static int bfd_dplane_new_tx_session_offload(struct bfd_dplane_server_session *bfd_session);
static int bfd_dplane_new_rx_session_offload(struct bfd_dplane_server_session *bfd_session);
static int bfd_dplane_update_tx_session_offload(struct bfd_dplane_server_session *bfd_session);
static int bfd_dplane_update_rx_session_offload(struct bfd_dplane_server_session *bfd_session);
static int bfd_dplane_delete_tx_session_offload(struct bfd_dplane_server_session *bfd_session);
static int bfd_dplane_delete_rx_session_offload(struct bfd_dplane_server_session *bfd_session);

/* Forward declarations for packet construction */
static void bfd_construct_tx_packet(sx_bfd_session_params_t *session_params_tx, struct bfd_pkt *bfd_packet_tx, struct bfd_dplane_server_session *session, bool new_session);
static void bfd_construct_rx_packet(sx_bfd_session_params_t *session_params_rx, struct bfd_pkt *bfd_packet_rx, struct bfd_dplane_server_session *session, bool new_session);

/* Forward declarations for state machine and helper functions */
static void bfd_dplane_set_slow_timer(struct bfd_dplane_server_session *bs);
static void bfd_dplane_final_handler(struct bfd_dplane_server_session *bs);
static void bfd_dplane_sess_up(struct bfd_dplane_server_session *session);
static void bfd_dplane_sess_dn(struct bfd_dplane_server_session *session, uint8_t diag, bool notify_admin_down);
static void bfd_dplane_state_handler(struct bfd_dplane_server_session *session, int nstate);

static struct event *timeout_trap_event = NULL;
static struct event *packet_trap_event = NULL;

#define BFD_DPLANE_DEF_SLOWTX (1000 * 1000) /* microseconds. */
#define BFD_DPLANE_DEFDETECTMULT 3

static void bfd_dplane_set_slow_timer(struct bfd_dplane_server_session *bs) {
        bs->detect_TO = (BFD_DPLANE_DEFDETECTMULT * BFD_DPLANE_DEF_SLOWTX);
        bs->transmit_interval = BFD_DPLANE_DEF_SLOWTX;
        bs->cur_timers_desired_min_tx = BFD_DEF_SLOWTX;
        bs->cur_timers_required_min_rx = BFD_DEF_SLOWTX;
}

/**
 * Calculate jittered transmit interval according to RFC 5880 Section 6.5.2
 * 
 * The transmit interval should be randomly jittered between 75% and 100%
 * of the nominal value (or 75%-90% if detect_mult is 1) to prevent
 * self-synchronization between multiple BFD sessions.
 * 
 * @param interval_us Base interval in microseconds
 * @param detect_mult Detection multiplier (used to determine jitter range)
 * @return Jittered interval in microseconds
 */
static uint32_t bfd_dplane_apply_jitter(uint32_t interval_us, uint8_t detect_mult)
{
	int maxpercent;
	uint32_t jitter;
	
	/*
	 * RFC 5880 Section 6.5.2:
	 * - Normally jitter between 75% and 100% (maxpercent = 26 gives us 75-101%)
	 * - If detect_mult is 1, jitter between 75% and 90% (maxpercent = 16 gives us 75-91%)
	 * This is more conservative when there's less tolerance for missed packets.
	 */
	maxpercent = (detect_mult == 1) ? 16 : 26;
	
	/* Calculate: interval * (75 + random(0 to maxpercent)) / 100 */
	jitter = (interval_us * (75 + (frr_weak_random() % maxpercent))) / 100;
	
	return jitter;
}

static sx_status_t initialize_sx_sdk(void) {
	sx_status_t rc;

	if (sx_handle != 0) {
		zlog_err("%s: sx_sdk is  already initialized", __func__);
		return SX_STATUS_ALREADY_INITIALIZED;
	}
	sx_handle = 0;

	frr_with_privs(&bglobal.bfdd_privs) {
		/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sx_api_open uses mixed enum types */
		rc = sx_api_open(NULL, &sx_handle);
	}
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to open SX API: %d", __func__, rc);
		return rc;
	}
	return SX_STATUS_SUCCESS;;
}

static sx_status_t initialize_sx_bfd_module(void) {
        sx_status_t rc;
        sx_bfd_init_params_t init_params = {0};

	//memset(&init_params, 0, sizeof(init_params));
	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_api_bfd_init_set(sx_handle, &init_params);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to init SX BFD: %d", __func__, rc);
                return rc;
        }
        return SX_STATUS_SUCCESS;;
}

static sx_status_t deinitialize_sx_sdk_bfd(void)
{
	sx_status_t rc;

	/* Don't return from any error case. Let's cleanup everything that could have been inited 
	 * The common scenario could be sx_sdk service has gone down and we try to cleanup
	 * In that case sx_api call will fail but we still have to cleanup all the fds and handles
	 */
	if (packet_notif_channel.channel.fd.valid) {
		frr_with_privs(&bglobal.bfdd_privs) {
			/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sx_api_host_ifc_close uses mixed enum types */
			rc = sx_api_host_ifc_close(sx_handle,
            			&packet_notif_channel.channel.fd);
		}
        	if (rc != SX_STATUS_SUCCESS) {
                	zlog_err("%s: Failed to de-init SX BFD packet trap: %d", __func__, rc);
        	}
	}
	event_cancel(&packet_trap_event);

	if (timeout_notif_channel.channel.fd.valid) {
		frr_with_privs(&bglobal.bfdd_privs) {
			/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sx_api_host_ifc_close uses mixed enum types */
			rc = sx_api_host_ifc_close(sx_handle,
            			&timeout_notif_channel.channel.fd);
		}
        	if (rc != SX_STATUS_SUCCESS) {
                	zlog_err("%s: Failed to de-register SX BFD timeout trap: %d", __func__, rc);
        	}
	}
	event_cancel(&timeout_trap_event);

	memset(&packet_notif_channel, 0, sizeof(sx_user_channel_t));
	memset(&timeout_notif_channel, 0, sizeof(sx_user_channel_t));
	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_api_bfd_deinit_set(sx_handle);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to de-init SX BFD: %d", __func__, rc);
        }
	frr_with_privs(&bglobal.bfdd_privs) {
		sx_api_close(&sx_handle);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to close SX BFD handle: %d", __func__, rc);
        }
	sx_handle = 0;
	return rc;
}

/**
 * Gets the next unused non zero identification.
 *
 * \param bdc the data plane context.
 *
 * \returns next usable id.
 */
static uint16_t bfd_dplane_next_id(struct bfd_dplane_server_ctx *bdc)
{
        bdc->last_id++;

        /* Don't use reserved id `0`. */
        if (bdc->last_id == 0)
                bdc->last_id = 1;

        return bdc->last_id;
}

/**
 * Handle request session counters message.
 */
static void bfd_dplane_server_handle_state_change(const struct bfd_dplane_server_session *session)
{
        struct bfddp_message reply = {};
	struct bfd_dplane_server_client *client;
        uint16_t msglen = sizeof(reply.header) + sizeof(reply.data.session_counters);

        /* Prepare reply header. */
        reply.header.version = BFD_DP_VERSION;
        reply.header.type = htons(BFD_STATE_CHANGE);
        reply.header.length = htons(msglen);
        reply.header.id = ntohs(bfd_dplane_next_id(server_ctx));

        /* Fill state data. */
        reply.data.state.lid = htonl(session->lid);
        reply.data.state.rid = htonl(session->rid);
        reply.data.state.state = session->state;
        
        reply.data.state.diagnostics = session->remote_diagnostics;
        
        reply.data.state.remote_flags = htonl(session->remote_flags);
        reply.data.state.detection_multiplier = session->remote_detect_mult;
        reply.data.state.desired_tx = htonl(session->remote_desired_tx);
        reply.data.state.required_rx = htonl(session->remote_required_rx);
        reply.data.state.required_echo_rx = htonl(session->remote_required_echo_rx);
	
        /* Send to all connected clients. */
        TAILQ_FOREACH(client, &server_ctx->clients, entry) {
                  bfd_dplane_server_send_message(client, &reply);
        }
}

static void bfd_dplane_read_timeout_trap(struct event *t) {
        sx_status_t rc;
        sx_receive_info_t *receive_info = NULL;
        uint8_t packet_buffer[2048];
        uint32_t packet_size = sizeof(packet_buffer);
	struct bfd_dplane_server_session *session = NULL;
	
	/* Allocate receive_info on heap to avoid large stack usage */
	receive_info = XCALLOC(MTYPE_TMP, sizeof(sx_receive_info_t));

        frr_with_privs(&bglobal.bfdd_privs) {
                rc = sx_lib_host_ifc_recv(&timeout_notif_channel.channel.fd, packet_buffer, &packet_size, receive_info);
        }
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to read timeout %d", __func__, rc);
                XFREE(MTYPE_TMP, receive_info);
                frr_with_privs(&bglobal.bfdd_privs) {
                        event_add_read(master, bfd_dplane_read_timeout_trap, NULL, timeout_notif_channel.channel.fd.fd, &timeout_trap_event);
                }
                return;
        }
	uint32_t opaque_data = receive_info->event_info.bfd_timeout.timeout_event.opaque_data;
	if (bglobal.debug_dplane)
		zlog_debug("%s: Opaque Data for session %lu lid %u", __func__, receive_info->event_info.bfd_timeout.timeout_event.opaque_data, opaque_data);
	session = hash_lookup(server_ctx->sessions, &opaque_data);
	if (!session) {
		zlog_err("%s: Session does not exist with LID=%u", __func__, opaque_data);
		XFREE(MTYPE_TMP, receive_info);
		goto TIMEOUT_ERROR;
	}
	/* Don't process the packet if the session is in admin down state*/
	if (session->state == BFD_SESSION_ADMIN_DOWN && (session->flags & SESSION_SHUTDOWN)) {
		XFREE(MTYPE_TMP, receive_info);
		goto TIMEOUT_ERROR;
	} 
	/*Ignore the timeout trap if we are in middle of poll for this session*/
	if (session->polling || session->send_final) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: Polling is happening for lid=%u", __func__, opaque_data);
		XFREE(MTYPE_TMP, receive_info);
		goto TIMEOUT_ERROR;
	}

        switch (session->state) {
	        case BFD_SESSION_INIT:
        	case BFD_SESSION_UP:
			if (bglobal.debug_dplane)
				zlog_err("%s: Bringing the session down due to timeout trap iLID=%u", __func__, opaque_data);
                	bfd_dplane_sess_dn(session, BFD_DPLANE_CONTROL_EXPIRED, false);
                	break;
        }

	bfd_dplane_server_handle_state_change(session);
	XFREE(MTYPE_TMP, receive_info);

TIMEOUT_ERROR:
	/** Schedule next read*/
	frr_with_privs(&bglobal.bfdd_privs) {
		event_add_read(master, bfd_dplane_read_timeout_trap, NULL, timeout_notif_channel.channel.fd.fd, &timeout_trap_event);
	}	
	return;
}

static void bfd_dplane_final_handler (struct bfd_dplane_server_session *bs)
{
	bs->cur_timers_required_min_rx = bs->config_required_rx;
	bs->cur_timers_desired_min_tx = bs->config_desired_tx;
	
	/* Calculate base transmit interval (negotiated between peers) */
	if (bs->config_desired_tx > bs->remote_required_rx)
		bs->transmit_interval = bs->config_desired_tx;
	else
		bs->transmit_interval = bs->remote_required_rx;

	/* 
	 * Note: RFC 5880 jitter (75-100% randomization) will be applied in
	 * bfd_construct_tx_packet when the TX session is actually updated to hardware.
	 * We store the base interval here, and jitter is calculated fresh each time
	 * to ensure proper randomization and prevent self-synchronization across
	 * multiple BFD sessions.
	 */

	bfd_dplane_update_tx_session_offload(bs);
}

/**
 * Process received BFD packet from trap and run state machine
 * Adapted from bfd_recv_cb() in bfd_packet.c for dplane server plugin
 * 
 * Key differences from control plane bfd_recv_cb:
 * - Packet already extracted from event trap (no socket recv needed)
 * - Session already looked up from hash table (no ptm_bfd_sess_find)
 * - Uses dplane server session structure
 * - Will call control plane state handlers via message or implement locally
 * 
 * @param session - BFD session from hash lookup
 * @param cp - BFD control packet from trap event
 */
static void bfd_dplane_process_rx_packet(struct bfd_dplane_server_session *session,
					  const struct bfd_pkt *cp)
{
	if (!session || !cp) {
		zlog_err("%s: NULL session or packet", __func__);
		return;
	}
	
	/*
	 * Packet validation already done in bfd_dplane_read_packet_trap:
	 * - BFD version check (BFD_GETVER)
	 * - detect_mult != 0
	 * - packet length >= BFD_PKT_LEN
	 * - my_discr != 0
	 */
	
	/* Update RX packet statistics */
	session->stats.control_input_packets++;
	session->stats.control_input_bytes += BFD_PKT_LEN;
	
	

	if (session->state == BFD_SESSION_ADMIN_DOWN || session->offloaded_tx_session_id == 0 || session->offloaded_rx_session_id ==0)
		return;
	/* Log remote discriminator changes */
	if ((session->rid != 0) && (session->rid != ntohl(cp->discrs.my_discr))) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: [lid=%u] remote discriminator mismatch (expected %u, got %u)",
				   __func__, session->lid, session->rid, ntohl(cp->discrs.my_discr));
	}
	
	/* Update remote discriminator */
	session->rid = ntohl(cp->discrs.my_discr);
	
	/* Save remote diagnostics before state switch */
	session->remote_diagnostics = cp->diag & BFD_DIAGMASK;
	
	/* Update remote timers settings (RFC 5880, Section 6.8.7) */
	session->remote_desired_tx = ntohl(cp->timers.desired_min_tx);
	session->remote_required_rx = ntohl(cp->timers.required_min_rx);
	session->remote_required_echo_rx = ntohl(cp->timers.required_min_echo);
	session->remote_detect_mult = cp->detect_mult;
	

	/* Update remote C-bit (Control Plane Independent) */
	if (BFD_GETCBIT(cp->flags))
		session->remote_flags |= (1 << 5); /* Set C-bit */
	else
		session->remote_flags &= ~(1 << 5); /* Clear C-bit */
	
	/*
	 * State switch from RFC 5880 section 6.2
	 * Extract remote state and process through state machine
	 */
	int remote_state = BFD_GETSTATE(cp->flags);
	
	if (bglobal.debug_dplane)
		zlog_debug("%s: [lid=%u] current_state=%s remote_state=%s",
			   __func__, session->lid,
			   session->state == BFD_SESSION_DOWN ? "DOWN" :
			   session->state == BFD_SESSION_INIT ? "INIT" :
			   session->state == BFD_SESSION_UP ? "UP" : "ADM_DOWN",
			   remote_state == BFD_SESSION_DOWN ? "DOWN" :
			   remote_state == BFD_SESSION_INIT ? "INIT" :
			   remote_state == BFD_SESSION_UP ? "UP" : "ADM_DOWN");
	
	/* Call state machine handler */
	bfd_dplane_state_handler(session, BFD_GETSTATE(cp->flags));
	
	/* RFC 5880, Section 6.5: handle POLL/FINAL negotiation sequence */
	if (session->polling && BFD_GETFBIT(cp->flags)) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: [lid=%u] FINAL bit received, polling complete",
				   __func__, session->lid);
		/* Disable polling */
		session->polling = 0;
		
		bfd_dplane_final_handler(session);
	}
	
	if (session->cur_timers_required_min_rx > session->remote_desired_tx)
		session->detect_TO = (uint64_t)session->remote_detect_mult * session->cur_timers_required_min_rx;
	else
		session->detect_TO = (uint64_t)session->remote_detect_mult * session->remote_desired_tx;

	bfd_dplane_update_rx_session_offload(session);	

	/*
	 * We've received a packet with the POLL bit set, we must send
	 * a control packet back with the FINAL bit set.
	 *
	 * RFC 5880, Section 6.5.
	 */
	if (BFD_GETPBIT(cp->flags)) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: [lid=%u] POLL bit set, need to send FINAL",
				   __func__, session->lid);

		session->send_final = 1;
		bfd_dplane_final_handler(session);
		/*Revert the final bit to 0 */
		session->send_final = 0;
		bfd_dplane_update_tx_session_offload(session);		
		
	}
	//bfd_dplane_server_handle_state_change(session);
	
	if (bglobal.debug_dplane)
		zlog_debug("%s: [lid=%u] packet processed: remote_tx=%u remote_rx=%u detect_TO=%lu",
			   __func__, session->lid,
			   session->remote_desired_tx,
			   session->remote_required_rx,
			   session->detect_TO);
}

/**
 * Transition session to UP state
 * Adapted from ptm_bfd_sess_up() in bfd.c
 */
static void bfd_dplane_sess_up(struct bfd_dplane_server_session *session)
{
	enum bfd_session_state old_state = session->state;
	
	session->diagnostics = 0;
	session->state = BFD_SESSION_UP;
	
	/* Connection is up, set polling to negotiate timers */
	session->polling = 1;

	bfd_dplane_update_tx_session_offload(session);
	
	bfd_dplane_server_handle_state_change(session);

	if (bglobal.debug_dplane)
		zlog_debug("state-change: [dplane lid=%u] %s -> UP",
			   session->lid,
			   old_state == BFD_SESSION_DOWN ? "DOWN" :
			   old_state == BFD_SESSION_INIT ? "INIT" : "ADM_DOWN");
	
}

/**
 * Transition session to DOWN state
 * Adapted from ptm_bfd_sess_dn() in bfd.c
 * 
 * @param session - BFD session
 * @param diag - Diagnostic code explaining reason for transition
 */
static void bfd_dplane_sess_dn(struct bfd_dplane_server_session *session, uint8_t diag, bool notify_admin_down)
{
	enum bfd_session_state old_state = session->state;
	
	session->diagnostics = diag;
	session->rid = 0;  /* Clear remote discriminator */
	session->state = BFD_SESSION_DOWN;
	session->polling = 0;
	
	if (bglobal.debug_dplane)
		zlog_debug("state-change: [dplane lid=%u] %s -> DOWN (diag=%u)",
			   session->lid,
			   old_state == BFD_SESSION_UP ? "UP" :
			   old_state == BFD_SESSION_INIT ? "INIT" : "ADM_DOWN",
			   diag);
	session->send_final = 0;
	bfd_dplane_update_tx_session_offload(session);

	bfd_dplane_set_slow_timer(session);
	
	bfd_dplane_update_tx_session_offload(session);
	bfd_dplane_update_rx_session_offload(session);

	bfd_dplane_server_handle_state_change(session);
	
}

/**
 * State machine handler when current state is ADMIN_DOWN
 * Adapted from bs_admin_down_handler() in bfd.c
 */
static void bfd_dplane_admin_down_handler(struct bfd_dplane_server_session *session
					   __attribute__((__unused__)),
					   int nstate __attribute__((__unused__)))
{
	/*
	 * We are administratively down, there is no state machine
	 * handling.
	 */
}

/**
 * State machine handler when current state is DOWN
 * Adapted from bs_down_handler() in bfd.c
 */
static void bfd_dplane_down_handler(struct bfd_dplane_server_session *session, int nstate)
{
        switch (nstate) {
        case BFD_SESSION_ADMIN_DOWN:
                /*
                 * Remote peer doesn't want to talk, so lets keep the
                 * connection down.
                 */
        case BFD_SESSION_UP:
                /* Peer can't be up yet, wait it go to 'init' or 'down'. */
                break;

        case BFD_SESSION_DOWN:
                /*
                 * Remote peer agreed that the path is down, lets try to
                 * bring it up.
                 */
		session->state = BFD_SESSION_INIT;

		if (bglobal.debug_dplane)
			zlog_debug("state-change: [dplane lid=%u] DOWN -> INIT",
				   session->lid);
		bfd_dplane_update_tx_session_offload(session);	
		//bfd_dplane_server_handle_state_change(session);
                /*
                 * RFC 5880, Section 6.1.
                 * A system taking the Passive role MUST NOT begin
                 * sending BFD packets for a particular session until
                 * it has received a BFD packet for that session, and thus
                 * has learned the remote system's discriminator value.
                 *
		 * For passive mode, SDK would handle this.
                 */
                break;

        case BFD_SESSION_INIT:
                /*
                 * Remote peer told us his path is up, lets turn
                 * activate the session.
                 */
		bfd_dplane_sess_up(session);
                break;

        default:
		if (bglobal.debug_dplane)
			zlog_debug("state-change: unhandled neighbor state: %d",
				   nstate);
                break;
        }
}

/**
 * State machine handler when current state is INIT
 * Adapted from bs_init_handler() in bfd.c
 */
static void bfd_dplane_init_handler(struct bfd_dplane_server_session *session, int nstate)
{
        switch (nstate) {
        case BFD_SESSION_ADMIN_DOWN:
                /*
		 * Remote peer sent Admin Down.
		 * Go to DOWN state.
                 */
		session->remote_diagnostics = BFD_DPLANE_ADMIN_DOWN;
		bfd_dplane_sess_dn(session, BD_NEIGHBOR_DOWN, true);
                break;

        case BFD_SESSION_DOWN:
                /* Remote peer hasn't moved to first stage yet. */
                break;

        case BFD_SESSION_INIT:
        case BFD_SESSION_UP:
                /* We agreed on the settings and the path is up. */
		bfd_dplane_sess_up(session);
                break;

        default:
		if (bglobal.debug_dplane)
			zlog_debug("state-change: unhandled neighbor state: %d",
				   nstate);
                break;
        }
}

/**
 * State machine handler when current state is UP
 * Adapted from bs_up_handler() in bfd.c
 */
static void bfd_dplane_up_handler(struct bfd_dplane_server_session *session, int nstate)
{
	switch (nstate) {
	case BFD_SESSION_ADMIN_DOWN:
		/*
		 * Remote peer sent Admin Down.
		 * Go to DOWN state.
		 */
		session->remote_diagnostics = BFD_DPLANE_ADMIN_DOWN;
		bfd_dplane_sess_dn(session, BD_NEIGHBOR_DOWN, true);
		break;
		
        case BFD_SESSION_DOWN:
		/* Peer lost connection - bring session down normally. */
		bfd_dplane_sess_dn(session, BD_NEIGHBOR_DOWN, false);
                break;

        case BFD_SESSION_INIT:
        case BFD_SESSION_UP:
		bfd_dplane_server_handle_state_change(session);
                /* Path is up and working. */
                break;

        default:
		if (bglobal.debug_dplane)
			zlog_debug("state-change: unhandled neighbor state: %d",
				   nstate);
                break;
        }
}

/**
 * Main BFD state machine handler for dplane server plugin
 * Adapted from bs_state_handler() in bfd.c
 * 
 * @param session - BFD session
 * @param nstate - New state from remote peer
 */
static void bfd_dplane_state_handler(struct bfd_dplane_server_session *session, int nstate)
{
        switch (session->state) {
        case BFD_SESSION_ADMIN_DOWN:
                bfd_dplane_admin_down_handler(session, nstate);
                break;
        case BFD_SESSION_DOWN:
                bfd_dplane_down_handler(session, nstate);
                break;
        case BFD_SESSION_INIT:
                bfd_dplane_init_handler(session, nstate);
                break;
        case BFD_SESSION_UP:
                bfd_dplane_up_handler(session, nstate);
                break;

        default:
		if (bglobal.debug_dplane)
			zlog_debug("state-change: [dplane lid=%u] is in invalid state: %d",
				   session->lid, nstate);
               break;
        }
}

static void bfd_dplane_read_packet_trap(struct event *t)
{
        sx_status_t rc;
	sx_receive_info_t *receive_info = NULL;
	uint8_t packet_buffer[2048] ={0};
        uint32_t packet_size = sizeof(packet_buffer);
	struct bfd_packet_event* event;
	struct bfd_pkt* bfd_packet;
	uint32_t lid, opaque_data;
	
	/* Allocate receive_info on heap to avoid large stack usage */
	receive_info = XCALLOC(MTYPE_TMP, sizeof(sx_receive_info_t));

	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_lib_host_ifc_recv(&packet_notif_channel.channel.fd, packet_buffer, &packet_size, receive_info);
	}
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to read packet from packet fd  %d",__func__, rc);
		XFREE(MTYPE_TMP, receive_info);
		goto PACKET_ERROR;
		}

	/* Compare the current state of the RX packet to the one which we received */
	/* Check what has changed */
	event = (struct bfd_packet_event*)packet_buffer;
	bfd_packet = (struct bfd_pkt*)event->packet;

	/* Log the packet received packet trap details */
	lid = ntohl(bfd_packet->discrs.remote_discr);
	opaque_data = event->opaque_data;

	if (bglobal.debug_dplane)	
		zlog_debug("PACKET_TRAP_RX: state=%s(%u) diag=%u my_discr=%u remote_discr=%u detect_mult=%u min_tx=%u min_rx=%u min_echo=%u P=%u F=%u C=%u opaque=%u",
			BFD_GETSTATE(bfd_packet->flags) == 0 ? "AdminDown" :
		   	BFD_GETSTATE(bfd_packet->flags) == 1 ? "Down" :
		   	BFD_GETSTATE(bfd_packet->flags) == 2 ? "Init" :
		   	BFD_GETSTATE(bfd_packet->flags) == 3 ? "Up" : "Unknown",
		   	BFD_GETSTATE(bfd_packet->flags),
		   	bfd_packet->diag & BFD_DIAGMASK,
		   	ntohl(bfd_packet->discrs.my_discr),
		   	lid,
		   	bfd_packet->detect_mult,
		   	ntohl(bfd_packet->timers.desired_min_tx),
		   	ntohl(bfd_packet->timers.required_min_rx),
		   	ntohl(bfd_packet->timers.required_min_echo),
		   	BFD_GETPBIT(bfd_packet->flags),
		   	BFD_GETFBIT(bfd_packet->flags),
		   	BFD_GETCBIT(bfd_packet->flags),
		   	opaque_data);

	if (BFD_GETVER(bfd_packet->diag) != BFD_VERSION) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: [lid=%u] bad version",
				   __func__, lid ? lid:opaque_data);
		XFREE(MTYPE_TMP, receive_info);
               goto PACKET_ERROR;
	}
	if (bfd_packet->detect_mult == 0) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: [lid=%u] detect multiplier set to 0",
				   __func__, lid ? lid:opaque_data);
		XFREE(MTYPE_TMP, receive_info);
		goto PACKET_ERROR;
	}
	if (bfd_packet->len < BFD_PKT_LEN) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: [lid=%u] packet too small",
				   __func__, lid ? lid:opaque_data);
		XFREE(MTYPE_TMP, receive_info);
		goto PACKET_ERROR;
	}
        if (ntohl(bfd_packet->discrs.my_discr) == 0) {
		if (bglobal.debug_dplane)
			zlog_debug("%s: [lid=%u] my discriminator is 0",
				   __func__, lid ? lid:opaque_data);
		XFREE(MTYPE_TMP, receive_info);
		goto PACKET_ERROR;
	}
	/*
	 * Only forward packets for sessions we have offloaded to SDK.
	 * Link-local sessions are handled by control plane's RAW socket with BPF filter.
	 * If we don't have this session in our hash table, it means:
	 * - Either it's a link-local session (control plane handles via RAW socket)
	 * - Or it's an unknown/stale session that should be ignored
	 * In both cases, we should NOT forward it to control plane via packet trap.
	 */
	struct bfd_dplane_server_session *session = hash_lookup(server_ctx->sessions, &lid);
	if (!session && lid == 0) {
		/* First packet - try opaque_data */
        	session = hash_lookup(server_ctx->sessions, &opaque_data);
	}
	
	if (!session) {
		/*
		 * No session found - this packet is either:
		 * 1. Link-local session (handled by control plane RAW socket)
		 * 2. Unknown/stale session
		 * Don't forward to control plane - let RAW socket handle it if needed.
		 */
		if (bglobal.debug_dplane)
			zlog_debug("PACKET_TRAP_RX: No session for LID=%u, discarding (RAW socket will handle link-local)",
				   lid == 0 ? opaque_data : lid);
		XFREE(MTYPE_TMP, receive_info);
		goto PACKET_ERROR;
	}

	/*
	 * Process the BFD packet locally to update session state
	 * This is similar to what bfd_recv_cb does in control plane
	 */
	bfd_dplane_process_rx_packet(session, bfd_packet);
	XFREE(MTYPE_TMP, receive_info);

PACKET_ERROR:
	//Schedule for next read 
	frr_with_privs(&bglobal.bfdd_privs) {
		event_add_read(master, bfd_dplane_read_packet_trap, NULL, packet_notif_channel.channel.fd.fd, &packet_trap_event);
	}
	return;
		
}
static sx_status_t bfd_register_sdk_packet_traps(void)
{
	sx_status_t rc;
	int poll_fd = -1;
	memset(&packet_notif_channel, 0, sizeof(sx_user_channel_t));
	packet_notif_channel.type = SX_USER_CHANNEL_TYPE_FD;
	// Open host interface for receiving events
	frr_with_privs(&bglobal.bfdd_privs) {
		/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sx_api_host_ifc_open uses mixed enum types */
		rc = sx_api_host_ifc_open(sx_handle, &packet_notif_channel.channel.fd);
	}
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to open host interface for packet traps: %d", __func__, rc);
		return rc;
	}

	frr_with_privs(&bglobal.bfdd_privs) {
		/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sxd_fd_get uses mixed enum types */
		rc = sxd_fd_get(packet_notif_channel.channel.fd.driver_handle, &poll_fd);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to get packet FD: %d", __func__, rc);
                return rc;
        }

	frr_with_privs(&bglobal.bfdd_privs) {
		/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sx_api_host_ifc_trap_id_register_set uses mixed enum types */
		rc = sx_api_host_ifc_trap_id_register_set(sx_handle, SX_ACCESS_CMD_REGISTER, 0,
							SX_TRAP_ID_BFD_PACKET_EVENT, &packet_notif_channel);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to register for  BFD packet traps: %d", __func__, rc);
                return rc;
        }
	frr_with_privs(&bglobal.bfdd_privs) {
		event_add_read(master, bfd_dplane_read_packet_trap, NULL, packet_notif_channel.channel.fd.fd, &packet_trap_event);
	}
	return SX_STATUS_SUCCESS;
}

static sx_status_t bfd_register_sdk_timeout_traps(void)
{
	sx_status_t rc;
	int poll_fd = -1;

	memset(&timeout_notif_channel, 0, sizeof(sx_user_channel_t));
	timeout_notif_channel.type = SX_USER_CHANNEL_TYPE_FD;
	// Open host interface for receiving events
	frr_with_privs(&bglobal.bfdd_privs) {
		/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sx_api_host_ifc_open uses mixed enum types */
		 rc = sx_api_host_ifc_open(sx_handle, &timeout_notif_channel.channel.fd);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to open host interface for timeout traps: %d", __func__, rc);
                return rc;
        }
	frr_with_privs(&bglobal.bfdd_privs) {
		/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sxd_fd_get uses mixed enum types */
		rc = sxd_fd_get(timeout_notif_channel.channel.fd.driver_handle, &poll_fd);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to get timeout FD: %d", __func__, rc);
                return rc;
        }
	frr_with_privs(&bglobal.bfdd_privs) {
		/* coverity[PW.MIXED_ENUM_TYPE] - SDK API sx_api_host_ifc_trap_id_register_set uses mixed enum types */
		rc = sx_api_host_ifc_trap_id_register_set(sx_handle, SX_ACCESS_CMD_REGISTER, 0,
							SX_TRAP_ID_BFD_TIMEOUT_EVENT, &timeout_notif_channel);
	}
        if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to register for BFD timeout traps: %d", __func__, rc);
                return rc;
        }
	frr_with_privs(&bglobal.bfdd_privs) {
		event_add_read(master, bfd_dplane_read_timeout_trap, NULL, timeout_notif_channel.channel.fd.fd, &timeout_trap_event);
	}
	return rc;
}

static const char *bfd_dplane_server_messagetype2str(sx_access_cmd_t cmd) __attribute__((unused));
static const char *bfd_dplane_server_messagetype2str(sx_access_cmd_t cmd) 
{
	switch (cmd) {
		case SX_ACCESS_CMD_CREATE:
			return "Create";
		case SX_ACCESS_CMD_DESTROY:
			return "Destroy";
		case SX_ACCESS_CMD_EDIT:
			return "EDIT";
		default:
			return "Unknown";
	}
}
/**
 * Offload new TX session to hardware.
 */
static int bfd_dplane_new_tx_session_offload(struct bfd_dplane_server_session *bfd_session)
{
	sx_bfd_session_params_t session_params_tx;
	struct bfd_pkt bfd_packet_tx = {};
	sx_status_t rc;
	int udp_port = BFD_UDP_SRCPORTINIT;
	bool is_udp_port_found = false;

	if (!bfd_session) {
		zlog_err("%s: BFD Session is NULL", __func__);
		return -1;
	}

	/* Initialize TX session parameters */
	memset(&session_params_tx, 0, sizeof(session_params_tx));

	/* Construct TX packet */
	bfd_construct_tx_packet(&session_params_tx, &bfd_packet_tx, bfd_session, true);

	if (bfd_session->flags & BFD_SESSION_FLAG_SHUTDOWN)
		return 0;

	/* Find available UDP port and create session */
	frr_with_privs(&bglobal.bfdd_privs) {
		/* Start from BFD_UDP_SRCPORTINIT till BFD_UDP_SRCPORTMAX and try to bind the session */
		for (udp_port = BFD_UDP_SRCPORTINIT; udp_port < BFD_UDP_SRCPORTMAX; udp_port++) {
			session_params_tx.session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.src_udp_port = udp_port;
			rc = sx_api_bfd_offload_set(sx_handle, SX_ACCESS_CMD_CREATE, &session_params_tx, &bfd_session->offloaded_tx_session_id);
			if (rc == SX_STATUS_SUCCESS) {
				is_udp_port_found = true;
				break;
			}
		}
		if (rc == SX_STATUS_SUCCESS) {
			bfd_session->src_port = udp_port;
		}
		if (!is_udp_port_found) {
			zlog_err("%s: Failed to find UDP src port for session lid %u", __func__, bfd_session->lid);
		}
	}

	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to CREATE TX session local discriminator %u", __func__, bfd_session->lid);
		return -1;
	}

	return 0;
}

/**
 * Offload new RX session to hardware.
 */
static int bfd_dplane_new_rx_session_offload(struct bfd_dplane_server_session *bfd_session)
{
	sx_bfd_session_params_t session_params_rx;
	struct bfd_pkt bfd_packet_rx = {};
	sx_status_t rc;	

	if (!bfd_session) {
		zlog_err("%s: BFD Session is NULL", __func__);
		return -1;
	}

	/* Initialize RX session parameters */
	memset(&session_params_rx, 0, sizeof(session_params_rx));

	/* Construct RX packet */
	bfd_construct_rx_packet(&session_params_rx, &bfd_packet_rx, bfd_session, true);

	if (bfd_session->flags & BFD_SESSION_FLAG_SHUTDOWN)
		return 0;

	/* Create RX session */
	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_api_bfd_offload_set(sx_handle, SX_ACCESS_CMD_CREATE, &session_params_rx, &bfd_session->offloaded_rx_session_id);
	}

	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to CREATE RX session local discriminator %u", __func__, bfd_session->lid);
		return -1;
	}

	return 0;
}

/**
 * Update existing TX session in hardware.
 */
static int bfd_dplane_update_tx_session_offload(struct bfd_dplane_server_session *bfd_session)
{
	sx_bfd_session_params_t session_params_tx;
	struct bfd_pkt bfd_packet_tx = {};
	sx_access_cmd_t cmd = SX_ACCESS_CMD_EDIT;
	sx_status_t rc;

	if (!bfd_session) {
		zlog_err("%s: BFD Session is NULL", __func__);
		return -1;
	}

	/* Initialize TX session parameters */
	memset(&session_params_tx, 0, sizeof(session_params_tx));

	/* Construct TX packet */
	bfd_construct_tx_packet(&session_params_tx, &bfd_packet_tx, bfd_session, false);
	if (!bfd_session->offloaded_tx_session_id)
		cmd = SX_ACCESS_CMD_CREATE;

	/* Update TX session */
	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_api_bfd_offload_set(sx_handle, cmd, &session_params_tx, &bfd_session->offloaded_tx_session_id);
	}

	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to EDIT TX session local discriminator %u", __func__, bfd_session->lid);
		return -1;
	}

	return 0;
}

/**
 * Update existing RX session in hardware.
 */
static int bfd_dplane_update_rx_session_offload(struct bfd_dplane_server_session *bfd_session)
{
	sx_bfd_session_params_t session_params_rx;
	struct bfd_pkt bfd_packet_rx = {};
        sx_access_cmd_t cmd = SX_ACCESS_CMD_EDIT;
	sx_status_t rc;

	if (!bfd_session) {
		zlog_err("%s: BFD Session is NULL", __func__);
		return -1;
	}

	/* Initialize RX session parameters */
	memset(&session_params_rx, 0, sizeof(session_params_rx));

	/* Construct RX packet */
	bfd_construct_rx_packet(&session_params_rx, &bfd_packet_rx, bfd_session, false);

        if (!bfd_session->offloaded_rx_session_id)
                cmd = SX_ACCESS_CMD_CREATE;

	/* Update RX session */
	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_api_bfd_offload_set(sx_handle, cmd, &session_params_rx, &bfd_session->offloaded_rx_session_id);
	}

	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to EDIT RX session local discriminator %u", __func__, bfd_session->lid);
		return -1;
	}

	return 0;
}

/**
 * Delete TX session from hardware.
 */
static int bfd_dplane_delete_tx_session_offload(struct bfd_dplane_server_session *bfd_session)
{
	sx_bfd_session_params_t session_params_tx;
	struct bfd_pkt bfd_packet_tx = {};
	sx_status_t rc;

	if (!bfd_session) {
		zlog_err("%s: BFD Session is NULL", __func__);
		return -1;
	}

	/* Initialize TX session parameters */
	memset(&session_params_tx, 0, sizeof(session_params_tx));

	/* Construct TX packet */
	bfd_construct_tx_packet(&session_params_tx, &bfd_packet_tx, bfd_session, false);

	/* Delete TX session */
	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_api_bfd_offload_set(sx_handle, SX_ACCESS_CMD_DESTROY, &session_params_tx, &bfd_session->offloaded_tx_session_id);
	}
	bfd_session->offloaded_tx_session_id = 0;

	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to DESTROY TX session local discriminator %u", __func__, bfd_session->lid);
		return -1;
	}

	return 0;
}

/**
 * Delete RX session from hardware.
 */
static int bfd_dplane_delete_rx_session_offload(struct bfd_dplane_server_session *bfd_session)
{
	sx_bfd_session_params_t session_params_rx;
	struct bfd_pkt bfd_packet_rx = {};
	sx_status_t rc;

	if (!bfd_session) {
		zlog_err("%s: BFD Session is NULL", __func__);
		return -1;
	}

	/* Initialize RX session parameters */
	memset(&session_params_rx, 0, sizeof(session_params_rx));

	/* Construct RX packet */
	bfd_construct_rx_packet(&session_params_rx, &bfd_packet_rx, bfd_session, false);

	/* Delete RX session */
	frr_with_privs(&bglobal.bfdd_privs) {
		rc = sx_api_bfd_offload_set(sx_handle, SX_ACCESS_CMD_DESTROY, &session_params_rx, &bfd_session->offloaded_rx_session_id);
	}
	bfd_session->offloaded_rx_session_id = 0;
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to DESTROY RX session local discriminator %u", __func__, bfd_session->lid);
		return -1;
	}

	return 0;
}

/**
 * Hash function for BFD sessions.
 */
static uint32_t bfd_dplane_server_session_hash(const void *arg)
{
	const struct bfd_dplane_server_session *session = arg;
	return jhash_1word(session->lid, 0);
}

/**
 * Hash equality function for BFD sessions.
 */
static bool bfd_dplane_server_session_hash_equal(const void *arg1, const void *arg2)
{
	const struct bfd_dplane_server_session *s1 = arg1;
	const struct bfd_dplane_server_session *s2 = arg2;

	return (s1->lid == s2->lid);
}

/**
 * Send message to client.
 */
static void bfd_dplane_server_send_message(struct bfd_dplane_server_client *client,
					   const struct bfddp_message *msg)
{
	size_t msglen = ntohs(msg->header.length);
	ssize_t written;

	if (client->sock == -1)
		return;

	/* Write message to output buffer. */
	if (msglen > STREAM_WRITEABLE(client->outbuf)) {
		zlog_warn("Output buffer full, dropping message");
		return;
	}

	stream_write(client->outbuf, msg, msglen);
	client->out_msgs++;

	/* Try to flush immediately. */
	while (STREAM_READABLE(client->outbuf)) {
		written = stream_flush(client->outbuf, client->sock);
		if (written == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				break;
			zlog_warn("Failed to write to client socket: %s", strerror(errno));
			//bfd_dplane_server_client_free(client);
			return;
		}
		if (written == 0) {
			zlog_err("Client disconnected");
			//bfd_dplane_server_client_free(client);
			return;
		}

		client->out_bytes += written;
		stream_forward_getp(client->outbuf, written);
	}

	stream_pulldown(client->outbuf);

	/* Schedule write event if there's more data. */
	if (STREAM_READABLE(client->outbuf)) {
		event_add_write(master, bfd_dplane_server_client_write, client,
				client->sock, &client->outbufev);
	}
}

/**
 * Convert IPv6 address byte order for hardware offload API compatibility
 * The hardware offload API may expect IPv6 addresses in a different byte order
 * than the standard network byte order used in struct in6_addr
 */
static void convert_ipv6_byte_order(struct in6_addr *dst, const struct in6_addr *src)
{
	for (int i = 0; i < 4; i++) {
		// Swap bytes within each 32-bit word
		uint32_t word = src->s6_addr32[i];
		dst->s6_addr32[i] = ((word & 0xFF000000) >> 24) |
				    ((word & 0x00FF0000) >> 8) |
				    ((word & 0x0000FF00) << 8) |
				    ((word & 0x000000FF) << 24);
	}
	return;
}

/**
 * Convert IPv4 address byte order for hardware offload API compatibility
 * The hardware offload API expects IPv4 addresses with bytes swapped
 * (e.g., 5.5.5.1 becomes 1.5.5.5 in the SDK representation)
 */
static void convert_ipv4_byte_order(struct in_addr *dst, const struct in_addr *src)
{
	uint32_t addr = src->s_addr;
	dst->s_addr = ((addr & 0xFF000000) >> 24) |
		      ((addr & 0x00FF0000) >> 8) |
		      ((addr & 0x0000FF00) << 8) |
		      ((addr & 0x000000FF) << 24);
}

static void bfd_construct_tx_packet(sx_bfd_session_params_t *session_params_tx, struct bfd_pkt *bfd_packet_tx, struct bfd_dplane_server_session *session, bool new_session) 
{
	uint32_t jittered_interval;
	
	session_params_tx->session_data.type = SX_BFD_ASYNC_ACTIVE_TX;
	
	/* Apply RFC 5880 jitter to transmit interval to prevent synchronization */
	jittered_interval = bfd_dplane_apply_jitter(session->transmit_interval, 
	                                            session->detect_mult);
	
	session_params_tx->session_data.data.tx_data.interval = jittered_interval;
	
	if (bglobal.debug_dplane)
		zlog_debug("%s: [lid=%u] Applied jitter: base=%u jittered=%u (%.1f%%)",
		           __func__, session->lid, 
		           session->transmit_interval, jittered_interval,
		           (jittered_interval * 100.0) / session->transmit_interval);

	session_params_tx->session_data.data.tx_data.packet_encap.encap_type = SX_BFD_UDP_OVER_IP;
	session_params_tx->peer.peer_type = SX_BFD_PEER_IP_AND_VRF;
	session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.dscp = 0;
	session_params_tx->peer.peer_data.ip_and_vrf.vrf_id = session->vrf_id;
	session_params_tx->peer.peer_data.ip_and_vrf.use_vrf_device = 1;
	if (session->vrf_id)
		strlcpy(session_params_tx->peer.peer_data.ip_and_vrf.vrf_linux_name, session->vrfname, sizeof(session_params_tx->peer.peer_data.ip_and_vrf.vrf_linux_name));

	if (session->flags & BFD_SESSION_FLAG_MULTIHOP) {
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.dest_udp_port = BFD_MULTIHOP_DESTPORT;
		if (!new_session)
			session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.src_udp_port = session->src_port;
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.ttl = BFD_TTL_VAL;
	}
	else {
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.dest_udp_port = BFD_SINGLEHOP_DESTPORT;
		if (!new_session)
			session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.src_udp_port = session->src_port;   
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.ttl = BFD_TTL_VAL;
	}

	if (session->flags & BFD_SESSION_FLAG_IPV6) {
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.src_ip_addr.version = SX_IP_VERSION_IPV6;
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.dest_ip_addr.version = SX_IP_VERSION_IPV6;
		session_params_tx->peer.peer_data.ip_and_vrf.ip_addr.version = SX_IP_VERSION_IPV6;
		convert_ipv6_byte_order(&session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.src_ip_addr.addr.ipv6, (struct in6_addr *)&session->src.v6);
		convert_ipv6_byte_order(&session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.dest_ip_addr.addr.ipv6, (struct in6_addr *)&session->dst.v6);
		convert_ipv6_byte_order(&session_params_tx->peer.peer_data.ip_and_vrf.ip_addr.addr.ipv6, (struct in6_addr *)&session->dst.v6);
	}
	else {
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.src_ip_addr.version = SX_IP_VERSION_IPV4;
		session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.dest_ip_addr.version = SX_IP_VERSION_IPV4;
		session_params_tx->peer.peer_data.ip_and_vrf.ip_addr.version = SX_IP_VERSION_IPV4;
		convert_ipv4_byte_order(&session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.src_ip_addr.addr.ipv4, &session->src.v4);
		convert_ipv4_byte_order(&session_params_tx->session_data.data.tx_data.packet_encap.encap_data.udp_over_ip.dest_ip_addr.addr.ipv4, &session->dst.v4);
		convert_ipv4_byte_order(&session_params_tx->peer.peer_data.ip_and_vrf.ip_addr.addr.ipv4, &session->dst.v4);
	}

	// Construct the TX packet
	bfd_packet_tx->diag = session->diagnostics;
	BFD_SETVER(bfd_packet_tx->diag, BFD_VERSION);
	bfd_packet_tx->len = 24;
	bfd_packet_tx->discrs.my_discr = htonl(session->lid);
	bfd_packet_tx->detect_mult = session->detect_mult;
	/*
	 * Set timer values in packet based on RFC 5880 Section 6.8.3:
	 * - When polling: advertise NEW config values (what we want to negotiate to)
	 * - When not polling: advertise cur_timers (current operational values)
	 */
	bfd_packet_tx->timers.desired_min_tx = htonl(session->config_desired_tx);
	bfd_packet_tx->timers.required_min_rx = htonl(session->config_required_rx);
	bfd_packet_tx->timers.required_min_echo = htonl(session->config_required_echo_rx);

	bfd_packet_tx->flags = 0;
	if (new_session) {
		/** Set the TX state to down */
		BFD_SETSTATE(bfd_packet_tx->flags, BFD_SESSION_DOWN);
		bfd_packet_tx->discrs.remote_discr = 0;
	} else {
		/* Use state and flags from session */
		BFD_SETSTATE(bfd_packet_tx->flags, session->state);
		if (CHECK_FLAG(session->flags, BFD_SESSION_FLAG_CBIT)) {
			BFD_SETCBIT(bfd_packet_tx->flags, BFD_CBIT);
		}
		BFD_SETDEMANDBIT(bfd_packet_tx->flags, BFD_DEF_DEMAND);
		bfd_packet_tx->discrs.remote_discr = htonl(session->rid);
		
		
		if (session->send_final) {
			BFD_SETFBIT(bfd_packet_tx->flags, 1);
		}
		if (!session->send_final && session->polling) {
			BFD_SETPBIT(bfd_packet_tx->flags, 1);
		}
		/* Sanity check: P-bit and F-bit should never be set simultaneously */
		if (session->polling) {
			bfd_packet_tx->timers.desired_min_tx = htonl(session->config_desired_tx);
			bfd_packet_tx->timers.required_min_rx = htonl(session->config_required_rx);
		} else {
			bfd_packet_tx->timers.desired_min_tx = htonl(session->cur_timers_desired_min_tx);
			bfd_packet_tx->timers.required_min_rx = htonl(session->cur_timers_required_min_rx);
		}
	}

	session_params_tx->packet.packet_buffer = (uint8_t*)bfd_packet_tx;
	session_params_tx->packet.buffer_length =  sizeof(struct bfd_pkt);
	session_params_tx->bfd_pid = getpid();

	/* Log TX session construction/update in a single line */
	
	if (bglobal.debug_dplane)
		zlog_err("TX_SESSION_CONSTRUCT: lid=%u rid=%u state=%s(%u) new=%u interval=%u detect_mult=%u min_tx=%u min_rx=%u curr_rx=%u curr_tx=%u P=%u F=%u mhop=%u",
			session->lid, session->rid,
			new_session ? "Down" : (session->state == 0 ? "AdminDown" : session->state == 1 ? "Down" : session->state == 2 ? "Init" : session->state == 3 ? "Up" : "Unknown"),
		   	new_session ? BFD_SESSION_DOWN : session->state,
		   	new_session ? 1 : 0,
		   	session_params_tx->session_data.data.tx_data.interval,
		   	session->detect_mult,
		   	session->config_desired_tx,
		  	session->config_required_rx,
		   	session->cur_timers_required_min_rx,
		  	session->cur_timers_desired_min_tx,
		   	new_session ? 0 : (session->polling ? 1 : 0),
		   	new_session ? 0 : (session->send_final ? 1 : 0),
		   	(session->flags & BFD_SESSION_FLAG_MULTIHOP) ? 1 : 0);

	return;
}

static void bfd_construct_rx_packet(sx_bfd_session_params_t *session_params_rx, struct bfd_pkt *bfd_packet_rx, struct bfd_dplane_server_session *session, bool new_session) 
{
        session_params_rx->session_data.type = SX_BFD_ASYNC_ACTIVE_RX;	
	//if (new_session || session->state != BFD_SESSION_UP)
	//	session_params_rx->session_data.data.rx_data.interval = (BFD_DEFDETECTMULT * BFD_DEF_SLOWTX);
	//else
		session_params_rx->session_data.data.rx_data.interval = session->detect_TO;

	session_params_rx->session_data.data.rx_data.opaque_data = session->lid;
	
	session_params_rx->peer.peer_type = SX_BFD_PEER_IP_AND_VRF;
	session_params_rx->peer.peer_data.ip_and_vrf.vrf_id = session->vrf_id;
	session_params_rx->peer.peer_data.ip_and_vrf.use_vrf_device = 1;
	if (session->vrf_id)
		strlcpy(session_params_rx->peer.peer_data.ip_and_vrf.vrf_linux_name, session->vrfname, sizeof(session_params_rx->peer.peer_data.ip_and_vrf.vrf_linux_name));
	if (session->flags & BFD_SESSION_FLAG_IPV6) {
		session_params_rx->peer.peer_data.ip_and_vrf.ip_addr.version = SX_IP_VERSION_IPV6;
		convert_ipv6_byte_order(&session_params_rx->peer.peer_data.ip_and_vrf.ip_addr.addr.ipv6, (struct in6_addr *)&session->dst.v6);
	} 
	else {
		/* IPv4 address - need byte order conversion for SDK */
		session_params_rx->peer.peer_data.ip_and_vrf.ip_addr.version = SX_IP_VERSION_IPV4;
		/* Extract and convert IPv4 address byte order */
		convert_ipv4_byte_order(&session_params_rx->peer.peer_data.ip_and_vrf.ip_addr.addr.ipv4, &session->dst.v4);
	}

        // Construct the RX packet
        bfd_packet_rx->diag = session->diagnostics;
        BFD_SETVER(bfd_packet_rx->diag, BFD_VERSION);
        bfd_packet_rx->len = 24;
        bfd_packet_rx->discrs.my_discr = htonl(session->rid);
        bfd_packet_rx->discrs.remote_discr = htonl(session->lid);
	bfd_packet_rx->timers.required_min_echo = htonl(session->remote_required_echo_rx);

        bfd_packet_rx->detect_mult = session->remote_detect_mult;
	/* Convert from host to network byte order for packet */
	bfd_packet_rx->timers.desired_min_tx = htonl(session->remote_desired_tx);
	bfd_packet_rx->timers.required_min_rx = htonl(session->remote_required_rx);

        bfd_packet_rx->flags = 0;
        BFD_SETSTATE(bfd_packet_rx->flags, BFD_SESSION_UP);

	/* Log final RX packet template in a single line */
	if (bglobal.debug_dplane)
		zlog_debug("%s: LID=%u detect_TO=%u opaque_data=%llu new=%u state=Up my_discr=%u remote_discr=%u detect_mult=%u min_tx=%u min_rx=%u",
		   	__func__, session->lid, session_params_rx->session_data.data.rx_data.interval,
		   	(unsigned long long)session_params_rx->session_data.data.rx_data.opaque_data, new_session ? 1 : 0,
		   	ntohl(bfd_packet_rx->discrs.my_discr), ntohl(bfd_packet_rx->discrs.remote_discr),
		   	bfd_packet_rx->detect_mult, ntohl(bfd_packet_rx->timers.desired_min_tx), ntohl(bfd_packet_rx->timers.required_min_rx));

        session_params_rx->packet.packet_buffer = (uint8_t*)bfd_packet_rx;
        session_params_rx->packet.buffer_length =  sizeof(struct bfd_pkt);
	session_params_rx->bfd_pid = getpid();

	return;	
}

static void bfd_dplane_update_session_parameters(struct bfd_dplane_server_session *session, const struct bfddp_message *msg) {
        uint32_t flags = ntohl(msg->data.session.flags);
        /* Update session parameters. */

	/* Update local discriminators */
	session->lid = ntohl(msg->data.session.lid);

	/* Update timer configuration */
        session->config_desired_tx = ntohl(msg->data.session.min_tx);
        session->config_required_rx = ntohl(msg->data.session.min_rx);
        session->config_required_echo_rx = ntohl(msg->data.session.min_echo_rx);
	session->min_echo_tx = ntohl(msg->data.session.min_echo_tx);
	session->min_echo_rx = ntohl(msg->data.session.min_echo_rx);

	/* Update session parameters */
        session->vrf_id = msg->data.session.vrf_id;
        session->ttl = BFD_TTL_VAL;//msg->data.session.ttl;
        session->detect_mult = msg->data.session.detect_mult;
	strlcpy(session->vrfname, msg->data.session.vrfname, sizeof(session->vrfname));

	/* Update addresses based on IP version */
        if (flags & SESSION_IPV6) {
                session->flags |= BFD_SESSION_FLAG_IPV6;
                memcpy(&session->src.v6, &msg->data.session.src, sizeof(struct in6_addr));
                memcpy(&session->dst.v6, &msg->data.session.dst, sizeof(struct in6_addr));
        } else {
                session->flags &= ~BFD_SESSION_FLAG_IPV6;
                memcpy(&session->src.v4, &msg->data.session.src, sizeof(struct in_addr));
                memcpy(&session->dst.v4, &msg->data.session.dst, sizeof(struct in_addr));
        }

	/* Update session flags */
        if (flags & SESSION_ECHO)
                session->flags |= BFD_SESSION_FLAG_ECHO;
        else
                session->flags &= ~BFD_SESSION_FLAG_ECHO;

        if (flags & SESSION_CBIT)
                session->flags |= BFD_SESSION_FLAG_CBIT;
        else
                session->flags &= ~BFD_SESSION_FLAG_CBIT;

        if (flags & SESSION_PASSIVE)
                session->flags |= BFD_SESSION_FLAG_PASSIVE;
        else
                session->flags &= ~BFD_SESSION_FLAG_PASSIVE;

        if (flags & SESSION_MULTIHOP)
                session->flags |= BFD_SESSION_FLAG_MULTIHOP;
        else
                session->flags &= ~BFD_SESSION_FLAG_MULTIHOP;

        if (flags & SESSION_SHUTDOWN)
                session->flags |= BFD_SESSION_FLAG_SHUTDOWN;
        else
                session->flags &= ~BFD_SESSION_FLAG_SHUTDOWN;

	/* Update interface information */
        session->ifindex = ntohl(msg->data.session.ifindex);
        strlcpy(session->ifname, msg->data.session.ifname, sizeof(session->ifname));

	return;
}

static void bfd_dplane_server_handle_update_session(struct bfd_dplane_server_client *client,
						    const struct bfddp_message *msg,
						    struct bfd_dplane_server_session *session)
{
	__attribute__((unused)) uint32_t lid = ntohl(msg->data.session.lid);
	bool old_shutdown = session->flags & BFD_SESSION_FLAG_SHUTDOWN;
	uint32_t old_config_desired_tx = session->config_desired_tx;
	uint32_t old_config_required_rx = session->config_required_rx;
	bool old_passive_mode  = session->flags & BFD_SESSION_FLAG_PASSIVE;
	bool is_up = (session->state == BFD_SESSION_UP);

	/* Copy the session parameters */
	bfd_dplane_update_session_parameters(session, msg);  

	bool timer_changed = ((session->config_desired_tx != old_config_desired_tx) ||
				(session->config_required_rx != old_config_required_rx));
	bool passive_mode_changed = old_passive_mode ^ (session->flags & BFD_SESSION_FLAG_PASSIVE);
	bool shutdown_mode_changed = old_shutdown ^ (session->flags & BFD_SESSION_FLAG_SHUTDOWN);
	
	if (passive_mode_changed) {
		//TODO handle this case
	} 
	bool is_shutdown;
        if (session->state == BFD_SESSION_UP)
                is_shutdown = false;
        else
                is_shutdown = CHECK_FLAG(session->state, BFD_SESSION_FLAG_SHUTDOWN);
	//zlog_err("shutdown mode lid=%u %s sutdown_mode_changed =%s", session->lid,  CHECK_FLAG(session->state, BFD_SESSION_FLAG_SHUTDOWN)? "yes": "no", shutdown_mode_changed? "yes":"no");
	if (shutdown_mode_changed) {
		if (session->flags & BFD_SESSION_FLAG_SHUTDOWN) {
			if (is_shutdown)
				return;
			/* Shutting down the session */
			if (bglobal.debug_dplane)
				zlog_err("bfd_dplane_server_handle_update_session: shutdown session lid=%u state=%d", 
					   session->lid, session->state);
			
			/* Transition to ADMIN_DOWN state */
			session->state = BFD_SESSION_ADMIN_DOWN;
			session->diagnostics = BFD_DPLANE_ADMIN_DOWN;
			
			/* Delete RX session (stop listening for packets) */
			bfd_dplane_delete_rx_session_offload(session);

			/* Update TX session to send Admin Down packet with correct diagnostic */
			bfd_dplane_update_tx_session_offload(session);
			
			/* Delete TX session (after final Admin Down packet is sent) */
			bfd_dplane_delete_tx_session_offload(session);
			
			/* 
			 * Don't notify control plane here - it already called control_notify()
			 * before sending us the update message (see bfd_set_shutdown() in bfd.c
			 * line 1341). The notification from here is only needed when we receive
			 * state changes from the REMOTE peer, not for local config changes.
			 */
		} else {
			//if (!is_shutdown)
			//	return;
			/* Re-enabling the session */
			if (bglobal.debug_dplane)
				zlog_err("bfd_dplane_server_handle_update_session: re-enable session lid=%u", session->lid);
			
			/* 
			 * Don't notify control plane here - it already called control_notify()
			 * before sending us the update message (see bfd_set_shutdown() in bfd.c
			 * line 1379). Sending another notification would cause duplicate notifications to BGP.
			 */
			
			/* Re-enable session: go to DOWN state */
			session->state = BFD_SESSION_DOWN;
			session->diagnostics = BFD_DPLANE_OK;
			bfd_dplane_set_slow_timer(session);
			bfd_dplane_update_tx_session_offload(session);
			/* Re-create sessions in SDK */
			bfd_dplane_update_rx_session_offload(session);
		}
	}
	if (is_up && timer_changed) {
		session->polling = 1;
		bool rx_changed = false;	
		/*
		 * RFC 5880 Section 6.8.3:
		 * - If DesiredMinTxInterval increases: don't change actual rate until poll completes
		 * - If RequiredMinRxInterval reduces: use old value for Detection Time until poll completes
		 * 
		 * For INCREASES in RX requirement or DECREASES in TX: we should use the more
		 * conservative (lenient) value immediately to avoid premature timeouts.
		 * 
		 * Strategy: Update cur_timers to max(old, new) so we advertise and use
		 * the most lenient values during the polling sequence.
		 */
	         
		/* For RX: If increasing requirement, use new (larger) value immediately for our detect_TO */
		if (session->config_required_rx > session->cur_timers_required_min_rx) {
			//session->cur_timers_required_min_rx = session->config_required_rx;
			rx_changed = true;
		}
		
		/* For TX: If increasing interval, keep old (faster) rate until poll completes */
		if (session->config_desired_tx < session->cur_timers_desired_min_tx) {
			session->transmit_interval = session->config_desired_tx;
		}
		
		/* Update both RX (detect_TO) and TX (send POLL) */
		if (rx_changed) {
			session->detect_TO = (uint64_t) session->remote_detect_mult * session->config_required_rx;
			bfd_dplane_update_rx_session_offload(session);
		}
		
		bfd_dplane_update_tx_session_offload(session);
	}
}

/**
 * Handle add session message.
 */
static void bfd_dplane_server_handle_add_session(struct bfd_dplane_server_client *client,
						 const struct bfddp_message *msg)
{
	__attribute__((unused)) sx_status_t rc;
	struct bfd_dplane_server_session *session = NULL;
	__attribute__((unused)) uint32_t lid = ntohl(msg->data.session.lid);

	session = XCALLOC(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_SESSION, sizeof(*session));

	session->lid = ntohl(msg->data.session.lid);
	session->opaque_data = ntohl(msg->data.session.lid);

	strlcpy(session->vrfname, msg->data.session.vrfname, sizeof(session->vrfname));


	/* Add to hash table. */
	session->hb = hash_get(server_ctx->sessions, session, hash_alloc_intern);
	TAILQ_INSERT_TAIL(&server_ctx->session_list, session, entry);
	server_ctx->stats.total_sessions++;

	/* Update the configured parameters */
	bfd_dplane_update_session_parameters(session, msg);

	/* Initiate new connection with slow timers*/
	session->detect_TO = (BFD_DEFDETECTMULT * BFD_DEF_SLOWTX);
	session->transmit_interval = BFD_DEF_SLOWTX;
	bfd_dplane_set_slow_timer(session);
	session->state = BFD_SESSION_DOWN;
	session->remote_state = BFD_SESSION_DOWN;
        session->remote_desired_tx = BFD_DEF_SLOWTX;
        session->remote_required_rx = BFD_DEF_SLOWTX;
        session->remote_required_echo_rx = BFD_DEF_REQ_MIN_ECHO_RX;
	session->detect_mult = BFD_DEFDETECTMULT;
	session->offloaded_tx_session_id = 0;
	session->offloaded_rx_session_id = 0;

	/* Offload the sessions */
	if (!(session->flags & BFD_SESSION_FLAG_SHUTDOWN)) {
		bfd_dplane_new_tx_session_offload(session);
		bfd_dplane_new_rx_session_offload(session);
	}
}

/**
 * Handle delete session message.
 */
static void bfd_dplane_server_handle_delete_session(struct bfd_dplane_server_client *client,
						    const struct bfddp_message *msg)
{
	struct bfd_dplane_server_session *session = NULL;
	uint32_t lid = ntohl(msg->data.session.lid);

	/* Look for session. */
	session = hash_lookup(server_ctx->sessions, &lid);
	if (!session) {
		zlog_err("Server plugin: Delete session: session lid=%u not found", lid);
		return;
	}

	/* Delete the TX and RX session */
	if (session->offloaded_tx_session_id)
		bfd_dplane_delete_tx_session_offload(session);
	if (session->offloaded_rx_session_id)
		bfd_dplane_delete_rx_session_offload(session);

	/* Remove from hash table and free. */
	hash_release(server_ctx->sessions, session->hb);
	TAILQ_REMOVE(&server_ctx->session_list, session, entry);
	
	server_ctx->stats.active_sessions--;

	XFREE(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_SESSION, session);
}

/**
 * Handle request session counters message.
 */
static void bfd_dplane_server_handle_request_counters(struct bfd_dplane_server_client *client,
						      const struct bfddp_message *msg)
{
	struct bfd_dplane_server_session *session;
	struct bfddp_message reply = {};
	uint32_t lid = ntohl(msg->data.counters_req.lid);
	uint16_t msglen = sizeof(reply.header) + sizeof(reply.data.session_counters);

	/* Look for session. */
	session = hash_lookup(server_ctx->sessions, &lid);
	if (!session) {
		zlog_err("Server plugin: Request counters: session lid=%u not found", lid);
		return;
	}

	/* Prepare reply header. */
	reply.header.version = BFD_DP_VERSION;
	reply.header.type = htons(BFD_SESSION_COUNTERS);
	reply.header.length = htons(msglen);
	reply.header.id = msg->header.id;

	/* Fill counters data. */
	reply.data.session_counters.lid = htonl(session->lid);
	reply.data.session_counters.control_input_bytes = htobe64(session->stats.control_input_bytes);
	reply.data.session_counters.control_input_packets = htobe64(session->stats.control_input_packets);
	reply.data.session_counters.control_output_bytes = htobe64(session->stats.control_output_bytes);
	reply.data.session_counters.control_output_packets = htobe64(session->stats.control_output_packets);
	reply.data.session_counters.echo_input_bytes = htobe64(session->stats.echo_input_bytes);
	reply.data.session_counters.echo_input_packets = htobe64(session->stats.echo_input_packets);
	reply.data.session_counters.echo_output_bytes = htobe64(session->stats.echo_output_bytes);
	reply.data.session_counters.echo_output_packets = htobe64(session->stats.echo_output_packets);

	bfd_dplane_server_send_message(client, &reply);
}

/**
 * Handle incoming message from client.
 */
static int bfd_dplane_server_handle_message(struct bfd_dplane_server_client *client,
					    const struct bfddp_message *msg)
{
	/* coverity[PW.MIXED_ENUM_TYPE] - ntohs returns uint16_t cast to enum bfddp_message_type */
	enum bfddp_message_type msg_type = ntohs(msg->header.type);

	server_ctx->stats.messages_processed++;
	if (!sx_handle && msg_type != DP_INIT_SDK) {
		zlog_err("%s: SDK is not initialized", __func__);
		return 0;
	}

	switch (msg_type) {
	case ECHO_REQUEST:
		server_ctx->stats.echo_requests++;
		//Not supported
		break;

	case DP_ADD_SESSION:
		uint32_t lid = ntohl(msg->data.session.lid);
		struct bfd_dplane_server_session* session = hash_lookup(server_ctx->sessions, &lid);
		if (!session)
			bfd_dplane_server_handle_add_session(client, msg);
		else
			bfd_dplane_server_handle_update_session(client, msg, session);
		break;

	case DP_DELETE_SESSION:
		bfd_dplane_server_handle_delete_session(client, msg);
		break;

	case DP_REQUEST_SESSION_COUNTERS:
		bfd_dplane_server_handle_request_counters(client, msg);
		break;

	case DP_INIT_SDK:
		bfd_dplane_server_handle_init_sdk(client, msg);
		break;

	case DP_DEINIT_SDK:
		bfd_dplane_server_handle_deinit_sdk(client, msg);
		break;

	case ECHO_REPLY:
	case BFD_STATE_CHANGE:
	case BFD_SESSION_COUNTERS:
		/* These are not expected from clients. */
		zlog_err("Server plugin: Unexpected message type %d from client", msg_type);
		break;

	default:
		zlog_err("Server plugin: Unknown message type %d from client", msg_type);
		break;
	}

	return 0;
}

/**
 * Client write handler.
 */
static void bfd_dplane_server_client_write(struct event *t)
{
	struct bfd_dplane_server_client *client = EVENT_ARG(t);
	ssize_t written;

	while (STREAM_READABLE(client->outbuf)) {
		written = stream_flush(client->outbuf, client->sock);
		if (written == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				break;
			zlog_warn("Server plugin: Failed to write to client socket: %s", strerror(errno));
			//bfd_dplane_server_client_free(client);
			return;
		}
		if (written == 0) {
			zlog_err("Server plugin: Client disconnected");
			//bfd_dplane_server_client_free(client);
			return;
		}

		client->out_bytes += written;
		stream_forward_getp(client->outbuf, written);
	}

	stream_pulldown(client->outbuf);
	EVENT_OFF(client->outbufev);
}

/**
 * Client read handler.
 */
static void bfd_dplane_server_client_read(struct event *t)
{
	struct bfd_dplane_server_client *client = EVENT_ARG(t);
	struct bfddp_message_header *header;
	size_t rlen = 0;
	ssize_t rv;

read_again:
	/* Read data from client. */
	rv = stream_read_try(client->inbuf, client->sock, STREAM_WRITEABLE(client->inbuf));
	if (rv == 0) {
		zlog_err("bfd_dplane_server_client_read: Server plugin: 0 bytes read");
		//bfd_dplane_server_client_free(client);
		return;
	}
	if (rv == -1) {
		zlog_warn("Server plugin: Failed to read from client socket: %s", strerror(errno));
		//bfd_dplane_server_client_free(client);
		return;
	}
	if (rv == -2) {
		/* Would block, reschedule. */
		event_add_read(master, bfd_dplane_server_client_read, client,
			       client->sock, &client->inbufev);
		return;
	}

	client->in_bytes += rv;
	rlen = STREAM_READABLE(client->inbuf);

	/* Process complete messages. */
	while (rlen >= sizeof(struct bfddp_message_header)) {
		header = (struct bfddp_message_header *)stream_pnt(client->inbuf);
		
		/* Check if we have a complete message. */
		if (ntohs(header->length) > rlen)
			goto read_again;

		/* Validate message. */
		if (header->version != BFD_DP_VERSION) {
			zlog_err("Server plugin: Invalid protocol version %d from client", header->version);
			//bfd_dplane_server_client_free(client);
			return;
		}

		/* Handle the message. */
		bfd_dplane_server_handle_message(client, (struct bfddp_message *)header);

		/* Advance buffer. */
		stream_forward_getp(client->inbuf, ntohs(header->length));
		rlen -= ntohs(header->length);
		client->in_msgs++;

		/* Reorganize buffer periodically. */
		if (client->in_msgs % 10 == 0)
			stream_pulldown(client->inbuf);
	}

	/* Reschedule read. */
	event_add_read(master, bfd_dplane_server_client_read, client,
		       client->sock, &client->inbufev);
}

/**
 * Free client context.
 */
static void bfd_dplane_server_client_free(struct bfd_dplane_server_client *client)
{
	if (!client)
		return;

	zlog_err("Server plugin: Freeing client connection");

	/* Remove from client list. */
	TAILQ_REMOVE(&server_ctx->clients, client, entry);
	server_ctx->stats.active_clients--;

	/* Close socket and free resources. */
	socket_close(&client->sock);
	stream_free(client->inbuf);
	stream_free(client->outbuf);
	EVENT_OFF(client->inbufev);
	EVENT_OFF(client->outbufev);

	XFREE(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_CTX, client);
}

/**
 * Accept new client connection.
 */
static void bfd_dplane_server_accept(struct event *t)
{
	struct bfd_dplane_server_ctx *ctx = EVENT_ARG(t);
	struct bfd_dplane_server_client *client;
	struct sockaddr_un client_addr;
	int sock;
	socklen_t addrlen = sizeof(struct sockaddr_un);

	/* Accept new connection. */
	sock = accept(ctx->listen_sock, (struct sockaddr *)&client_addr, &addrlen);
	if (sock == -1) {
		zlog_warn("Server plugin: Failed to accept client connection: %s", strerror(errno));
		goto reschedule;
	}

	/* Set non-blocking. */
	set_nonblocking(sock);

	/* Create client context. */
	client = XCALLOC(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_CTX, sizeof(*client));
	client->sock = sock;
	client->addrlen = addrlen;
	client->inbuf = stream_new(BFD_DPLANE_SERVER_BUF_SIZE);
	client->outbuf = stream_new(BFD_DPLANE_SERVER_BUF_SIZE);

	/* Add to client list. */
	TAILQ_INSERT_TAIL(&ctx->clients, client, entry);
	ctx->stats.active_clients++;
	ctx->stats.total_clients++;

	/* Start reading from client. */
	event_add_read(master, bfd_dplane_server_client_read, client,
		       sock, &client->inbufev);

	zlog_info("Server plugin: New client connected (total: %lu)", ctx->stats.active_clients);

reschedule:
	/* Reschedule accept. */
	event_add_read(master, bfd_dplane_server_accept, ctx, ctx->listen_sock,
		       &ctx->accept_ev);
}

/**
 * Initialize BFD data plane server plugin.
 */
static int bfd_dplane_server_plugin_init(const char *socket_path)
{
	struct bfd_dplane_server_ctx *ctx;

	if (plugin_initialized) {
		zlog_warn("BFD data plane server plugin already initialized");
		return -1;
	}

	/* Use default path if none provided. */
	if (!socket_path)
		socket_path = BFD_DPLANE_SERVER_SOCK_PATH;

	zlog_info("Initializing BFD data plane server plugin on %s", socket_path);

	/* Create server context. */
	ctx = XCALLOC(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_CTX, sizeof(*ctx));
	ctx->listen_sock = -1;
	ctx->last_id = 0;
	TAILQ_INIT(&ctx->clients);
	TAILQ_INIT(&ctx->session_list);

	/* Create session hash table. */
	ctx->sessions = hash_create(bfd_dplane_server_session_hash, 
				     bfd_dplane_server_session_hash_equal,
				     "BFD Data Plane Server Plugin Sessions");

	/* Set socket path. */
	strlcpy(ctx->socket_path, socket_path, sizeof(ctx->socket_path));

	server_ctx = ctx;
	plugin_initialized = true;
	bfd_dplane_server_plugin_start();
	zlog_info("BFD data plane server plugin initialized successfully");

	return 0;
}

/**
 * Start BFD data plane server plugin.
 */
static int bfd_dplane_server_plugin_start(void)
{
	struct sockaddr_un sun;
	int sock;

	if (!plugin_initialized) {
		zlog_warn("BFD data plane server plugin not initialized");
		return -1;
	}

	/* coverity[lock_evasion] - False positive: BFD runs in single-threaded event loop */
	if (plugin_running) {
		zlog_warn("BFD data plane server plugin already running");
		return -1;
	}

	zlog_info("Starting BFD data plane server plugin on %s", server_ctx->socket_path);

	/* Create Unix socket. */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		zlog_err("%s: Failed to create Unix socket: %s", __func__, strerror(errno));
		return -1;
	}

	/* Remove existing socket file. */
	unlink(server_ctx->socket_path);

	/* Bind to socket path. */
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, server_ctx->socket_path, sizeof(sun.sun_path));

	if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		zlog_err("%s: Failed to bind to %s: %s", __func__, server_ctx->socket_path, strerror(errno));
		close(sock);
		return -1;
	}

	/* Set socket permissions. */
	if (chmod(server_ctx->socket_path, 0777) < 0) {
		zlog_warn("%s: Failed to chmod socket %s: %s", __func__, 
			  server_ctx->socket_path, strerror(errno));
	}

	/* Listen for connections. */
	if (listen(sock, SOMAXCONN) == -1) {
		zlog_err("%s: Failed to listen on socket: %s", __func__, strerror(errno));
		close(sock);
		unlink(server_ctx->socket_path);
		return -1;
	}

	server_ctx->listen_sock = sock;

	/* Start accepting connections. */
	event_add_read(master, bfd_dplane_server_accept, server_ctx, sock, &server_ctx->accept_ev);

	plugin_running = true;
	zlog_info("%s: BFD data plane server plugin started successfully", __func__);

	return 0;
}

/**
 * Stop BFD data plane server plugin.
 */
static int bfd_dplane_server_plugin_stop(void)
{
	struct bfd_dplane_server_client *client;
	struct bfd_dplane_server_session *session;

	if (!plugin_initialized) {
		zlog_warn("%s: BFD data plane server plugin not initialized", __func__);
		return -1;
	}

	if (!plugin_running) {
		zlog_warn("%s: BFD data plane server plugin not running", __func__);
		return -1;
	}

	/* Close listening socket. */
	EVENT_OFF(server_ctx->accept_ev);
	if (server_ctx->listen_sock != -1) {
		close(server_ctx->listen_sock);
		unlink(server_ctx->socket_path);
	}

	/* Free all clients. */
	while ((client = TAILQ_FIRST(&server_ctx->clients)) != NULL) {
		bfd_dplane_server_client_free(client);
	}

	/* Free all sessions. */
	while ((session = TAILQ_FIRST(&server_ctx->session_list)) != NULL) {
		bfd_dplane_server_session_free(session);
	}

	plugin_running = false;
	zlog_info("%s: BFD data plane server plugin stopped", __func__);

	return 0;
}

/**
 * Cleanup BFD data plane server plugin.
 */
static int bfd_dplane_server_plugin_cleanup(void)
{
	if (!plugin_initialized) {
		zlog_warn("%s: BFD data plane server plugin not initialized", __func__);
		return -1;
	}

	/* Stop plugin if running. */
	if (plugin_running) {
		bfd_dplane_server_plugin_stop();
	}

	/* Free hash table. */
	if (server_ctx && server_ctx->sessions)
		hash_free(server_ctx->sessions);

	/* Free server context. */
	if (server_ctx) {
		XFREE(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_CTX, server_ctx);
		server_ctx = NULL;
	}

	plugin_initialized = false;
	plugin_running = false;
	zlog_info("%s: BFD data plane server plugin cleanup complete", __func__);

	return 0;
}

/**
 * Free session.
 */
static void bfd_dplane_server_session_free(struct bfd_dplane_server_session *session)
{
	if (!session)
		return;

        /* Delete the TX and RX session */
        bfd_dplane_delete_tx_session_offload(session);
        bfd_dplane_delete_rx_session_offload(session);

	if (session->hb)
		hash_release(server_ctx->sessions, session->hb);

	TAILQ_REMOVE(&server_ctx->session_list, session, entry);
	XFREE(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_SESSION, session);
}

/**
 * Check if this is a hardware platform (not VX/virtual).
 * 
 * @return true if hardware platform, false if virtual platform
 */
static bool
is_hardware_platform(void)
{
	FILE *fp;
	char result[128];
	bool is_hardware = true;

	/* Run platform-detect and check for 'vx' in output */
	fp = popen("/usr/bin/platform-detect 2>/dev/null | grep vx", "r");
	if (fp == NULL) {
		/* If platform-detect doesn't exist, assume hardware platform */
		return true;
	}

	/* If grep finds 'vx', fgets will return non-NULL (virtual platform) */
	if (fgets(result, sizeof(result), fp) != NULL) {
		/* Found 'vx' in output - this is a virtual platform */
		is_hardware = false;
		zlog_info("BFD dplane server plugin: Virtual platform detected: %s", result);
	}

	pclose(fp);
	return is_hardware;
}

/**
 * Plugin initialization hook - runs during frr_init phase.
 * This ensures the server is ready before BFD daemon starts.
 */
static int bfd_dplane_server_plugin_hook_init(struct event_loop *tm)
{
	__attribute__((unused)) sx_status_t rc;
	
	/* Check if this is a hardware platform */
	if (!is_hardware_platform()) {
		zlog_warn("BFD data plane server plugin is only supported on hardware platforms, not on virtual/VX platforms");
		zlog_warn("Plugin will not be initialized");
		/* Return success to not break FRR initialization, just skip plugin loading */
		return 0;
	}

	/* Initialize the plugin. */
	if (bfd_dplane_server_plugin_init(NULL) != 0) {
		zlog_err("%s: Failed to initialize BFD data plane server plugin", __func__);
		return -1;
	}
	return 0;
}

/**
 * SDK initialization..
 * Communication channel open
 * SDK BFD init
 * Register for traps
 */
static int bfd_dplane_server_plugin_sdk_init()
{
	sx_status_t rc;

	/* Initialize the SDK*/
	rc = initialize_sx_sdk();
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to initialize SX SDK for BFD dplane server: %d", __func__, rc);
		return -1;
	}
	rc = initialize_sx_bfd_module();
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to initialize SX SDK BFD module for BFD dplane server: %d", __func__, rc);
		return -1;
	}
	rc = bfd_register_sdk_packet_traps();
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to initialize SX SDK BFD packet traps: %d", __func__, rc);
		return -1;
	}
	rc = bfd_register_sdk_timeout_traps();
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: Failed to initialize SX SDK BFD timeout traps: %d", __func__, rc);
		return -1;
	}

	zlog_info("%s: BFD data plane server plugin hook: initialized successfully (server ready)", __func__);
	return 0;
}

/* ============================================================
 * SDK Init/Deinit Handlers
 * ============================================================ */

/**
 * Handle DP_INIT_SDK message
 * Called when BFD main module detects that sx_sdk servce has come up
 * 
 * This function should:
 * - Re-initialize SDK connection
 * - Re-register packet/timeout traps
 * - Prepare plugin to accept new session configurations
 * 
 * @param client The client that sent the message
 * @param msg The DP_INIT_SDK message (header only)
 */
static void bfd_dplane_server_handle_init_sdk(struct bfd_dplane_server_client *client,
                                               const struct bfddp_message *msg)
{
	/* TODO: User will fill in the implementation */
	/* Suggested implementation:
	 * 1. Close existing SDK handle if any (sx_api_close)
	 * 2. Re-open SDK connection (sx_api_open)
	 * 3. Re-initialize BFD module (sx_api_bfd_init_set)
	 * 4. Re-register packet traps (bfd_register_sdk_packet_traps)
	 * 5. Re-register timeout traps (bfd_register_sdk_timeout_traps)
	 * 6. Clear any stale session state if needed
	 */
        int rc = bfd_dplane_server_plugin_sdk_init();
        if (rc != 0) {
                zlog_err("%s: Failed to initialize BFD SDK module on SDK event", __func__);
        }	
}

/**
 * Handle DP_DEINIT_SDK message
 * Called when BFD main module detects that sx_sdk service has gone down
 * 
 * This function should:
 * - Clean up SDK resources
 * - Unregister traps
 * - Set SDK handle to invalid
 * - Mark all sessions as not offloaded
 * 
 * @param client The client that sent the message
 * @param msg The DP_DEINIT_SDK message (header only)
 */
static void bfd_dplane_server_handle_deinit_sdk(struct bfd_dplane_server_client *client,
                                                 const struct bfddp_message *msg)
{
	sx_status_t rc;
	struct bfd_dplane_server_session *session, *session_next;
	int session_count = 0;
	
	/* Step 1: Remove all sessions from hardware and free them */
	if (server_ctx && !TAILQ_EMPTY(&server_ctx->session_list)) {
		zlog_info("%s: DP_DEINIT_SDK - Removing all sessions", __func__);
		
		TAILQ_FOREACH_SAFE(session, &server_ctx->session_list, entry, session_next) {
			if (bglobal.debug_dplane)
				zlog_debug("%s: DP_DEINIT_SDK - Removing session LID=%u", 
			        	__func__, session->lid);
			//session->state == BFD_SESSION_ADMIN_DOWN;
			//session->remote_diagnostics = BFD_DPLANE_CONTROL_EXPIRED;
		 	//bfd_dplane_server_handle_state_change(session);	
			/* Remove from hash table */
			if (session->hb) {
				hash_release(server_ctx->sessions, session->hb);
				session->hb = NULL;
			}
			
			/* Remove from list */
			TAILQ_REMOVE(&server_ctx->session_list, session, entry);
			
			/* Free session memory */
			XFREE(MTYPE_BFDD_DPLANE_SERVER_PLUGIN_SESSION, session);
			
			session_count++;
		}
		
		zlog_info("%s: DP_DEINIT_SDK - Removed %d sessions", __func__, session_count);
		
		/* Update statistics */
		server_ctx->stats.total_sessions = 0;
		server_ctx->stats.active_sessions = 0;
	}
	
	/* Step 2: Deinitialize SDK resources (traps, channels, etc.) */
	rc = deinitialize_sx_sdk_bfd();
	if (rc != SX_STATUS_SUCCESS) {
		zlog_err("%s: DP_DEINIT_SDK - Failed to de-initialize SX SDK BFD: %d", __func__, rc);
		return;
	}
}

/**
 * Plugin cleanup hook.
 */
static int bfd_dplane_server_plugin_hook_cleanup(void)
{
	sx_status_t rc;
	/* Cleanup the plugin. */
	if (bfd_dplane_server_plugin_cleanup() != 0) {
		zlog_err("%s: Failed to cleanup BFD data plane server plugin", __func__);
		//return -1;
	}

	rc = deinitialize_sx_sdk_bfd();
	if (rc != SX_STATUS_SUCCESS) {
                zlog_err("%s: Failed to de-initialize SX SDK BFD: %d", __func__, rc);
                //return -1;
	}
	return 0;
}

/**
 * Module initialization.
 */
static int bfd_dplane_server_plugin_module_init(void)
{
	zlog_info("%s: BFD data plane server plugin module: loading", __func__);

	/* Register hooks. */
	hook_register(frr_late_init, bfd_dplane_server_plugin_hook_init);
	hook_register(frr_fini, bfd_dplane_server_plugin_hook_cleanup);

	return 0;
}

/**
 * FRR module setup.
 */
/* coverity[RW.EXP_TYPE_SPECIFIER] - FRR_MODULE_SETUP macro expands correctly */
/* coverity[PW.MISSING_DECL_SPECIFIERS] - FRR_MODULE_SETUP macro expands correctly */
FRR_MODULE_SETUP(
	.name = "bfd_dplane_server_plugin",
	.version = "0.0.1",
	.description = "BFD data plane server plugin using Unix socket",
	.init = bfd_dplane_server_plugin_module_init,
);

#else /* !HAVE_SX_SDK_SX_API_H */

/*
 * Stub implementation when SX SDK is not available.
 * This file will be compiled but the plugin won't be built as a module
 * due to the conditional in bfdd/subdir.am
 */

#include <zebra.h>

#include "lib/log.h"

void __bfd_dplane_server_plugin_stub(void)
{
	/* This is a stub to ensure the file compiles when SX SDK is not available.
	 * The actual module won't be loaded because MLXSDK_LIBS_BUILT_INSTALLED
	 * conditional in subdir.am prevents building the .la module.
	 */
	zlog_err("BFD data plane server plugin requires Mellanox SX SDK, "
		 "which is not available on this platform");
}

#endif /* HAVE_SX_SDK_SX_API_H */


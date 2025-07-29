#include "bgpd/bgpd.h"
#include "northbound.h"
#include "bgpd/bgp_debug.h"
#include "lib/vrf.h"
#include "lib/debug.h"
#include "bgp_vty.h"

/*
 * XPath: /frr-bgp-peer:lib/vrf
 */
const void *lib_vrf_get_next(struct nb_cb_get_next_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;
	if (args->list_entry == NULL) {
		vrfp = RB_MIN(vrf_name_head, &vrfs_by_name);
	} else {
		vrfp = RB_NEXT(vrf_name_head, vrfp);
	}
	return vrfp;
}

int lib_vrf_get_keys(struct nb_cb_get_keys_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;
	args->keys->num = 1;
	DEBUGD(&nb_dbg_events, "Vrf %s", vrfp->name);
	strlcpy(args->keys->key[0], vrfp->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

int lib_vrf_peer_afi_safi_get_keys(struct nb_cb_get_keys_args *args)
{
	if (!args || !args->list_entry)
		return NB_OK;
	args->keys->num = 1;
	struct peer_af *paf;
	paf = (struct peer_af *)args->list_entry;
	if (yang_afi_safi_value2identity(paf->afi, paf->safi))
		strlcpy(args->keys->key[0], yang_afi_safi_value2identity(paf->afi, paf->safi),
			sizeof(args->keys->key[0]));
	else
		strlcpy(args->keys->key[0], "", sizeof(args->keys->key[0]));
	return NB_OK;
}

const void *lib_vrf_peer_afi_safi_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct peer *peer = (struct peer *)args->parent_list_entry;
	struct peer_af *paf = NULL;
	enum bgp_af_index index;
	if (!peer) {
		DEBUGD(&nb_dbg_events, "Parent list doesn't hold peer");
		return NULL;
	}
	const char *afisafi_name = args->keys->key[0];
	index = yang_afi_safi_name2index(afisafi_name);
	DEBUGD(&nb_dbg_events, "AFI index is %d", index);
	paf = peer->peer_af_array[index];
	return paf;
}

const void *lib_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrfname = args->keys->key[0];
	struct vrf *vrf = vrf_lookup_by_name(vrfname);
	return vrf;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/id
 */
struct yang_data *lib_vrf_id_get_elem(struct nb_cb_get_elem_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;
	return yang_data_new_uint32(args->xpath, vrfp->vrf_id);
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer
 */
const void *lib_vrf_peer_get_next(struct nb_cb_get_next_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;
	struct vrf *vrfp = (struct vrf *)args->parent_list_entry;

	if (!vrfp) {
		DEBUGD(&nb_dbg_events, "VRF NULL in parent list");
		return NULL;
	}
	if (!vrfp->vrf_id)
		bgp = bgp_get_default();
	else
		bgp = bgp_lookup_by_vrf_id(vrfp->vrf_id);
	if (!bgp || !bgp->peer) {
		DEBUGD(&nb_dbg_events, "No BGP peers in vrf %d", vrfp->vrf_id);
		return NULL;
	}
	if (args->list_entry == NULL) {
		if (bgp)
			return listnode_head(bgp->peer);
	} else {
		peer = (struct peer *)args->list_entry;
		if (!peer)
			return NULL;
		node = listnode_lookup(bgp->peer, peer);
		nnode = listnextnode(node);
		if (nnode)
			return listgetdata(nnode);
		else
			return NULL;
	}
	return NULL;
}

int lib_vrf_peer_get_keys(struct nb_cb_get_keys_args *args)
{
	args->keys->num = 1;
	if (args->list_entry) {
		struct peer *peer = (struct peer *)args->list_entry;
		if (peer) {
			if (peer->conf_if)
				strlcpy(args->keys->key[0], peer->conf_if,
					sizeof(args->keys->key[0]));
			else if (peer->host)
				strlcpy(args->keys->key[0], peer->host, sizeof(args->keys->key[0]));
			else {
				char buf[INET6_ADDRSTRLEN];
				if (peer->connection->su.sa.sa_family == AF_INET) {
					inet_ntop(AF_INET,
						  &peer->connection->su.sin.sin_addr, buf,
						  sizeof(buf));
					strlcpy(args->keys->key[0], buf,
						sizeof(args->keys->key[0]));
				} else if (peer->connection->su.sa.sa_family == AF_INET6) {
					if (inet_ntop(AF_INET6, &peer->connection->su.sin6.sin6_addr, buf, INET6_ADDRSTRLEN) == NULL) {
						return NB_ERR;
					}
					strlcpy(args->keys->key[0], buf,
						sizeof(args->keys->key[0]));
				}
			}
		}
		DEBUGD(&nb_dbg_events, "Peer name %s", args->keys->key[0]);
	}
	return NB_OK;
}

const void *lib_vrf_peer_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	if (!args || !args->keys || !args->parent_list_entry) {
		DEBUGD(&nb_dbg_events, "Key or Parent list is NULL");
		return NULL;
	}
	const char *peer_str = args->keys->key[0];
	struct bgp *bgp = NULL;
	struct peer *peer = NULL;
	union sockunion su;
	struct vrf *vrfp = (struct vrf *)args->parent_list_entry;

	if (!vrfp) {
		DEBUGD(&nb_dbg_events, "VRF NULL in parent list");
		return NULL;
	}
	if (!vrfp->vrf_id)
		bgp = bgp_get_default();
	else
		bgp = bgp_lookup_by_vrf_id(vrfp->vrf_id);
	if (!bgp || !bgp->peer) {
		DEBUGD(&nb_dbg_events, "No BGP peers in vrf %d", vrfp->vrf_id);
		return NULL;
	}
	int ret = str2sockunion(peer_str, &su);
	if (ret < 0) {
		peer = peer_lookup_by_hostname(bgp, peer_str);
		if (!peer)
			peer = peer_lookup_by_conf_if(bgp, peer_str);
		return peer;
	} else
		return peer_lookup(bgp, &su);
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/name
 */
struct yang_data *lib_vrf_peer_name_get_elem(struct nb_cb_get_elem_args *args)
{
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/status
 */
struct yang_data *lib_vrf_peer_status_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_string(args->xpath, lookup_msg(bgp_status_msg,
								    peer->connection->status, NULL));
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/established-transitions
 */
struct yang_data *lib_vrf_peer_established_transitions_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	peer = (struct peer *)args->list_entry;
	if (peer)
		return yang_data_new_uint32(args->xpath, peer->established);
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/in-queue
 */
struct yang_data *lib_vrf_peer_in_queue_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	struct yang_data *ret;
	peer = (struct peer *)args->list_entry;
	if (peer) {
		frr_with_mutex (&peer->connection->io_mtx) {
			ret = yang_data_new_uint32(args->xpath, peer->connection->ibuf->count);
		}
		return ret;
	}
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/out-queue
 */
struct yang_data *lib_vrf_peer_out_queue_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	struct yang_data *ret;
	peer = (struct peer *)args->list_entry;
	if (peer) {
		frr_with_mutex (&peer->connection->io_mtx) {
			ret = yang_data_new_uint32(args->xpath, peer->connection->obuf->count);
		}
		return ret;
	}
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/tx-updates
 */
struct yang_data *lib_vrf_peer_tx_updates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	int update_out = 0;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	update_out = atomic_load_explicit(&peer->update_out, memory_order_relaxed);
	return yang_data_new_uint32(args->xpath, update_out);
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/rx-updates
 */
struct yang_data *lib_vrf_peer_rx_updates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	int update_in = 0;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	update_in = atomic_load_explicit(&peer->update_in, memory_order_relaxed);
	return yang_data_new_uint32(args->xpath, update_in);
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/total-msgs-sent
 */
struct yang_data *lib_vrf_peer_total_msgs_sent_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	return yang_data_new_uint32(args->xpath, PEER_TOTAL_TX(peer));
}

/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/total-msgs_rcvd
 *   */
struct yang_data *lib_vrf_peer_total_msgs_recvd_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	return yang_data_new_uint32(args->xpath, PEER_TOTAL_RX(peer));
}

/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/local-as
 *   */
struct yang_data *
lib_vrf_peer_local_as_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	return yang_data_new_uint32(args->xpath, peer->local_as);
}
/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/peer-as
 *   */
struct yang_data *
lib_vrf_peer_as_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	return yang_data_new_uint32(args->xpath, peer->as);
}
/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/last-established
 *   */
struct yang_data *
lib_vrf_peer_last_established_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	time_t uptime;
	time_t epoch_tbuf;

	uptime = monotime(NULL);
	uptime -= peer->uptime;
	epoch_tbuf = time(NULL) - uptime;
	return yang_data_new_uint64(args->xpath, epoch_tbuf);
}
/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/description
 *   */
struct yang_data *
lib_vrf_peer_description_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	if (peer->desc == NULL){
		return yang_data_new_string(args->xpath, "");
	}
	return yang_data_new_string(args->xpath, peer->desc);
}

/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/peer-group
 *   */
struct yang_data *
lib_vrf_peer_group_get_elem(struct nb_cb_get_elem_args *args){
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	if (peer->group == NULL){
		return yang_data_new_string(args->xpath, "");
	}
	return yang_data_new_string(args->xpath, peer->group->name);
}

/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/peer-type
 *   */
struct yang_data *
lib_vrf_peer_type_get_elem(struct nb_cb_get_elem_args *args){
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	if (!peer->sort)
		return yang_data_new_string(args->xpath, "");
	return yang_data_new_string(args->xpath, yang_peer_type2str(peer->sort));
}
/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/neighbor-address
 *   */
struct yang_data *
lib_vrf_peer_neighbor_address_get_elem(struct nb_cb_get_elem_args *args){
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	if (peer->connection->su.sa.sa_family == AF_INET) {
		return yang_data_new_string(args->xpath, inet_ntoa(peer->connection->su.sin.sin_addr));
	} else if (peer->connection->su.sa.sa_family == AF_INET6) {
		char addr_str[INET6_ADDRSTRLEN];
		if (inet_ntop(AF_INET6, &peer->connection->su.sin6.sin6_addr, addr_str, INET6_ADDRSTRLEN) == NULL) {
			return yang_data_new_string(args->xpath, "");
		}
		return yang_data_new_string(args->xpath, addr_str);
	}
	return yang_data_new_string(args->xpath, "");
}

/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/messages/sent/last-notification-error-code
 *   */
struct yang_data *
lib_vrf_peer_messages_sent_last_notification_error_code_get_elem(struct nb_cb_get_elem_args *args){
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	if (!peer->notify.code_sent)
		return yang_data_new_string(args->xpath, "");
	return yang_data_new_string(args->xpath, yang_bgp_notify_code2str(peer->notify.code_sent));
}
/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/messages/received/last-notification-error-code
 *   */
struct yang_data *
lib_vrf_peer_messages_received_last_notification_error_code_get_elem(struct nb_cb_get_elem_args *args){
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	if (!peer->notify.code_received)
		return yang_data_new_string(args->xpath, "");
	return yang_data_new_string(args->xpath, yang_bgp_notify_code2str(peer->notify.code_received));
}
/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/graceful-shutdown
 *  Streams peer graceful shutdown status
 *  Ref Nvue config command : nv set vrf default router bgp neighbor swp1s1 graceful-shutdown on
 *  Ref Nvue show command : nv show vrf default router bgp neighbor swp1s1
 *   */
struct yang_data *lib_vrf_peer_graceful_shutdown_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer;
	if (!args || !args->list_entry)
		return NULL;
	peer = (struct peer *)args->list_entry;
	return yang_data_new_bool(args->xpath,
				  bgp_in_graceful_shutdown(peer->bgp) ||
					  CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_SHUTDOWN));
}
/*
 *  * XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi
 *   */
const void *lib_vrf_peer_afi_safi_get_next(struct nb_cb_get_next_args *args)
{
	if (!args || !args->parent_list_entry)
		return NULL;
	struct peer *peer = (struct peer *)args->parent_list_entry;
	struct peer_af *paf;
	int index;
	if (!args->list_entry) {
		for (index = BGP_AF_START; index < BGP_AF_MAX; index++) {
			if (peer->peer_af_array[index]) {
				paf = peer->peer_af_array[index];
				return paf;
			}
		}
	} else {
		paf = (struct peer_af *)args->list_entry;
		for (index = paf->afid + 1; index < BGP_AF_MAX; index++) {
			if (peer->peer_af_array[index]) {
				paf = peer->peer_af_array[index];
				return paf;
			}
		}
	}
	return NULL;
}

/*
 * XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/afi_safi_afi_safi_name
 */
struct yang_data *lib_vrf_peer_afi_safi_afi_safi_name_get_elem(struct nb_cb_get_elem_args *args)
{
	zlog_err("lib_vrf_peer_afi_safi_afi_safi_name_get_elem with afi safi");
	struct peer_af *paf;
	if (!args || !args->list_entry)
		return NULL;
	paf = (struct peer_af *)args->list_entry;
	return yang_data_new_string(args->xpath, get_afi_safi_str(paf->afi, paf->safi, false));
}

/*
 *  XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx
 */
struct yang_data *lib_vrf_peer_afi_safi_rcvd_pfx_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf;
	if (!args || !args->list_entry)
		return NULL;
	paf = (struct peer_af *)args->list_entry;
	return yang_data_new_uint32(args->xpath, paf->peer->pcount[paf->afi][paf->safi]);
}

/*
 *  XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx-installed
 */
struct yang_data *lib_vrf_peer_afi_safi_rcvd_pfx_installed_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf;
	if (!args || !args->list_entry)
		return NULL;
	paf = (struct peer_af *)args->list_entry;
	return yang_data_new_uint32(args->xpath, paf->peer->pinstalledcnt[paf->afi][paf->safi]);
}

/*
 *  XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx
 */
struct yang_data *lib_vrf_peer_afi_safi_pfx_sent_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf;
	if (!args || !args->list_entry)
		return NULL;
	paf = (struct peer_af *)args->list_entry;
	if (!PAF_SUBGRP(paf)) {
		DEBUGD(&nb_dbg_events, "Peer AF is NULL");
		return NULL;
	}
	return yang_data_new_uint32(args->xpath, (PAF_SUBGRP(paf))->scount);
}

/*
 *  XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/afi
 */
struct yang_data *lib_vrf_peer_afi_safi_afi_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf;
	if (!args || !args->list_entry)
		return NULL;
	paf = (struct peer_af *)args->list_entry;
	return yang_data_new_string(args->xpath, afi2str(paf->afi));
}

/*
 *  XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/safi
 */
struct yang_data *lib_vrf_peer_afi_safi_safi_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf;
	if (!args || !args->list_entry)
		return NULL;
	paf = (struct peer_af *)args->list_entry;
	return yang_data_new_string(args->xpath, safi2str(paf->safi));
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_peer_info = {
	.name = "frr-bgp-peer",
	.nodes = {
		{
			.xpath = "/frr-bgp-peer:lib/vrf",
			.cbs = {
				.get_next = lib_vrf_get_next,
				.get_keys = lib_vrf_get_keys,
				.lookup_entry = lib_vrf_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/id",
			.cbs = {
				.get_elem = lib_vrf_id_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer",
			.cbs = {
				.get_next = lib_vrf_peer_get_next,
				.get_keys = lib_vrf_peer_get_keys,
				.lookup_entry = lib_vrf_peer_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/name",
			.cbs = {
				.get_elem = lib_vrf_peer_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/status",
			.cbs = {
				.get_elem = lib_vrf_peer_status_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/established-transitions",
			.cbs = {
				.get_elem = lib_vrf_peer_established_transitions_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/in-queue",
			.cbs = {
				.get_elem = lib_vrf_peer_in_queue_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/out-queue",
			.cbs = {
				.get_elem = lib_vrf_peer_out_queue_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/sent/updates",
			.cbs = {
				.get_elem = lib_vrf_peer_tx_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/received/updates",
			.cbs = {
				.get_elem = lib_vrf_peer_rx_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/local-as",
			.cbs = {
				.get_elem = lib_vrf_peer_local_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/peer-as",
			.cbs = {
				.get_elem = lib_vrf_peer_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/last-established",
			.cbs = {
				.get_elem = lib_vrf_peer_last_established_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/description",
			.cbs = {
				.get_elem = lib_vrf_peer_description_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/peer-group",
			.cbs = {
				.get_elem = lib_vrf_peer_group_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/peer-type",
			.cbs = {
				.get_elem = lib_vrf_peer_type_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/neighbor-address",
			.cbs = {
				.get_elem = lib_vrf_peer_neighbor_address_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/sent/last-notification-error-code",
			.cbs = {
				.get_elem = lib_vrf_peer_messages_sent_last_notification_error_code_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/received/last-notification-error-code",
			.cbs = {
				.get_elem = lib_vrf_peer_messages_received_last_notification_error_code_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/graceful-shutdown",
			.cbs = {
				.get_elem = lib_vrf_peer_graceful_shutdown_get_elem,
			}
		},
                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi",
                        .cbs = {
                                .get_next = lib_vrf_peer_afi_safi_get_next,
                                .get_keys = lib_vrf_peer_afi_safi_get_keys,
                                .lookup_entry = lib_vrf_peer_afi_safi_lookup_entry,
                        }
                },
                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/afi-safi-name",
                        .cbs = {
                               .get_elem = lib_vrf_peer_afi_safi_afi_safi_name_get_elem,
                        }
                },
	        {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/afi",
                        .cbs = {
                                .get_elem = lib_vrf_peer_afi_safi_afi_get_elem,
                        }
                },
                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/safi",
                        .cbs = {
                                .get_elem = lib_vrf_peer_afi_safi_safi_get_elem,
                        }
                },
                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx",
                        .cbs = {
                                .get_elem = lib_vrf_peer_afi_safi_rcvd_pfx_get_elem,
                        }
                },
		{
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx-installed",
                        .cbs = {
                                .get_elem = lib_vrf_peer_afi_safi_rcvd_pfx_installed_get_elem,
                        }
                },
                                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/pfx-sent",
                        .cbs = {
                                .get_elem = lib_vrf_peer_afi_safi_pfx_sent_get_elem,
                        }
                },
                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/total-msgs-sent",
                        .cbs = {
                                .get_elem = lib_vrf_peer_total_msgs_sent_get_elem,
                        }
                },
                {
                        .xpath = "/frr-bgp-peer:lib/vrf/peer/total-msgs-recvd",
                        .cbs = {
                                .get_elem = lib_vrf_peer_total_msgs_recvd_get_elem,
                        }
                },
		{
			.xpath = NULL,
		},
	}
};

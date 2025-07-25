// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "frrevent.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "srcdest_table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "hash.h"
#include "jhash.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"
#include "static_vty.h"
#include "static_debug.h"
#include "zclient.h"
#include "static_srv6.h"
#include "lib_errors.h"
#include "zebra/interface.h"

DEFINE_MTYPE_STATIC(STATIC, STATIC_NHT_DATA, "Static Nexthop tracking data");
DEFINE_MTYPE_STATIC(STATIC, STATIC_PEER_LL_WAITING_QUEUE,
		    "Static peer link-local waiting queue entry");
DEFINE_MTYPE_STATIC(STATIC, STATIC_IF, "Static interface info");

/* Static interface info structure */
struct static_if {
	uint32_t flags;
};

/* RA flags for static interface */
#define STATIC_IF_FLAG_PEER_LL_WAITING	 (1 << 0)
#define STATIC_IF_FLAG_PEER_LL_CONFIRMED (1 << 1)

PREDECL_HASH(static_nht_hash);

struct static_nht_data {
	struct static_nht_hash_item itm;

	struct prefix nh;
	safi_t safi;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint16_t nh_num;
	bool registered;
};

static int static_nht_data_cmp(const struct static_nht_data *nhtd1,
			       const struct static_nht_data *nhtd2)
{
	if (nhtd1->nh_vrf_id != nhtd2->nh_vrf_id)
		return numcmp(nhtd1->nh_vrf_id, nhtd2->nh_vrf_id);
	if (nhtd1->safi != nhtd2->safi)
		return numcmp(nhtd1->safi, nhtd2->safi);

	return prefix_cmp(&nhtd1->nh, &nhtd2->nh);
}

static unsigned int static_nht_data_hash(const struct static_nht_data *nhtd)
{
	unsigned int key = 0;

	key = prefix_hash_key(&nhtd->nh);
	return jhash_2words(nhtd->nh_vrf_id, nhtd->safi, key);
}

DECLARE_HASH(static_nht_hash, struct static_nht_data, itm, static_nht_data_cmp,
	     static_nht_data_hash);

static struct static_nht_hash_head static_nht_hash[1];

/* Zebra structure to hold current status. */
struct zclient *zclient;
uint32_t zebra_ecmp_count = MULTIPATH_NUM;

/* Queue for uA SID allocation after peer link-local confirmation */
struct static_peer_ll_waiting_queue {
	struct static_srv6_sid *sid;
	struct static_peer_ll_waiting_queue *next;
};

static struct static_peer_ll_waiting_queue *peer_ll_waiting_queue_head = NULL;
static struct static_peer_ll_waiting_queue *peer_ll_waiting_queue_tail = NULL;

static void static_zebra_initiate_ra(struct interface *ifp, bool enable, uint32_t interval)
{
	struct static_if *sif;

	if (!ifp || !zclient || zclient->sock < 0)
		return;

	if (enable) {
		/* Set the waiting flag on staticd's interface structure */
		sif = ifp->info;
		if (sif)
			SET_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_WAITING);

		zclient_send_interface_radv_req(zclient, ifp->vrf->vrf_id, ifp, 1, interval);
	} else {
		/* Clear the waiting flag when disabling RA */
		sif = ifp->info;
		if (sif) {
			UNSET_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_WAITING);
			UNSET_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_CONFIRMED);
		}
		zclient_send_interface_radv_req(zclient, ifp->vrf->vrf_id, ifp, 0, 0);
	}
}

/* Queue uA SID allocation to wait for peer link-local address */
static bool static_queue_ua_sid_allocation_after_peer_ll(struct static_srv6_sid *sid)
{
	struct static_peer_ll_waiting_queue *queue_entry;

	queue_entry = XCALLOC(MTYPE_STATIC_PEER_LL_WAITING_QUEUE,
			      sizeof(struct static_peer_ll_waiting_queue));
	if (!queue_entry)
		return false;

	queue_entry->sid = sid;
	queue_entry->next = NULL;

	if (peer_ll_waiting_queue_tail) {
		peer_ll_waiting_queue_tail->next = queue_entry;
		peer_ll_waiting_queue_tail = queue_entry;
	} else {
		peer_ll_waiting_queue_head = queue_entry;
		peer_ll_waiting_queue_tail = queue_entry;
	}

	/* Set flag to indicate SID is queued waiting for peer link-local */
	SET_FLAG(sid->flags, STATIC_FLAG_SRV6_UA_SID_QUEUED_FOR_PEER_LL);

	DEBUGD(&static_dbg_srv6, "%s: SID %pFX queued for peer link-local confirmation", __func__,
	       &sid->addr);

	return true;
}

/* Process queued uA SID allocations after peer link-local confirmation */
static void static_process_queued_ua_sid_allocations(struct interface *ifp)
{
	struct static_peer_ll_waiting_queue *current, *next;

	current = peer_ll_waiting_queue_head;
	while (current) {
		next = current->next;

		if (strcmp(current->sid->attributes.ifname, ifp->name) == 0) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Processing queued uA SID %pFX for interface %s", __func__,
			       &current->sid->addr, ifp->name);

			/* Proceed with SID allocation */
			static_zebra_request_srv6_sid(current->sid);

			/* Remove from queue */
			if (current == peer_ll_waiting_queue_head) {
				peer_ll_waiting_queue_head = next;
				if (!peer_ll_waiting_queue_head)
					peer_ll_waiting_queue_tail = NULL;
			} else {
				struct static_peer_ll_waiting_queue *prev =
					peer_ll_waiting_queue_head;
				while (prev && prev->next != current)
					prev = prev->next;
				if (prev)
					prev->next = next;
				if (current == peer_ll_waiting_queue_tail)
					peer_ll_waiting_queue_tail = prev;
			}

			UNSET_FLAG(current->sid->flags, STATIC_FLAG_SRV6_UA_SID_QUEUED_FOR_PEER_LL);

			XFREE(MTYPE_STATIC_PEER_LL_WAITING_QUEUE, current);
		}

		current = next;
	}
}

/* Check if uA SID is queued for peer link-local */
static bool static_ua_sid_is_queued_for_peer_ll(struct static_srv6_sid *sid)
{
	return CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_UA_SID_QUEUED_FOR_PEER_LL);
}

/* Check if peer link-local confirmation was received for this interface */
static bool static_peer_ll_confirmation_received(struct interface *ifp)
{
	struct static_if *sif;

	if (!ifp)
		return false;

	sif = ifp->info;
	if (!sif)
		return false;

	return CHECK_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_CONFIRMED);
}

/*
 * uA behavior needs RA only if:
 *   1. Behavior is uA (END_X_NEXT_CSID)
 *   2. Interface is configured
 */
static bool static_srv6_ua_needs_ra(struct static_srv6_sid *sid)
{
	return (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID &&
		sid->attributes.ifname[0] != '\0');
}

/* Remove SID from peer LL waiting queue */
static void static_remove_ua_sid_queued_for_peer_ll(struct static_srv6_sid *sid)
{
	struct static_peer_ll_waiting_queue *current, *next, *prev = NULL;

	current = peer_ll_waiting_queue_head;
	while (current) {
		next = current->next;

		if (current->sid == sid) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Found SID %pFX in peer LL waiting queue, Removing", __func__,
			       &sid->addr);

			/* Remove from queue */
			if (current == peer_ll_waiting_queue_head) {
				peer_ll_waiting_queue_head = next;
				if (!peer_ll_waiting_queue_head)
					peer_ll_waiting_queue_tail = NULL;
			} else {
				if (prev)
					prev->next = next;
				if (current == peer_ll_waiting_queue_tail)
					peer_ll_waiting_queue_tail = prev;
			}

			/* Clear flag to indicate SID is no longer queued for peer LL */
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_UA_SID_QUEUED_FOR_PEER_LL);

			XFREE(MTYPE_STATIC_PEER_LL_WAITING_QUEUE, current);
			break;
		}

		prev = current;
		current = next;
	}
}

/*
 * Checks if there are other uA SIDs on the same interface that need are
 * waiting for peer LL
 *
 * - Checks global SID list for other uA SIDs on the same interface
 * - Checks peer LL waiting queue for other uA SIDs if none found in global list
 * - Always removes sid_to_eval from the peer LL waiting queue if found there
 * - Returns true if other uA SIDs exist on same intf (RA stays enabled)
 * - Returns false if no other uA SIDs exist on same intf (RA can be disabled)
 */
static bool static_ua_sids_exist_on_interface(const char *ifname,
					      struct static_srv6_sid *sid_to_eval)
{
	struct listnode *node = NULL;
	struct static_srv6_sid *sid = NULL;
	struct static_peer_ll_waiting_queue *queue_entry = NULL;
	bool found = false;
	bool sid_to_eval_in_queue = false;

	if (!ifname || ifname[0] == '\0')
		return false;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		/* Skip the SID being evaluated */
		if (sid == sid_to_eval)
			continue;

		if (static_srv6_ua_needs_ra(sid) && strcmp(sid->attributes.ifname, ifname) == 0) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Found other uA SID %pFX on interface %s (in global list)",
			       __func__, &sid->addr, ifname);
			found = true;
			break;
		}
	}

	/* Check if sid_to_eval is in the queue using the flag */
	if (static_ua_sid_is_queued_for_peer_ll(sid_to_eval)) {
		sid_to_eval_in_queue = true;
	}

	/* Check if other sids in queue are on the same interface */
	if (!found) {
		queue_entry = peer_ll_waiting_queue_head;
		while (queue_entry) {
			/* Skip the SID being evaluated */
			if (queue_entry->sid == sid_to_eval) {
				queue_entry = queue_entry->next;
				continue;
			}

			if (strcmp(queue_entry->sid->attributes.ifname, ifname) == 0) {
				DEBUGD(&static_dbg_srv6,
				       "%s: Found other uA SID %pFX on interface %s (in queue)",
				       __func__, &queue_entry->sid->addr, ifname);
				found = true;
				break;
			}

			queue_entry = queue_entry->next;
		}
	}

	if (sid_to_eval_in_queue) {
		DEBUGD(&static_dbg_srv6,
		       "%s: SID to evaluate %pFX is in peer LL waiting queue, Removing it.",
		       __func__, &sid_to_eval->addr);
		static_remove_ua_sid_queued_for_peer_ll(sid_to_eval);
	}

	DEBUGD(&static_dbg_srv6, "%s: Interface %s has other uA SIDs: %s", __func__, ifname,
	       found ? "true" : "false");

	return found;
}

/* Handle enabling/disabling RA for uA behavior */
void static_srv6_ua_handle_ra(struct static_srv6_sid *sid, bool enable)
{
	struct interface *ifp;
	struct static_if *sif;

	DEBUGD(&static_dbg_srv6, "%s: %s RA on interface '%s' for SID %pFX behavior %u", __func__,
	       enable ? "Enabling" : "Disabling", sid->attributes.ifname, &sid->addr, sid->behavior);

	if (!static_srv6_ua_needs_ra(sid))
		return;

	ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("%s: SID %pFX interface '%s' not found in default VRF", __func__,
			  &sid->addr, sid->attributes.ifname);
		return;
	}

	if (enable) {
		sif = ifp->info;
		if (sif && CHECK_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_WAITING)) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Interface '%s' already has RA waiting to be enabled, skipping for SID %pFX ",
			       __func__, ifp->name, &sid->addr);
			return;
		}

		DEBUGD(&static_dbg_srv6,
		       "%s:Requesting RA on interface '%s' with 1s interval for SID %pFX  ",
		       __func__, ifp->name, &sid->addr);
		static_zebra_initiate_ra(ifp, true, 1);
	} else {
		/* Check if there are other uA SIDs on the same interface before releasing RA */
		if (static_ua_sids_exist_on_interface(sid->attributes.ifname, sid)) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Interface '%s' has other uA SIDs, keeping RA enabled(evaluated for SID %pFX) ",
			       __func__, ifp->name, &sid->addr);
			return;
		}

		DEBUGD(&static_dbg_srv6, "%s: Disabling RA on interface %s for SID %pFX", __func__,
		       ifp->name, &sid->addr);
		static_zebra_initiate_ra(ifp, false, 0);
	}
}

/* Clean up RA queue during shutdown */
void static_srv6_ua_sids_cleanup_queued_for_peer_ll(void)
{
	struct static_peer_ll_waiting_queue *current, *next;

	current = peer_ll_waiting_queue_head;
	while (current) {
		next = current->next;
		DEBUGD(&static_dbg_srv6,
		       "%s: Shutdown: Freeing peer LL waiting queue entry for SID %pFX", __func__,
		       &current->sid->addr);
		XFREE(MTYPE_STATIC_PEER_LL_WAITING_QUEUE, current);
		current = next;
	}

	peer_ll_waiting_queue_head = NULL;
	peer_ll_waiting_queue_tail = NULL;
}

/* Peer link-local confirmation callback handler */
static int static_zebra_peer_ll_confirmation(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	ifindex_t ifindex;
	struct interface *ifp;
	struct static_if *sif;

	s = zclient->ibuf;

	/* Get interface index */
	STREAM_GETL(s, ifindex);

	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (!ifp) {
		zlog_err("%s: Peer link-local confirmation for unknown interface %u", __func__,
			 ifindex);
		return -1;
	}

	if (static_srv6_un_ua_sids_enabled) {
		sif = ifp->info;
		if (!sif) {
			zlog_warn("%s: No static interface info for %s", __func__, ifp->name);
			return -1;
		}

		/* Set the peer link-local confirmation flag and clear the waiting flag */
		SET_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_CONFIRMED);
		UNSET_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_WAITING);

		DEBUGD(&static_dbg_srv6,
		       "%s: Peer link-local confirmation received for interface %s (ifindex %u)",
		       __func__, ifp->name, ifindex);

		/* Process queued uA SID allocations for this interface */
		static_process_queued_ua_sid_allocations(ifp);
	} else
		DEBUGD(&static_dbg_srv6,
		       "%s: Ignoring peer link-local confirmation for interface %s (ifindex %u) as Feature for SRv6 uN/uA SIDs is disabled",
		       __func__, ifp->name, ifindex);

	return 0;

stream_failure:
	return -1;
}

static void static_zebra_peer_ll_change_handler(struct interface *ifp, struct in6_addr *new_ll_addr)
{
	struct static_if *sif;
	struct listnode *node;
	struct static_srv6_sid *sid;

	assert(new_ll_addr);
	sif = ifp->info;
	if (!sif)
		return;

	DEBUGD(&static_dbg_srv6,
	       "%s: Peer LL changed on interface %s to %pI6, Uninstall Existing sids and Reinstalling sid with new LL",
	       __func__, ifp->name, new_ll_addr);

	/* Update next-hop to new LL and reinstall SIDs (alloc + install) */
	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (strcmp(sid->attributes.ifname, ifp->name) == 0 &&
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID) {
			if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
				static_zebra_release_srv6_sid(sid);
				UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
			}

			if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
				static_zebra_srv6_sid_uninstall(sid);
				UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
			}

			sid->attributes.nh6 = *new_ll_addr;
			DEBUGD(&static_dbg_srv6,
			       "%s: Updated SID %pFX next-hop to %pI6 for reinstallation", __func__,
			       &sid->addr, &sid->attributes.nh6);

			static_zebra_request_srv6_sid(sid);
		}
	}
}

static int static_zebra_peer_ll_change(ZAPI_CALLBACK_ARGS)
{
	struct stream *s;
	ifindex_t ifindex;
	struct interface *ifp;
	struct in6_addr new_ll_addr;

	s = zclient->ibuf;
	STREAM_GETL(s, ifindex);

	/* Get the new LL address */
	STREAM_GET(&new_ll_addr, s, sizeof(struct in6_addr));

	ifp = if_lookup_by_index(ifindex, vrf_id);
	if (!ifp) {
		zlog_err("%s: Peer link-local change for unknown interface %u", __func__, ifindex);
		return -1;
	}

	if (static_srv6_un_ua_sids_enabled)
		static_zebra_peer_ll_change_handler(ifp, &new_ll_addr);
	else
		DEBUGD(&static_dbg_srv6,
		       "%s: Ignoring peer link-local change for interface %s (ifindex %u) as Feature for SRv6 uN/uA SIDs is disabled",
		       __func__, ifp->name, ifindex);

	return 0;

stream_failure:
	return -1;
}

/* Interface addition message from zebra. */
static int static_ifp_create(struct interface *ifp)
{
	struct static_if *sif;

	sif = XCALLOC(MTYPE_STATIC_IF, sizeof(struct static_if));
	if (!sif)
		return -1;

	ifp->info = sif;
	static_ifindex_update(ifp, true);

	return 0;
}

static int static_ifp_destroy(struct interface *ifp)
{
	static_ifindex_update(ifp, false);
	if (ifp->info) {
		XFREE(MTYPE_STATIC_IF, ifp->info);
		ifp->info = NULL;
	}

	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static int static_ifp_up(struct interface *ifp)
{
	struct listnode *node;
	struct static_srv6_sid *sid;

	static_ifindex_update(ifp, true);

	if (static_srv6_un_ua_sids_enabled) {
		/* Re-queue SIDs that need peer LL confirmation for this interface */
		if (srv6_sids) {
			for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
				if (static_srv6_ua_needs_ra(sid) && sid->attributes.ifname[0] &&
				    strcmp(sid->attributes.ifname, ifp->name) == 0 &&
				    !CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID) &&
				    !static_ua_sid_is_queued_for_peer_ll(sid) &&
				    !static_peer_ll_confirmation_received(ifp)) {
					DEBUGD(&static_dbg_srv6,
					       "%s: Interface %s up, re-queuing SID %pFX for peer LL confirmation",
					       __func__, ifp->name, &sid->addr);

					static_queue_ua_sid_allocation_after_peer_ll(sid);
				}
			}
		}

		static_ifp_srv6_sids_update(ifp, true);
	} else
		DEBUGD(&static_dbg_srv6,
		       "%s: Ignoring interface %s up as Feature for SRv6 uN/uA SIDs is disabled",
		       __func__, ifp->name);

	return 0;
}

static int static_ifp_down(struct interface *ifp)
{
	struct static_if *sif;
	struct static_peer_ll_waiting_queue *current, *next;

	static_ifindex_update(ifp, false);

	if (static_srv6_un_ua_sids_enabled) {
		/* Clear peer LL flags when interface goes down */
		sif = ifp->info;
		if (sif) {
			UNSET_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_WAITING);
			UNSET_FLAG(sif->flags, STATIC_IF_FLAG_PEER_LL_CONFIRMED);
		}

		/* Remove SIDs from peer LL waiting queue for this interface */
		current = peer_ll_waiting_queue_head;
		while (current) {
			next = current->next;

			if (strcmp(current->sid->attributes.ifname, ifp->name) == 0) {
				DEBUGD(&static_dbg_srv6,
				       "%s: Interface %s down, removing SID %pFX from peer LL waiting queue",
				       __func__, ifp->name, &current->sid->addr);

				/* Remove from queue */
				if (current == peer_ll_waiting_queue_head) {
					peer_ll_waiting_queue_head = next;
					if (!peer_ll_waiting_queue_head)
						peer_ll_waiting_queue_tail = NULL;
				} else {
					struct static_peer_ll_waiting_queue *prev =
						peer_ll_waiting_queue_head;
					while (prev && prev->next != current)
						prev = prev->next;
					if (prev)
						prev->next = next;
					if (current == peer_ll_waiting_queue_tail)
						peer_ll_waiting_queue_tail = prev;
				}

				UNSET_FLAG(current->sid->flags,
					   STATIC_FLAG_SRV6_UA_SID_QUEUED_FOR_PEER_LL);

				XFREE(MTYPE_STATIC_PEER_LL_WAITING_QUEUE, current);
			}

			current = next;
		}
		/* Update all SIDs for this interface */
		static_ifp_srv6_sids_update(ifp, false);
	} else
		DEBUGD(&static_dbg_srv6,
		       "%s: Ignoring interface %s down as Feature for SRv6 uN/uA SIDs is disabled",
		       __func__, ifp->name);

	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p;
	enum zapi_route_notify_owner note;
	uint32_t table_id;
	safi_t safi;

	if (!zapi_route_notify_decode(zclient->ibuf, &p, &table_id, &note, NULL,
				      &safi))
		return -1;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn("%s: Route %pFX failed to install for table: %u",
			  __func__, &p, table_id);

		/* Handle SRv6 SID route install failures */
		if (p.family == AF_INET6 && srv6_sids) {
			struct static_srv6_sid *sid;
			struct listnode *node;

			/* Look up SID by comparing fields directly */
			for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
				if (sid->addr.family == AF_INET6 &&
				    sid->addr.prefixlen == p.prefixlen &&
				    memcmp(&sid->addr.prefix, &p.u.prefix6,
					   sizeof(struct in6_addr)) == 0) {
					if (CHECK_FLAG(sid->flags,
						       STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
						DEBUGD(&static_dbg_srv6,
						       "%s: SRv6 SID %pFX route install failed, clearing SENT_TO_ZEBRA flag",
						       __func__, &sid->addr);
						UNSET_FLAG(sid->flags,
							   STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
					}
					break;
				}
			}
		}

		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn(
			"%s: Route %pFX over-ridden by better route for table: %u",
			__func__, &p, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVED:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_NOT_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		static_nht_mark_state(&p, safi, vrf_id, STATIC_INSTALLED);
		zlog_warn("%s: Route %pFX failure to remove for table: %u",
			  __func__, &p, table_id);
		break;
	}

	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	struct vrf *vrf;

	zebra_route_notify_send(ZEBRA_ROUTE_NOTIFY_REQUEST, zclient, true);
	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	vrf = vrf_lookup_by_id(VRF_DEFAULT);
	assert(vrf);
	static_fixup_vrf_ids(vrf);

	/*
	 * It's possible that staticd connected after config was read
	 * in.
	 */
	static_install_nexthops_on_startup();

	static_zebra_request_srv6_sids();
}

/* API to check whether the configured nexthop address is
 * one of its local connected address or not.
 */
static bool
static_nexthop_is_local(vrf_id_t vrfid, struct prefix *addr, int family)
{
	if (family == AF_INET) {
		if (if_address_is_local(&addr->u.prefix4, AF_INET, vrfid))
			return true;
	} else if (family == AF_INET6) {
		if (if_address_is_local(&addr->u.prefix6, AF_INET6, vrfid))
			return true;
	}
	return false;
}

static void static_zebra_nexthop_update(struct vrf *vrf, struct prefix *matched,
					struct zapi_route *nhr)
{
	struct static_nht_data *nhtd, lookup;
	afi_t afi = AFI_IP;

	if (zclient->bfd_integration)
		bfd_nht_update(matched, nhr);

	if (matched->family == AF_INET6)
		afi = AFI_IP6;

	if (nhr->type == ZEBRA_ROUTE_CONNECT) {
		if (static_nexthop_is_local(vrf->vrf_id, matched,
					    nhr->prefix.family))
			nhr->nexthop_num = 0;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = *matched;
	lookup.nh_vrf_id = vrf->vrf_id;
	lookup.safi = nhr->safi;

	nhtd = static_nht_hash_find(static_nht_hash, &lookup);

	if (nhtd) {
		nhtd->nh_num = nhr->nexthop_num;

		static_nht_reset_start(matched, afi, nhr->safi, nhtd->nh_vrf_id);
		static_nht_update(NULL, matched, nhr->nexthop_num, afi,
				  nhr->safi, nhtd->nh_vrf_id);
	} else
		zlog_err("No nhtd?");
}

static void static_zebra_capabilities(struct zclient_capabilities *cap)
{
	mpls_enabled = cap->mpls_enabled;
	zebra_ecmp_count = cap->ecmp;
}

static struct static_nht_data *
static_nht_hash_getref(const struct static_nht_data *ref)
{
	struct static_nht_data *nhtd;

	nhtd = static_nht_hash_find(static_nht_hash, ref);
	if (!nhtd) {
		nhtd = XCALLOC(MTYPE_STATIC_NHT_DATA, sizeof(*nhtd));

		prefix_copy(&nhtd->nh, &ref->nh);
		nhtd->nh_vrf_id = ref->nh_vrf_id;
		nhtd->safi = ref->safi;

		static_nht_hash_add(static_nht_hash, nhtd);
	}

	nhtd->refcount++;
	return nhtd;
}

static bool static_nht_hash_decref(struct static_nht_data **nhtd_p)
{
	struct static_nht_data *nhtd = *nhtd_p;

	*nhtd_p = NULL;

	if (--nhtd->refcount > 0)
		return true;

	static_nht_hash_del(static_nht_hash, nhtd);
	XFREE(MTYPE_STATIC_NHT_DATA, nhtd);
	return false;
}

static void static_nht_hash_clear(void)
{
	struct static_nht_data *nhtd;

	while ((nhtd = static_nht_hash_pop(static_nht_hash)))
		XFREE(MTYPE_STATIC_NHT_DATA, nhtd);
}

static bool static_zebra_nht_get_prefix(const struct static_nexthop *nh,
					struct prefix *p)
{
	switch (nh->type) {
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
		p->family = AF_UNSPEC;
		return false;

	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;
		p->u.prefix4 = nh->addr.ipv4;
		return true;

	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_BITLEN;
		p->u.prefix6 = nh->addr.ipv6;
		return true;
	}

	assertf(0, "BUG: someone forgot to add nexthop type %u", nh->type);
	return false;
}

void static_zebra_nht_register(struct static_nexthop *nh, bool reg)
{
	struct static_path *pn = nh->pn;
	struct route_node *rn = pn->rn;
	struct static_route_info *si = static_route_info_from_rnode(rn);
	struct static_nht_data *nhtd, lookup = {};
	uint32_t cmd;

	if (!static_zebra_nht_get_prefix(nh, &lookup.nh))
		return;

	if (nh->nh_vrf_id == VRF_UNKNOWN)
		return;

	lookup.nh_vrf_id = nh->nh_vrf_id;
	lookup.safi = si->safi;

	if (nh->nh_registered) {
		/* nh->nh_registered means we own a reference on the nhtd */
		nhtd = static_nht_hash_find(static_nht_hash, &lookup);

		assertf(nhtd, "BUG: NH %pFX registered but not in hashtable",
			&lookup.nh);
	} else if (reg) {
		nhtd = static_nht_hash_getref(&lookup);

		if (nhtd->refcount > 1)
			DEBUGD(&static_dbg_route,
			       "Reusing registered nexthop(%pFX) for %pRN %d",
			       &lookup.nh, rn, nhtd->nh_num);
	} else {
		/* !reg && !nh->nh_registered */
		zlog_warn("trying to unregister nexthop %pFX twice",
			  &lookup.nh);
		return;
	}

	nh->nh_registered = reg;

	if (reg) {
		if (nhtd->nh_num) {
			/* refresh with existing data */
			afi_t afi = prefix_afi(&lookup.nh);

			if (nh->state == STATIC_NOT_INSTALLED ||
			    nh->state == STATIC_SENT_TO_ZEBRA)
				nh->state = STATIC_START;
			static_nht_update(&rn->p, &nhtd->nh, nhtd->nh_num, afi,
					  si->safi, nh->nh_vrf_id);
			return;
		}

		if (nhtd->registered)
			/* have no data, but did send register */
			return;

		cmd = ZEBRA_NEXTHOP_REGISTER;
		DEBUGD(&static_dbg_route, "Registering nexthop(%pFX) for %pRN",
		       &lookup.nh, rn);
	} else {
		bool was_zebra_registered;

		was_zebra_registered = nhtd->registered;
		if (static_nht_hash_decref(&nhtd))
			/* still got references alive */
			return;

		/* NB: nhtd is now NULL. */
		if (!was_zebra_registered)
			return;

		cmd = ZEBRA_NEXTHOP_UNREGISTER;
		DEBUGD(&static_dbg_route,
		       "Unregistering nexthop(%pFX) for %pRN", &lookup.nh, rn);
	}

	if (zclient_send_rnh(zclient, cmd, &lookup.nh, si->safi, false, false,
			     nh->nh_vrf_id) == ZCLIENT_SEND_FAILURE)
		zlog_warn("%s: Failure to send nexthop %pFX for %pRN to zebra",
			  __func__, &lookup.nh, rn);
	else if (reg)
		nhtd->registered = true;
}

extern void static_zebra_route_add(struct static_path *pn, bool install)
{
	struct route_node *rn = pn->rn;
	struct static_route_info *si = rn->info;
	struct static_nexthop *nh;
	const struct prefix *p, *src_pp;
	struct zapi_nexthop *api_nh;
	struct zapi_route api;
	uint32_t nh_num = 0;

	if (!si->svrf->vrf || si->svrf->vrf->vrf_id == VRF_UNKNOWN)
		return;

	p = src_pp = NULL;
	srcdest_rnode_prefixes(rn, &p, &src_pp);

	memset(&api, 0, sizeof(api));
	api.vrf_id = si->svrf->vrf->vrf_id;
	api.type = ZEBRA_ROUTE_STATIC;
	api.safi = si->safi;
	memcpy(&api.prefix, p, sizeof(api.prefix));

	if (src_pp) {
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
		memcpy(&api.src_prefix, src_pp, sizeof(api.src_prefix));
	}
	SET_FLAG(api.flags, ZEBRA_FLAG_RR_USE_DISTANCE);
	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	if (pn->distance) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = pn->distance;
	}
	if (pn->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = pn->tag;
	}
	if (pn->table_id != 0) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
		api.tableid = pn->table_id;
	}
	frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
		/* Don't overrun the nexthop array */
		if (nh_num == zebra_ecmp_count)
			break;

		api_nh = &api.nexthops[nh_num];
		if (nh->nh_vrf_id == VRF_UNKNOWN)
			continue;
		/* Skip next hop which peer is down. */
		if (nh->path_down)
			continue;

		api_nh->vrf_id = nh->nh_vrf_id;
		if (nh->onlink)
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
		if (nh->color != 0) {
			SET_FLAG(api.message, ZAPI_MESSAGE_SRTE);
			api_nh->srte_color = nh->color;
		}

		nh->state = STATIC_SENT_TO_ZEBRA;

		switch (nh->type) {
		case STATIC_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IFINDEX;
			break;
		case STATIC_IPV4_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV4;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV4_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->ifindex = nh->ifindex;
			api_nh->gate = nh->addr;
			break;
		case STATIC_BLACKHOLE:
			api_nh->type = NEXTHOP_TYPE_BLACKHOLE;
			switch (nh->bh_type) {
			case STATIC_BLACKHOLE_DROP:
			case STATIC_BLACKHOLE_NULL:
				api_nh->bh_type = BLACKHOLE_NULL;
				break;
			case STATIC_BLACKHOLE_REJECT:
				api_nh->bh_type = BLACKHOLE_REJECT;
			}
			break;
		}

		if (nh->snh_label.num_labels) {
			int i;

			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL);
			api_nh->label_num = nh->snh_label.num_labels;
			for (i = 0; i < api_nh->label_num; i++)
				api_nh->labels[i] = nh->snh_label.label[i];
		}
		if (nh->snh_seg.num_segs) {
			int i;

			api_nh->seg6local_action =
				ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6);
			SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
			api.safi = SAFI_UNICAST;

			api_nh->seg_num = nh->snh_seg.num_segs;
			for (i = 0; i < api_nh->seg_num; i++)
				memcpy(&api_nh->seg6_segs[i],
				       &nh->snh_seg.seg[i],
				       sizeof(struct in6_addr));
		}
		nh_num++;
	}

	api.nexthop_num = nh_num;

	/*
	 * If we have been given an install but nothing is valid
	 * go ahead and delete the route for double plus fun
	 */
	if (!nh_num && install)
		install = false;

	zclient_route_send(install ?
			   ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
			   zclient, &api);
}

/**
 * Send SRv6 SID to ZEBRA for installation or deletion.
 *
 * @param cmd		ZEBRA_ROUTE_ADD or ZEBRA_ROUTE_DELETE
 * @param sid		SRv6 SID to install or delete
 * @param prefixlen	Prefix length
 * @param oif		Outgoing interface
 * @param action	SID action
 * @param context	SID context
 */
static void static_zebra_send_localsid(int cmd, const struct in6_addr *sid, uint16_t prefixlen,
				       ifindex_t oif, enum seg6local_action_t action,
				       const struct seg6local_context *context)
{
	struct prefix_ipv6 p = {};
	struct zapi_route api = {};
	struct zapi_nexthop *znh;

	if (cmd != ZEBRA_ROUTE_ADD && cmd != ZEBRA_ROUTE_DELETE) {
		flog_warn(EC_LIB_DEVELOPMENT, "%s: wrong ZEBRA command", __func__);
		return;
	}

	if (prefixlen > IPV6_MAX_BITLEN) {
		flog_warn(EC_LIB_DEVELOPMENT, "%s: wrong prefixlen %u", __func__, prefixlen);
		return;
	}

	DEBUGD(&static_dbg_srv6, "%s:  |- %s SRv6 SID %pI6 behavior %s", __func__,
	       cmd == ZEBRA_ROUTE_ADD ? "Add" : "Delete", sid, seg6local_action2str(action));

	p.family = AF_INET6;
	p.prefixlen = prefixlen;
	p.prefix = *sid;

	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_STATIC;
	api.instance = 0;
	api.safi = SAFI_UNICAST;
	memcpy(&api.prefix, &p, sizeof(p));

	if (cmd == ZEBRA_ROUTE_DELETE)
		return (void)zclient_route_send(ZEBRA_ROUTE_DELETE, zclient, &api);

	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);

	znh = &api.nexthops[0];

	memset(znh, 0, sizeof(*znh));

	znh->type = NEXTHOP_TYPE_IFINDEX;
	znh->ifindex = oif;
	SET_FLAG(znh->flags, ZAPI_NEXTHOP_FLAG_SEG6LOCAL);
	znh->seg6local_action = action;
	memcpy(&znh->seg6local_ctx, context, sizeof(struct seg6local_context));

	api.nexthop_num = 1;

	zclient_route_send(ZEBRA_ROUTE_ADD, zclient, &api);
}

/**
 * Install SRv6 SID in the forwarding plane through Zebra.
 *
 * @param sid		SRv6 SID
 */
void static_zebra_srv6_sid_install(struct static_srv6_sid *sid)
{
	enum seg6local_action_t action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	struct seg6local_context ctx = {};
	struct interface *ifp = NULL;
	struct vrf *vrf;
	struct prefix_ipv6 sid_locator = {};

	if (!sid)
		return;

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		return;

	if (!STATIC_SRV6_UN_UA_FEATURE_ENABLED(sid)) {
		DEBUGD(&static_dbg_srv6,
		       "%s: Feature for SRv6 uN/uA SIDs disabled, skipping install for SID %pFX",
		       __func__, &sid->addr);
		return;
	}

	/* Check if SID is queued for peer LL confirmation */
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_UA_SID_QUEUED_FOR_PEER_LL)) {
		DEBUGD(&static_dbg_srv6,
		       "%s: SID %pFX is queued for peer LL confirmation, skipping install",
		       __func__, &sid->addr);
		return;
	}

	if (!sid->locator) {
		zlog_err("Failed to install SID %pFX: missing locator information", &sid->addr);
		return;
	}

	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_PSP);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_PSP);
		ctx.flv.lcblock_len = sid->locator->block_bits_length;
		ctx.flv.lcnode_func_len = sid->locator->node_bits_length +
					  sid->locator->function_bits_length;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		ctx.flv.lcblock_len = sid->locator->block_bits_length;
		ctx.flv.lcnode_func_len = sid->locator->node_bits_length +
					  sid->locator->function_bits_length;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		ctx.nh6 = sid->attributes.nh6;
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get interface %s",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		ctx.flv.lcblock_len = sid->locator->block_bits_length;
		ctx.flv.lcnode_func_len = sid->locator->node_bits_length +
					  sid->locator->function_bits_length;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		break;
	}

	ctx.block_len = sid->locator->block_bits_length;
	sid_locator = sid->addr;
	sid_locator.prefixlen = sid->locator->block_bits_length + sid->locator->node_bits_length;
	apply_mask(&sid_locator);

	if (prefix_same(&sid_locator, &sid->locator->prefix))
		ctx.node_len = sid->locator->node_bits_length;

	ctx.function_len = sid->addr.prefixlen - (ctx.block_len + ctx.node_len);

	/* Attach the SID to the SRv6 interface */
	if (!ifp) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to install SRv6 SID %pFX: %s interface not found",
				  &sid->addr, DEFAULT_SRV6_IFNAME);
			return;
		}
	}

	/* Send the SID to zebra */
	static_zebra_send_localsid(ZEBRA_ROUTE_ADD, &sid->addr.prefix, sid->addr.prefixlen,
				   ifp->ifindex, action, &ctx);

	SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
}

void static_zebra_srv6_sid_uninstall(struct static_srv6_sid *sid)
{
	enum seg6local_action_t action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	struct interface *ifp = NULL;
	struct seg6local_context ctx = {};
	struct vrf *vrf;
	struct prefix_ipv6 sid_block = {};
	struct prefix_ipv6 locator_block = {};
	struct prefix_ipv6 sid_locator = {};

	if (!sid)
		return;

	if (!CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		return;

	if (!sid->locator) {
		zlog_err("Failed to uninstall SID %pFX: missing locator information", &sid->addr);
		return;
	}

	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END:
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		ctx.nh6 = sid->attributes.nh6;
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get interface %s",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		return;
	}

	/* The SID is attached to the SRv6 interface */
	if (!ifp) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("%s interface not found: nothing to uninstall",
				  DEFAULT_SRV6_IFNAME);
			return;
		}
	}

	sid_block = sid->addr;
	sid_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&sid_block);

	locator_block = sid->locator->prefix;
	locator_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&locator_block);

	if (prefix_same(&sid_block, &locator_block))
		ctx.block_len = sid->locator->block_bits_length;
	else {
		zlog_warn("SID block %pFX does not match locator block %pFX", &sid_block,
			  &locator_block);
		return;
	}

	sid_locator = sid->addr;
	sid_locator.prefixlen = sid->locator->block_bits_length + sid->locator->node_bits_length;
	apply_mask(&sid_locator);

	if (prefix_same(&sid_locator, &sid->locator->prefix))
		ctx.node_len = sid->locator->node_bits_length;

	ctx.function_len = sid->addr.prefixlen - (ctx.block_len + ctx.node_len);

	static_zebra_send_localsid(ZEBRA_ROUTE_DELETE, &sid->addr.prefix, sid->addr.prefixlen,
				   ifp->ifindex, action, &ctx);

	UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
}

/* Validate if the sid block and locator block are the same */
static bool static_zebra_sid_locator_block_check(struct static_srv6_sid *sid)
{
	struct prefix_ipv6 sid_block = {};
	struct prefix_ipv6 locator_block = {};

	sid_block = sid->addr;
	sid_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&sid_block);

	locator_block = sid->locator->prefix;
	locator_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&locator_block);

	if (!prefix_same(&sid_block, &locator_block)) {
		zlog_warn("SID block %pFX does not match locator block %pFX", &sid_block,
			  &locator_block);

		return false;
	}

	return true;
}

extern void static_zebra_request_srv6_sid(struct static_srv6_sid *sid)
{
	struct srv6_sid_ctx ctx = {};
	int ret = 0;
	struct vrf *vrf;
	struct interface *ifp;

	if (!sid)
		return;

	if (!STATIC_SRV6_UN_UA_FEATURE_ENABLED(sid)) {
		DEBUGD(&static_dbg_srv6,
		       "%s: Feature for SRv6 uN/uA SIDs disabled, skipping SID %pFX", __func__,
		       &sid->addr);
		return;
	}

	if (!sid->locator) {
		static_zebra_srv6_manager_get_locator(sid->locator_name);
		return;
	}

	if (!static_zebra_sid_locator_block_check(sid))
		return;

	/* convert `srv6_endpoint_behavior_codepoint` to `seg6local_action_t` */
	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END:
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		ctx.nh6 = sid->attributes.nh6;
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to request SRv6 SID %pFX: interface %s does not exist",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		ctx.ifindex = ifp->ifindex;

		if (!static_peer_ll_confirmation_received(ifp)) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Interface %s waiting on peer LL confirmation for SID %pFX , queuing SID allocation",
			       __func__, ifp->name, &sid->addr);
			static_queue_ua_sid_allocation_after_peer_ll(sid);
			static_srv6_ua_handle_ra(sid, true);
			return;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		return;
	}

	/* Request SRv6 SID from SID Manager */
	ret = srv6_manager_get_sid(zclient, &ctx, &sid->addr.prefix, sid->locator->name, NULL);
	if (ret < 0)
		zlog_warn("%s: error getting SRv6 SID!", __func__);
}

extern void static_zebra_release_srv6_sid(struct static_srv6_sid *sid)
{
	struct srv6_sid_ctx ctx = {};
	struct vrf *vrf;
	int ret = 0;
	struct interface *ifp;

	if (!sid || !CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID))
		return;

	/* convert `srv6_endpoint_behavior_codepoint` to `seg6local_action_t` */
	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END:
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		ctx.nh6 = sid->attributes.nh6;
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to request SRv6 SID %pFX: interface %s does not exist",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		ctx.ifindex = ifp->ifindex;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		return;
	}

	/* remove the SRv6 SID from the zebra RIB */
	DEBUGD(&static_dbg_srv6,
	       "%s: Releasing SRv6 SID associated with locator %s, behavior %u, sid %pI6", __func__,
	       sid->locator_name, sid->behavior, &sid->addr.prefix);
	ret = srv6_manager_release_sid(zclient, &ctx, sid->locator_name);
	if (ret == ZCLIENT_SEND_FAILURE)
		flog_err(EC_LIB_ZAPI_SOCKET, "zclient_send_get_srv6_sid() delete failed: %s",
			 safe_strerror(errno));
}

/**
 * Ask the SRv6 Manager (zebra) about a specific locator
 *
 * @param name Locator name
 * @return 0 on success, -1 otherwise
 */
int static_zebra_srv6_manager_get_locator(const char *name)
{
	if (!name)
		return -1;

	/*
	 * Send the Get Locator request to the SRv6 Manager and return the
	 * result
	 */
	return srv6_manager_get_locator(zclient, name);
}

static void request_srv6_sids(struct static_srv6_locator *locator)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (sid->locator == locator)
			static_zebra_request_srv6_sid(sid);
	}
}

/**
 * Internal function to process an SRv6 locator
 *
 * @param locator The locator to be processed
 */
static int static_zebra_process_srv6_locator_internal(struct srv6_locator *locator)
{
	struct static_srv6_locator *loc;
	struct listnode *node;
	struct static_srv6_sid *sid;

	if (!locator)
		return -1;

	DEBUGD(&static_dbg_srv6,
	       "%s: Received SRv6 locator %s %pFX, loc-block-len=%u, loc-node-len=%u func-len=%u, arg-len=%u",
	       __func__, locator->name, &locator->prefix, locator->block_bits_length,
	       locator->node_bits_length, locator->function_bits_length,
	       locator->argument_bits_length);

	/* If we are already aware about the locator, nothing to do */
	loc = static_srv6_locator_lookup(locator->name);
	if (loc)
		return 0;

	loc = static_srv6_locator_alloc(locator->name);

	DEBUGD(&static_dbg_srv6, "%s: SRv6 locator (locator %s, prefix %pFX) set", __func__,
	       locator->name, &locator->prefix);

	/* Store the locator prefix */
	loc->prefix = locator->prefix;
	loc->block_bits_length = locator->block_bits_length;
	loc->node_bits_length = locator->node_bits_length;
	loc->function_bits_length = locator->function_bits_length;
	loc->argument_bits_length = locator->argument_bits_length;
	loc->flags = locator->flags;

	listnode_add(srv6_locators, loc);

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (strncmp(sid->locator_name, loc->name, sizeof(loc->name)) == 0)
			sid->locator = loc;
	}

	/* Request SIDs from the locator */
	request_srv6_sids(loc);
	if (!static_srv6_un_ua_sids_enabled)
		DEBUGD(&static_dbg_srv6,
		       "%s: Ignored SRv6 SIDs request for locator %s as Feature for SRv6 uN/uA SIDs is disabled",
		       __func__, loc->name);

	return 0;
}

/**
 * Callback to process an SRv6 locator received from SRv6 Manager (zebra).
 *
 * @result 0 on success, -1 otherwise
 */
static int static_zebra_process_srv6_locator_add(ZAPI_CALLBACK_ARGS)
{
	struct srv6_locator loc = {};

	if (!srv6_locators)
		return -1;

	/* Decode the SRv6 locator */
	if (zapi_srv6_locator_decode(zclient->ibuf, &loc) < 0)
		return -1;

	return static_zebra_process_srv6_locator_internal(&loc);
}

/**
 * Callback to process a notification from SRv6 Manager (zebra) of an SRv6
 * locator deleted.
 *
 * @result 0 on success, -1 otherwise
 */
static int static_zebra_process_srv6_locator_delete(ZAPI_CALLBACK_ARGS)
{
	struct srv6_locator loc = {};
	struct listnode *node2, *nnode2;
	struct static_srv6_sid *sid;
	struct static_srv6_locator *locator;

	if (!srv6_locators)
		return -1;

	/* Decode the received zebra message */
	if (zapi_srv6_locator_decode(zclient->ibuf, &loc) < 0)
		return -1;

	DEBUGD(&static_dbg_srv6,
	       "%s: SRv6 locator deleted in zebra: name %s, prefix %pFX, block_len %u, node_len %u, func_len %u, arg_len %u",
	       __func__, loc.name, &loc.prefix, loc.block_bits_length, loc.node_bits_length,
	       loc.function_bits_length, loc.argument_bits_length);

	locator = static_srv6_locator_lookup(loc.name);
	if (!locator)
		return 0;

	DEBUGD(&static_dbg_srv6, "%s: Deleting srv6 sids from locator %s", __func__, locator->name);

	/* Delete SRv6 SIDs */
	for (ALL_LIST_ELEMENTS(srv6_sids, node2, nnode2, sid)) {
		if (sid->locator != locator)
			continue;

		DEBUGD(&static_dbg_srv6, "%s: Deleting SRv6 SID (locator %s, sid %pFX)", __func__,
		       locator->name, &sid->addr);

		if (static_srv6_un_ua_sids_enabled) {
			if (static_ua_sid_is_queued_for_peer_ll(sid))
				static_remove_ua_sid_queued_for_peer_ll(sid);
			/*
			 * Uninstall the SRv6 SID from the forwarding plane
			 * through Zebra
			 */
			if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
				static_zebra_srv6_sid_uninstall(sid);
				UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
			}
		} else
			DEBUGD(&static_dbg_srv6,
			       "%s: Ignoring SRv6 SIDs deletion for locator %s as Feature for SRv6 uN/uA SIDs is disabled",
			       __func__, locator->name);

		sid->locator = NULL;
	}

	listnode_delete(srv6_locators, locator);
	static_srv6_locator_free(locator);

	return 0;
}

static int static_zebra_srv6_sid_notify(ZAPI_CALLBACK_ARGS)
{
	struct srv6_sid_ctx ctx;
	struct in6_addr sid_addr;
	enum zapi_srv6_sid_notify note;
	uint32_t sid_func;
	struct listnode *node;
	char buf[256];
	struct static_srv6_sid *sid = NULL;
	char *loc_name;
	bool found = false;

	if (!srv6_locators)
		return -1;

	/* Decode the received notification message */
	if (!zapi_srv6_sid_notify_decode(zclient->ibuf, &ctx, &sid_addr, &sid_func, NULL, &note,
					 &loc_name)) {
		zlog_err("%s : error in msg decode", __func__);
		return -1;
	}

	DEBUGD(&static_dbg_srv6,
	       "%s: received SRv6 SID notify: ctx %s sid_value %pI6 sid_func %u note %s", __func__,
	       srv6_sid_ctx2str(buf, sizeof(buf), &ctx), &sid_addr, sid_func,
	       zapi_srv6_sid_notify2str(note));

	/* Handle notification */
	switch (note) {
	case ZAPI_SRV6_SID_ALLOCATED:

		DEBUGD(&static_dbg_srv6, "%s: SRv6 SID %pI6 %s ALLOCATED", __func__, &sid_addr,
		       srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
			if (IPV6_ADDR_SAME(&sid->addr.prefix, &sid_addr)) {
				found = true;
				break;
			}
		}

		if (!found || !sid) {
			zlog_err("SRv6 SID %pI6 %s: not found", &sid_addr,
				 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));
			return 0;
		}

		if (!IPV6_ADDR_SAME(&ctx.nh6, &in6addr_any))
			sid->attributes.nh6 = ctx.nh6;

		SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);

		if (STATIC_SRV6_UN_UA_FEATURE_ENABLED(sid)) {
			/* Install new SRv6 End SID in forwarding plane through Zebra */
			static_zebra_srv6_sid_install(sid);

			SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
		} else {
			/* If uN/uA SIDs are disabled, release the SID immediately */
			DEBUGD(&static_dbg_srv6,
			       "%s: Feature for SRv6 uN/uA SIDs disabled, releasing SID %pFX",
			       __func__, &sid->addr);
			static_zebra_release_srv6_sid(sid);
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
		}

		break;
	case ZAPI_SRV6_SID_RELEASED:

		DEBUGD(&static_dbg_srv6, "%s: SRv6 SID %pI6 %s: RELEASED", __func__, &sid_addr,
		       srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
			if (IPV6_ADDR_SAME(&sid->addr.prefix, &sid_addr)) {
				found = true;
				break;
			}
		}

		if (!found || !sid) {
			zlog_err("SRv6 SID %pI6 %s: not found", &sid_addr,
				 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));
			return 0;
		}

		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);

		if (STATIC_SRV6_UN_UA_FEATURE_ENABLED(sid) &&
		    CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
			static_zebra_srv6_sid_uninstall(sid);
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
		}

		break;
	case ZAPI_SRV6_SID_FAIL_ALLOC:
		zlog_err("SRv6 SID %pI6 %s: Failed to allocate", &sid_addr,
			 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Error will be logged by zebra module */
		break;
	case ZAPI_SRV6_SID_FAIL_RELEASE:
		zlog_err("%s: SRv6 SID %pI6 %s failure to release", __func__, &sid_addr,
			 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Error will be logged by zebra module */
		break;
	}

	return 0;
}

static zclient_handler *const static_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = interface_address_delete,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = route_notify_owner,
	[ZEBRA_SRV6_LOCATOR_ADD] = static_zebra_process_srv6_locator_add,
	[ZEBRA_SRV6_LOCATOR_DELETE] = static_zebra_process_srv6_locator_delete,
	[ZEBRA_SRV6_SID_NOTIFY] = static_zebra_srv6_sid_notify,
	[ZEBRA_PEER_LL_CONFIRMATION] = static_zebra_peer_ll_confirmation,
	[ZEBRA_PEER_LL_CHANGE] = static_zebra_peer_ll_change,
};

void static_zebra_init(void)
{
	hook_register_prio(if_real, 0, static_ifp_create);
	hook_register_prio(if_up, 0, static_ifp_up);
	hook_register_prio(if_down, 0, static_ifp_down);
	hook_register_prio(if_unreal, 0, static_ifp_destroy);
	hook_register_prio(if_del, 0, static_ifp_destroy);

	zclient = zclient_new(master, &zclient_options_default, static_handlers,
			      array_size(static_handlers));

	zclient_init(zclient, ZEBRA_ROUTE_STATIC, 0, &static_privs);
	zclient->zebra_capabilities = static_zebra_capabilities;
	zclient->zebra_connected = zebra_connected;
	zclient->nexthop_update = static_zebra_nexthop_update;

	static_nht_hash_init(static_nht_hash);
	static_bfd_initialize(zclient, master);
}

/* Clean up all static interface info structures */
static void static_cleanup_interface_info(void)
{
	struct vrf *vrf;
	struct interface *ifp;

	/* Clean up interface info for all VRFs */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifp->info) {
				XFREE(MTYPE_STATIC_IF, ifp->info);
				ifp->info = NULL;
			}
		}
	}
}

/* static_zebra_stop used by tests/lib/test_grpc.cpp */
void static_zebra_stop(void)
{
	static_nht_hash_clear();
	static_nht_hash_fini(static_nht_hash);

	/* Clean up all static interface info structures */
	static_cleanup_interface_info();

	if (!zclient)
		return;
	zclient_stop(zclient);
	zclient_free(zclient);
	zclient = NULL;
}

void static_zebra_vrf_register(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_reg_requests(zclient, vrf->vrf_id);
}

void static_zebra_vrf_unregister(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_dereg_requests(zclient, vrf->vrf_id);
}

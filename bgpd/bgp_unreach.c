// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information SAFI
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 */

#include <zebra.h>

#include "prefix.h"
#include "log.h"
#include "stream.h"
#include "memory.h"
#include "command.h"
#include "json.h"
#include "frrevent.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_unreach.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_updgrp.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_UNREACH_INFO, "BGP Unreachability Information");

/* Helper function to convert reason code to string */
const char *bgp_unreach_reason_str(uint16_t code)
{
	static const char *reason_names[] = {
		"Unspecified",	      /* 0 */
		"Policy-Blocked",     /* 1 */
		"Security-Filtered",  /* 2 */
		"RPKI-Invalid",	      /* 3 */
		"No-Export-Policy",   /* 4 */
		"Martian-Address",    /* 5 */
		"Bogon-Prefix",	      /* 6 */
		"Route-Dampening",    /* 7 */
		"Local-Admin-Action", /* 8 */
		"Local-Link-Down"     /* 9 */
	};

	if (code <= 9)
		return reason_names[code];
	else if (code >= 64536)
		return "Private-Use";
	else
		return "Reserved";
}

/* Parse TLVs from unreachability NLRI
 *
 * This function parses a single Reporter TLV from the NLRI data.
 * Per the draft, multiple Reporter TLVs MAY be present in a single NLRI,
 * but current implementation processes only the first one.
 *
 * Parameters:
 *   data - Pointer to TLV data (may contain multiple Reporter TLVs)
 *   len  - Total length of TLV data
 *   unreach - Output structure to store parsed Reporter TLV fields
 *
 * Returns:
 *   0 on success (first Reporter TLV parsed)
 *   -1 on parse error
 *
 * Note: Only the first Reporter TLV is extracted. Additional Reporter TLVs
 *       in the data are not processed by this function. The caller is
 *       responsible for detecting and logging presence of additional TLVs.
 */
int bgp_unreach_tlv_parse(uint8_t *data, uint16_t len, struct bgp_unreach_nlri *unreach)
{
	uint8_t *pnt = data;
	uint8_t *end = data + len;

	/* Initialize */
	memset(&unreach->reporter, 0, sizeof(unreach->reporter));
	unreach->reporter_as = 0;
	unreach->reason_code = 0;
	unreach->timestamp = 0;
	unreach->has_reason_code = false;
	unreach->has_timestamp = false;
	unreach->has_reporter = false;
	unreach->has_reporter_as = false;

	/* Validate minimum length for Reporter TLV */
	if (len < BGP_UNREACH_REPORTER_TLV_MIN_LEN) {
		zlog_err("Unreachability NLRI too short: %u bytes (min %u)", len,
			 BGP_UNREACH_REPORTER_TLV_MIN_LEN);
		return -1;
	}

	/* Parse Reporter TLV (Type 1 - mandatory container) */
	if (pnt + BGP_UNREACH_TLV_HEADER_LEN > end) {
		zlog_err("Truncated Reporter TLV header");
		return -1;
	}

	uint8_t tlv_type = *pnt++;
	uint16_t tlv_len = ((uint16_t)*pnt++ << 8);
	tlv_len |= *pnt++;

	/* Validate Reporter TLV Type */
	if (tlv_type != BGP_UNREACH_TLV_TYPE_REPORTER) {
		zlog_err("Invalid TLV type: expected %u (Reporter), got %u",
			 BGP_UNREACH_TLV_TYPE_REPORTER, tlv_type);
		return -1;
	}

	/* Validate Reporter TLV length */
	if (tlv_len < BGP_UNREACH_REPORTER_FIXED_LEN) {
		zlog_err("Reporter TLV too short: %u bytes (min %u)", tlv_len,
			 BGP_UNREACH_REPORTER_FIXED_LEN);
		return -1;
	}

	if (pnt + tlv_len > end) {
		zlog_err("Reporter TLV length overflow: %u bytes", tlv_len);
		return -1;
	}

	uint8_t *reporter_end = pnt + tlv_len;

	/* Extract Reporter Identifier (4 bytes) - mandatory */
	if (pnt + BGP_UNREACH_REPORTER_ID_LEN > reporter_end) {
		zlog_err("Truncated Reporter Identifier");
		return -1;
	}
	memcpy(&unreach->reporter, pnt, BGP_UNREACH_REPORTER_ID_LEN);
	unreach->has_reporter = true;
	pnt += BGP_UNREACH_REPORTER_ID_LEN;

	/* Extract Reporter AS Number (4 bytes) - mandatory */
	if (pnt + BGP_UNREACH_REPORTER_AS_LEN > reporter_end) {
		zlog_err("Truncated Reporter AS Number");
		return -1;
	}
	unreach->reporter_as = ((uint32_t)*pnt++ << 24);
	unreach->reporter_as |= ((uint32_t)*pnt++ << 16);
	unreach->reporter_as |= ((uint32_t)*pnt++ << 8);
	unreach->reporter_as |= *pnt++;
	unreach->has_reporter_as = true;

	/* Parse Sub-TLVs */
	while (pnt < reporter_end) {
		if (pnt + BGP_UNREACH_SUBTLV_HEADER_LEN > reporter_end) {
			zlog_err("Truncated Sub-TLV header");
			return -1;
		}

		uint8_t sub_type = *pnt++;
		uint16_t sub_len = ((uint16_t)*pnt++ << 8);
		sub_len |= *pnt++;

		if (pnt + sub_len > reporter_end) {
			zlog_err("Sub-TLV length overflow: type=%u len=%u", sub_type, sub_len);
			return -1;
		}

		switch (sub_type) {
		case BGP_UNREACH_SUBTLV_TYPE_REASON_CODE:
			if (sub_len != BGP_UNREACH_REASON_CODE_LEN) {
				zlog_err("Invalid Reason Code Sub-TLV length: %u (expected %u)",
					 sub_len, BGP_UNREACH_REASON_CODE_LEN);
				return -1;
			}
			unreach->reason_code = ((uint16_t)*pnt << 8);
			unreach->reason_code |= *(pnt + 1);
			unreach->has_reason_code = true;
			break;

		case BGP_UNREACH_SUBTLV_TYPE_TIMESTAMP:
			if (sub_len != BGP_UNREACH_TIMESTAMP_LEN) {
				zlog_err("Invalid Timestamp Sub-TLV length: %u (expected %u)",
					 sub_len, BGP_UNREACH_TIMESTAMP_LEN);
				return -1;
			}
			unreach->timestamp = ((uint64_t)*pnt << 56);
			unreach->timestamp |= ((uint64_t) * (pnt + 1) << 48);
			unreach->timestamp |= ((uint64_t) * (pnt + 2) << 40);
			unreach->timestamp |= ((uint64_t) * (pnt + 3) << 32);
			unreach->timestamp |= ((uint64_t) * (pnt + 4) << 24);
			unreach->timestamp |= ((uint64_t) * (pnt + 5) << 16);
			unreach->timestamp |= ((uint64_t) * (pnt + 6) << 8);
			unreach->timestamp |= *(pnt + 7);
			unreach->has_timestamp = true;
			break;

		default:
			/* Unknown Sub-TLVs silently ignored per extensibility */
			zlog_debug("Unknown Unreachability Sub-TLV type: %u", sub_type);
			break;
		}

		pnt += sub_len;
	}

	return 0;
}

/* Encode TLVs into stream (per draft order) */
int bgp_unreach_tlv_encode(struct stream *s, struct bgp_unreach_nlri *unreach)
{
	/* Calculate Reporter TLV total length:
	 * - Reporter ID (4 bytes) + Reporter AS (4 bytes) = 8 bytes fixed
	 * - Sub-TLV Type 1 (Reason): 3 + 2 = 5 bytes (if present)
	 * - Sub-TLV Type 2 (Timestamp): 3 + 8 = 11 bytes (if present)
	 */
	uint16_t reporter_tlv_len = BGP_UNREACH_REPORTER_FIXED_LEN;

	if (unreach->has_reason_code)
		reporter_tlv_len += BGP_UNREACH_SUBTLV_HEADER_LEN + BGP_UNREACH_REASON_CODE_LEN;

	if (unreach->has_timestamp)
		reporter_tlv_len += BGP_UNREACH_SUBTLV_HEADER_LEN + BGP_UNREACH_TIMESTAMP_LEN;

	/* Encode Reporter TLV header */
	stream_putc(s, BGP_UNREACH_TLV_TYPE_REPORTER);
	stream_putw(s, reporter_tlv_len);

	/* Reporter Identifier (4 bytes) - mandatory */
	stream_put(s, &unreach->reporter, BGP_UNREACH_REPORTER_ID_LEN);

	/* Reporter AS Number (4 bytes) - mandatory */
	stream_putl(s, unreach->reporter_as);

	/* Sub-TLV Type 1: Reason Code (optional) */
	if (unreach->has_reason_code) {
		stream_putc(s, BGP_UNREACH_SUBTLV_TYPE_REASON_CODE);
		stream_putw(s, BGP_UNREACH_REASON_CODE_LEN);
		stream_putw(s, unreach->reason_code);
	}

	/* Sub-TLV Type 2: Timestamp (optional) */
	if (unreach->has_timestamp) {
		uint64_t ts = htobe64(unreach->timestamp);
		stream_putc(s, BGP_UNREACH_SUBTLV_TYPE_TIMESTAMP);
		stream_putw(s, BGP_UNREACH_TIMESTAMP_LEN);
		stream_put(s, &ts, BGP_UNREACH_TIMESTAMP_LEN);
	}

	return 0;
}

/* Parse unreachability NLRI */
int bgp_nlri_parse_unreach(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			   bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	struct prefix p;
	int psize = 0;
	uint8_t prefixlen;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	struct bgp_unreach_nlri unreach;

	/* Start processing the NLRI */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	for (; pnt < lim; pnt += psize) {
		/* Clear structures */
		memset(&p, 0, sizeof(p));
		memset(&unreach, 0, sizeof(unreach));

		/* Get AddPath ID if applicable */
		if (addpath_capable) {
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length */
		if (pnt >= lim) {
			zlog_err("%s: Premature end of unreachability NLRI", peer->host);
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		prefixlen = *pnt++;
		p.family = afi2family(afi);
		p.prefixlen = prefixlen;

		/* Prefix length check */
		if (prefixlen > prefix_blen(&p) * 8) {
			zlog_err("%s: Invalid prefix length %d for AFI %u", peer->host, prefixlen,
				 afi);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
		}

		/* Calculate size of prefix in bytes */
		psize = PSIZE(prefixlen);

		/* Check packet size */
		if (pnt + psize > lim) {
			zlog_err("%s: Prefix length %d overflows packet", peer->host, prefixlen);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* Copy prefix */
		if (psize > 0)
			memcpy(&p.u.prefix, pnt, psize);
		pnt += psize;

		/* Parse TLVs - per draft, multiple Reporter TLVs MAY be present.
	 * Current implementation processes only the first Reporter TLV.
	 * Additional Reporter TLVs are silently ignored (forward compatibility).
	 */
		if (pnt < lim) {
			uint16_t total_tlv_data = lim - pnt;

			/* Read first Reporter TLV header to determine its length */
			if (total_tlv_data < BGP_UNREACH_TLV_HEADER_LEN) {
				zlog_err("%s: Insufficient TLV data for %pFX", peer->host, &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Peek at TLV Length field (offset +1, 2 bytes, network byte order) */
			uint16_t first_tlv_len = ((uint16_t)pnt[1] << 8) | pnt[2];
			uint16_t first_tlv_total = BGP_UNREACH_TLV_HEADER_LEN + first_tlv_len;

			if (bgp_unreach_tlv_parse(pnt, total_tlv_data, &unreach) < 0) {
				zlog_err("%s: Failed to parse unreachability TLVs for %pFX",
					 peer->host, &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Check if additional Reporter TLVs are present (ignored per current implementation).
		 * Log at INFO level for visibility without alarming operators.
		 */
			if (total_tlv_data > first_tlv_total) {
				if (BGP_DEBUG(update, UPDATE_IN))
					zlog_info("%s: Multiple Reporter TLVs received for %pFX (only first processed, %u of %u bytes used)",
						  peer->host, &p, first_tlv_total, total_tlv_data);
			}

			pnt = lim; /* Advance past all TLV data */
			psize = 0;
		}

		/* Store prefix in unreach structure */
		prefix_copy(&unreach.prefix, &p);

		/* Store TLV data in attr for bgp_update() to access.
		 * This follows the same pattern as EVPN (see bgp_route.c:5418-5421).
		 */
		if (attr && !withdraw) {
			/* Allocate and attach TLV data to attributes */
			struct bgp_unreach_nlri *unreach_copy =
				XCALLOC(MTYPE_TMP, sizeof(struct bgp_unreach_nlri));
			*unreach_copy = unreach;
			attr->unreach_nlri = unreach_copy;
		}

		/* Process via standard bgp_update()/bgp_withdraw() - this gives us:
		 * - Standard BGP loop prevention (ORIGINATOR_ID, CLUSTER_LIST, AS-path)
		 * - Import/export policies
		 * - Proper route selection
		 * - Per-peer path info entries
		 */
		if (withdraw) {
			bgp_withdraw(peer, &p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0, NULL);
		} else {
			bgp_update(peer, &p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);
		}

		/* Free temporary TLV data */
		if (attr && attr->unreach_nlri) {
			XFREE(MTYPE_TMP, attr->unreach_nlri);
			attr->unreach_nlri = NULL;
		}

		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("%s: Processed unreachability info for %pFX via bgp_update()",
				   peer->host, &p);
	}

	return 0;
}

/* Create new unreachability info */
struct bgp_unreach_info *bgp_unreach_info_new(struct prefix *prefix)
{
	struct bgp_unreach_info *info;

	info = XCALLOC(MTYPE_BGP_UNREACH_INFO, sizeof(struct bgp_unreach_info));
	prefix_copy(&info->prefix, prefix);
	info->received_time = monotime(NULL);

	return info;
}

/* Free unreachability info */
void bgp_unreach_info_free(struct bgp_unreach_info *info)
{
	XFREE(MTYPE_BGP_UNREACH_INFO, info);
}

/* Add unreachability information to RIB */
int bgp_unreach_info_add(struct bgp *bgp, afi_t afi, struct bgp_unreach_nlri *nlri,
			 struct attr *attr)
{
	struct bgp_dest *dest;
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;
	struct attr attr_new;
	struct attr *attr_interned;

	if (!bgp || !nlri)
		return -1;

	/* Get/create destination node */
	dest = bgp_node_get(bgp->rib[afi][SAFI_UNREACH], &nlri->prefix);

	/* Check for existing path */
	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next) {
		if (bpi->peer == bgp->peer_self)
			break;
	}

	/* Safety check: Don't overwrite locally-originated routes with received routes.
	 * This should not happen if ORIGINATOR_ID loop prevention works correctly,
	 * but acts as a defense-in-depth measure.
	 * - attr == NULL: locally-originated (from VTY inject), can create/update
	 * - attr != NULL && bpi exists: received route trying to overwrite local, reject
	 */
	if (bpi && attr) {
		if (BGP_DEBUG(update, UPDATE_IN))
			zlog_debug("%s: UNREACH INFO ADD %pFX: ignoring - locally-originated route already exists",
				   __func__, &nlri->prefix);
		bgp_dest_unlock_node(dest);
		return 0;
	}

	/* Create new path or update existing */
	if (!bpi) {
		/* Initialize attributes (no TLV data in attr) */
		if (attr) {
			attr_new = *attr;
		} else {
			/* Set default attributes for locally originated route */
			bgp_attr_default_set(&attr_new, bgp, BGP_ORIGIN_IGP);
		}

		/* Set nexthop length to 0 for SAFI_UNREACH (no nexthop, like Flowspec) */
		attr_new.mp_nexthop_len = 0;

		/* Intern the attributes */
		attr_interned = bgp_attr_intern(&attr_new);

		new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, bgp->peer_self, attr_interned,
				dest);

		if (!new->extra)
			new->extra = bgp_path_info_extra_get(new);

		new->extra->unreach = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_UNREACH,
					      sizeof(struct bgp_path_info_extra_unreach));

		new->extra->unreach->timestamp = nlri->timestamp;
		new->extra->unreach->has_timestamp = nlri->has_timestamp;
		new->extra->unreach->reason_code = nlri->reason_code;
		new->extra->unreach->has_reason_code = nlri->has_reason_code;
		new->extra->unreach->reporter = nlri->reporter;
		new->extra->unreach->has_reporter = nlri->has_reporter;
		new->extra->unreach->reporter_as = nlri->reporter_as;
		new->extra->unreach->has_reporter_as = nlri->has_reporter_as;

		bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);
		bgp_path_info_add(dest, new);
		bgp_process(bgp, dest, new, afi, SAFI_UNREACH);
	} else {
		/* Update existing path with new TLV data */
		if (!bpi->extra)
			bpi->extra = bgp_path_info_extra_get(bpi);

		if (!bpi->extra->unreach)
			bpi->extra->unreach = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_UNREACH,
						      sizeof(struct bgp_path_info_extra_unreach));

		if (bgp_debug_update(NULL, &nlri->prefix, NULL, 0)) {
			zlog_debug("UNREACH UPDATE %pFX: old reason=%u new reason=%u", &nlri->prefix,
				   bpi->extra->unreach->reason_code, nlri->reason_code);
		}

		bpi->extra->unreach->timestamp = nlri->timestamp;
		bpi->extra->unreach->has_timestamp = nlri->has_timestamp;
		bpi->extra->unreach->reason_code = nlri->reason_code;
		bpi->extra->unreach->has_reason_code = nlri->has_reason_code;
		bpi->extra->unreach->reporter = nlri->reporter;
		bpi->extra->unreach->has_reporter = nlri->has_reporter;
		bpi->extra->unreach->reporter_as = nlri->reporter_as;
		bpi->extra->unreach->has_reporter_as = nlri->has_reporter_as;

		bpi->uptime = monotime(NULL);
		bgp_path_info_set_flag(dest, bpi, BGP_PATH_ATTR_CHANGED);
		bgp_process(bgp, dest, bpi, afi, SAFI_UNREACH);
	}

	bgp_dest_unlock_node(dest);

	return 0;
}

/* Delete unreachability information */
void bgp_unreach_info_delete(struct bgp *bgp, afi_t afi, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_path_info *bpi;

	if (!bgp || !prefix)
		return;

	dest = bgp_node_lookup(bgp->rib[afi][SAFI_UNREACH], prefix);
	if (!dest)
		return;

	for (bpi = bgp_dest_get_bgp_path_info(dest); bpi; bpi = bpi->next) {
		if (bpi->peer == bgp->peer_self) {
			bgp_rib_remove(dest, bpi, bgp->peer_self, afi, SAFI_UNREACH);
			break;
		}
	}

	bgp_dest_unlock_node(dest);
}

/* Encode unreachability NLRI for transmission */
void bgp_unreach_nlri_encode(struct stream *s, struct bgp_unreach_nlri *unreach,
			     bool addpath_capable, uint32_t addpath_id)
{
	/* AddPath ID if needed */
	if (addpath_capable)
		stream_putl(s, addpath_id);

	/* Prefix length */
	stream_putc(s, unreach->prefix.prefixlen);

	/* Prefix */
	int psize = PSIZE(unreach->prefix.prefixlen);
	if (psize > 0)
		stream_put(s, &unreach->prefix.u.prefix, psize);

	/* TLVs */
	bgp_unreach_tlv_encode(s, unreach);
}

/* Show unreachability information */

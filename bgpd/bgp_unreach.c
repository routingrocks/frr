// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Unreachability Information SAFI
 * Copyright (C) 2025 Nvidia Corporation
 *                    Karthikeya Venkat Muppalla
 *
 * Wire format per draft-tantsura-idr-unreachability-safi:
 *
 * NLRI Format (Section 3.2-3.3):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Prefix Length |           Prefix (variable)                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Reporter TLV (variable)                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Reporter TLV Format (Section 3.4):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type=1    |            Length             |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
 * |              Reporter Identifier (4 octets)                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Reporter AS Number (4 octets)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Sub-TLVs (variable)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Sub-TLV Format (Section 3.5):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Sub-Type    |         Sub-Length            |               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
 * |                   Sub-Value (variable)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Implementation notes:
 * - Multiple NLRIs can be packed in single UPDATE message
 * - Current implementation: 1 Reporter TLV per NLRI (no aggregation)
 * - Unknown Sub-TLV types are silently ignored (forward compatibility)
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
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_conditional_disagg.h"

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
	else if (code >= 64512 && code <= 65534)
		return "Private-Use";
	else
		return "Reserved";
}

/* Helper function to convert reason string to code
 * Returns 0 on success, -1 if the string is not recognized
 */
int bgp_unreach_reason_str2code(const char *str, uint16_t *code)
{
	if (strmatch(str, "unspecified"))
		*code = BGP_UNREACH_REASON_UNSPECIFIED;
	else if (strmatch(str, "policy-blocked"))
		*code = BGP_UNREACH_REASON_POLICY_BLOCKED;
	else if (strmatch(str, "security-filtered"))
		*code = BGP_UNREACH_REASON_SECURITY_FILTERED;
	else if (strmatch(str, "rpki-invalid"))
		*code = BGP_UNREACH_REASON_RPKI_INVALID;
	else if (strmatch(str, "no-export-policy"))
		*code = BGP_UNREACH_REASON_NO_EXPORT_POLICY;
	else if (strmatch(str, "martian-address"))
		*code = BGP_UNREACH_REASON_MARTIAN_ADDRESS;
	else if (strmatch(str, "bogon-prefix"))
		*code = BGP_UNREACH_REASON_BOGON_PREFIX;
	else if (strmatch(str, "route-dampening"))
		*code = BGP_UNREACH_REASON_ROUTE_DAMPENING;
	else if (strmatch(str, "local-admin-action"))
		*code = BGP_UNREACH_REASON_LOCAL_ADMIN_ACTION;
	else if (strmatch(str, "local-link-down"))
		*code = BGP_UNREACH_REASON_LOCAL_LINK_DOWN;
	else
		return -1;

	return 0;
}

/* Parse Reporter TLV from unreachability NLRI
 *
 * Extracts Reporter ID, Reporter AS, and Sub-TLVs (Reason Code, Timestamp).
 * Wire format documented at top of file.
 *
 * Parameters:
 *   data - Pointer to start of ONE Reporter TLV (Type + Length + payload)
 *   len  - Length of THIS Reporter TLV only (caller pre-calculated)
 *   unreach - Output structure to store parsed fields
 *
 * Returns:
 *   0 on success
 *   -1 on parse error
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

		/* Reject zero-length Sub-TLVs (invalid, no data) */
		if (sub_len == 0) {
			zlog_err("Zero-length Sub-TLV type %u", sub_type);
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

/* Encode Reporter TLV into stream
 *
 * Encodes Reporter ID, Reporter AS, and Sub-TLVs (Reason Code, Timestamp).
 * Wire format documented at top of file.
 */
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

/* Parse unreachability NLRI
 *
 * Parses one or more UNREACH NLRIs from UPDATE message.
 * Wire format documented at top of file.
 */
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
	/* coverity[mixed_enum_type:SUPPRESS] */
	afi = packet->afi;
	/* coverity[mixed_enum_type:SUPPRESS] */
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	while (pnt < lim) {
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

		/* Copy prefix and advance pointer */
		if (psize > 0)
			memcpy(&p.u.prefix, pnt, psize);
		pnt += psize;

		/* Parse TLVs for this NLRI.
		 * Each NLRI has: [prefix][Reporter TLV(s)]
		 * Withdrawals do NOT include TLVs - only parse for updates.
		 */
		if (!withdraw && pnt < lim) {
			uint16_t remaining_in_packet = lim - pnt;

			/* Read Reporter TLV header to determine its length */
			if (remaining_in_packet < BGP_UNREACH_TLV_HEADER_LEN) {
				zlog_err("%s: Insufficient Reporter TLV data for %pFX", peer->host,
					 &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Read Reporter TLV Length field (2 bytes, network byte order) */
			uint16_t reporter_tlv_len = ((uint16_t)pnt[BGP_UNREACH_TLV_LEN_OFFSET]
						     << 8) |
						    pnt[BGP_UNREACH_TLV_LEN_OFFSET + 1];

			/* Validate Reporter TLV length is within valid range */
			if (reporter_tlv_len < BGP_UNREACH_REPORTER_FIXED_LEN) {
				zlog_err("%s: Reporter TLV length %u too short (min %u) for %pFX",
					 peer->host, reporter_tlv_len,
					 BGP_UNREACH_REPORTER_FIXED_LEN, &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			uint16_t reporter_tlv_total = BGP_UNREACH_TLV_HEADER_LEN + reporter_tlv_len;

			/* Validate Reporter TLV doesn't overflow remaining packet */
			if (reporter_tlv_total > remaining_in_packet) {
				zlog_err("%s: Reporter TLV length %u exceeds remaining packet %u for %pFX",
					 peer->host, reporter_tlv_total, remaining_in_packet, &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Parse Reporter TLV (extracts Reporter ID, AS, Sub-TLVs) */
			if (bgp_unreach_tlv_parse(pnt, reporter_tlv_total, &unreach) < 0) {
				zlog_err("%s: Failed to parse Reporter TLV for %pFX", peer->host,
					 &p);
				return BGP_NLRI_PARSE_ERROR;
			}

			/* Advance pointer past THIS NLRI's Reporter TLV to next NLRI.
		 *
		 * Implementation note: We expect 1 Reporter TLV per NLRI. If sender
		 * includes multiple Reporter TLVs without capability negotiation,
		 * they will be misinterpreted as next NLRI, causing parse error and
		 * UPDATE rejection. This enforces proper capability negotiation.
		 */
			pnt += reporter_tlv_total;
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
		} else if (attr) {
			bgp_update(peer, &p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);
		} else {
			/* attr is required for non-withdraw updates - skip this NLRI */
			if (BGP_DEBUG(update, UPDATE_IN))
				zlog_debug("%s: Missing attributes for unreachability update %pFX, skipping",
					   peer->host, &p);
			continue;
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
void bgp_unreach_info_delete(struct bgp *bgp, afi_t afi, const struct prefix *prefix)
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
			/* Conditional Disaggregation: Withdraw generated SAFI_UNICAST route if needed */
			if (CHECK_FLAG(bgp->per_src_nhg_flags[afi][SAFI_UNICAST],
				       BGP_FLAG_CONDITIONAL_DISAGG))
				bgp_conditional_disagg_withdraw(bgp, prefix, bpi, afi,
								bgp->peer_self);

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
void bgp_unreach_show(struct vty *vty, struct bgp *bgp, afi_t afi, struct prefix *prefix,
		      bool use_json, bool detail)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	json_object *json = NULL;
	json_object *json_paths = NULL;
	int count = 0;

	if (!bgp) {
		if (use_json)
			vty_out(vty, "{}\n");
		return;
	}

	table = bgp->rib[afi][SAFI_UNREACH];
	if (!table) {
		if (use_json)
			vty_out(vty, "{}\n");
		else
			vty_out(vty, "No unreachability information\n");
		return;
	}

	if (use_json)
		json = json_object_new_object();

	/* Show specific prefix or all */
	if (prefix) {
		dest = bgp_node_lookup(table, prefix);
		if (!dest) {
			if (use_json) {
				vty_json(vty, json);
			} else {
				vty_out(vty, "%% Network not in table\n");
			}
			return;
		}

		if (use_json)
			json_paths = json_object_new_array();
		else {
			/* Print header once before looping through paths */
			route_vty_out_detail_header(vty, bgp, dest, prefix, NULL, afi, SAFI_UNREACH,
						    NULL, false);
		}

		int multi_path_count = 0;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			count++;
			if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
				multi_path_count++;

			if (use_json) {
				json_object *json_path = json_object_new_object();

				/* Add all path details like table view */
				struct bgp_path_info_extra_unreach *unreach_data =
					(pi->extra) ? pi->extra->unreach : NULL;

				/* TLV Type 1: Original Reporter */
				if (unreach_data && unreach_data->has_reporter) {
					char reporter[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &unreach_data->reporter, reporter,
						  sizeof(reporter));
					json_object_string_add(json_path, "reporter", reporter);
				}
				if (unreach_data && unreach_data->has_reporter_as) {
					json_object_int_add(json_path, "reporterAs",
							    unreach_data->reporter_as);
				}

				/* TLV Type 2: Reason Code */
				if (unreach_data && unreach_data->has_reason_code) {
					const char *reason_str =
						bgp_unreach_reason_str(unreach_data->reason_code);
					json_object_string_add(json_path, "reason", reason_str);
				}

				if (unreach_data && unreach_data->has_timestamp) {
					time_t ts = (time_t)unreach_data->timestamp;
					char timebuf[64];
					json_object *json_ts = json_object_new_object();
					json_object_int_add(json_ts, "epoch", ts);
					json_object_string_add(json_ts, "string",
							       ctime_r(&ts, timebuf));
					json_object_object_add(json_path, "timestamp", json_ts);
				}

				if (pi->peer) {
					json_object_string_addf(json_path, "peer", "%pSU",
								&pi->peer->connection->su);
					if (pi->peer->hostname)
						json_object_string_add(json_path, "peerHostname",
								       pi->peer->hostname);
				}

				/* Add origin */
				if (pi->attr) {
					const char *origin_str = "?";
					if (pi->attr->origin == BGP_ORIGIN_IGP)
						origin_str = "i";
					else if (pi->attr->origin == BGP_ORIGIN_EGP)
						origin_str = "e";
					json_object_string_add(json_path, "origin", origin_str);
				}

				/* Add flags */
				json_object_boolean_add(json_path, "valid",
							CHECK_FLAG(pi->flags, BGP_PATH_VALID));
				json_object_boolean_add(json_path, "best",
							CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
				json_object_boolean_add(json_path, "stale",
							CHECK_FLAG(pi->flags, BGP_PATH_STALE));
				json_object_boolean_add(json_path, "multipath",
							CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH));

				/* Add pathFrom */
				if (pi->peer && pi->peer->sort == BGP_PEER_IBGP)
					json_object_string_add(json_path, "pathFrom", "internal");
				else if (pi->peer && pi->peer->sort == BGP_PEER_EBGP)
					json_object_string_add(json_path, "pathFrom", "external");

				/* Add lastUpdate */
				{
					time_t tbuf = time(NULL) - (monotime(NULL) - pi->uptime);
					char timebuf[64];
					json_object *json_last_update = json_object_new_object();
					json_object_int_add(json_last_update, "epoch", tbuf);
					json_object_string_add(json_last_update, "string",
							       ctime_r(&tbuf, timebuf));
					json_object_object_add(json_path, "lastUpdate",
							       json_last_update);
				}

				/* Add extendedCommunity if present */
				if (pi->attr && bgp_attr_get_ecommunity(pi->attr)) {
					json_object *json_ecomm = json_object_new_object();
					json_object_string_add(json_ecomm, "string",
							       bgp_attr_get_ecommunity(pi->attr)->str);
					json_object_object_add(json_path, "extendedCommunity",
							       json_ecomm);
				}

				/* Add AS path if present */
				if (pi->attr && pi->attr->aspath) {
					json_object *json_aspath = json_object_new_object();
					json_object_string_add(json_aspath, "string",
							       aspath_print(pi->attr->aspath));
					json_object_int_add(json_aspath, "length",
							    aspath_count_hops(pi->attr->aspath));
					json_object_object_add(json_path, "aspath", json_aspath);
				}

				json_object_array_add(json_paths, json_path);
			} else {
				/* Use standard BGP route detail display for single prefix */
				route_vty_out_detail(vty, bgp, dest, prefix, pi, afi, SAFI_UNREACH,
						     RPKI_NOT_BEING_USED, NULL);
			}
		}

		if (use_json) {
			json_object_object_add(json, "paths", json_paths);
			json_object_int_add(json, "pathCount", count);
			json_object_int_add(json, "multiPathCount", multi_path_count);

			/* Add advertisedTo for single route view */
			json_object *json_adv_to = NULL;
			struct peer *peer;
			struct listnode *node, *nnode;
			/* coverity[non_const_printf_format_string:SUPPRESS] */
			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
				if (bgp_adj_out_lookup(peer, dest, 0)) {
					if (!json_adv_to)
						json_adv_to = json_object_new_object();
					json_object *json_peer = json_object_new_object();
					if (peer->hostname)
						json_object_string_add(json_peer, "hostname",
								       peer->hostname);
					if (peer->conf_if)
						json_object_object_add(json_adv_to, peer->conf_if,
								       json_peer);
					else {
						char peer_str[SU_ADDRSTRLEN];
						sockunion2str(&peer->connection->su, peer_str,
							      sizeof(peer_str));
						json_object_object_add(json_adv_to, peer_str,
								       json_peer);
					}
				}
			}
			if (json_adv_to)
				json_object_object_add(json, "advertisedTo", json_adv_to);

			vty_json(vty, json);
		}

		bgp_dest_unlock_node(dest);
	} else {
		/* Show all unreachability information */

		/* If detail flag, use detailed output per route */
		if (detail) {
			int prefix_count = 0;

			if (use_json)
				json = json_object_new_object();

			for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
				const struct prefix *p = bgp_dest_get_prefix(dest);
				bool has_paths = false;

				if (use_json) {
					/* Build detailed JSON output (like single prefix view) */
					json_object *json_paths = json_object_new_array();
					char prefix_str[PREFIX2STR_BUFFER];
					prefix2str(p, prefix_str, sizeof(prefix_str));

					for (pi = bgp_dest_get_bgp_path_info(dest); pi;
					     pi = pi->next) {
						json_object *json_path = json_object_new_object();
						struct bgp_path_info_extra_unreach *unreach_data =
							(pi->extra) ? pi->extra->unreach : NULL;

						/* Add all detailed fields */
						if (unreach_data && unreach_data->has_reporter) {
							char reporter[INET_ADDRSTRLEN];
							inet_ntop(AF_INET, &unreach_data->reporter,
								  reporter, sizeof(reporter));
							json_object_string_add(json_path,
									       "reporter", reporter);
						}
						if (unreach_data && unreach_data->has_reporter_as)
							json_object_int_add(json_path, "reporterAs",
									    unreach_data->reporter_as);

						if (unreach_data && unreach_data->has_reason_code) {
							const char *reason_str =
								bgp_unreach_reason_str(
									unreach_data->reason_code);
							json_object_string_add(json_path, "reason",
									       reason_str);
						}

						if (unreach_data && unreach_data->has_timestamp) {
							time_t ts = (time_t)unreach_data->timestamp;
							char timebuf[64];
							json_object *json_ts =
								json_object_new_object();
							json_object_int_add(json_ts, "epoch", ts);
							json_object_string_add(json_ts, "string",
									       ctime_r(&ts,
										       timebuf));
							json_object_object_add(json_path,
									       "timestamp", json_ts);
						}

						if (pi->peer) {
							json_object_string_addf(json_path, "peer",
										"%pSU",
										&pi->peer->connection
											 ->su);
							if (pi->peer->hostname)
								json_object_string_add(json_path,
										       "peerHostname",
										       pi->peer->hostname);
						}

						if (pi->attr) {
							const char *origin_str = "?";
							if (pi->attr->origin == BGP_ORIGIN_IGP)
								origin_str = "i";
							else if (pi->attr->origin == BGP_ORIGIN_EGP)
								origin_str = "e";
							json_object_string_add(json_path, "origin",
									       origin_str);
						}

						json_object_boolean_add(json_path, "valid",
									CHECK_FLAG(pi->flags,
										   BGP_PATH_VALID));
						json_object_boolean_add(json_path, "best",
									CHECK_FLAG(pi->flags,
										   BGP_PATH_SELECTED));
						json_object_boolean_add(json_path, "stale",
									CHECK_FLAG(pi->flags,
										   BGP_PATH_STALE));
						json_object_boolean_add(json_path, "multipath",
									CHECK_FLAG(pi->flags,
										   BGP_PATH_MULTIPATH));

						if (pi->peer && pi->peer->sort == BGP_PEER_IBGP)
							json_object_string_add(json_path, "pathFrom",
									       "internal");
						else if (pi->peer && pi->peer->sort == BGP_PEER_EBGP)
							json_object_string_add(json_path, "pathFrom",
									       "external");

						{
							time_t tbuf = time(NULL) -
								      (monotime(NULL) - pi->uptime);
							char timebuf[64];
							json_object *json_last_update =
								json_object_new_object();
							json_object_int_add(json_last_update,
									    "epoch", tbuf);
							json_object_string_add(json_last_update,
									       "string",
									       ctime_r(&tbuf,
										       timebuf));
							json_object_object_add(json_path,
									       "lastUpdate",
									       json_last_update);
						}

						if (pi->attr && bgp_attr_get_ecommunity(pi->attr)) {
							json_object *json_ecomm =
								json_object_new_object();
							json_object_string_add(json_ecomm, "string",
									       bgp_attr_get_ecommunity(
										       pi->attr)
										       ->str);
							json_object_object_add(json_path,
									       "extendedCommunity",
									       json_ecomm);
						}

						if (pi->attr && pi->attr->aspath) {
							if (!pi->attr->aspath->json)
								aspath_str_update(pi->attr->aspath,
										  true);
							json_object_lock(pi->attr->aspath->json);
							json_object_object_add(json_path, "aspath",
									       pi->attr->aspath->json);
						}

						json_object_array_add(json_paths, json_path);
						count++;
						has_paths = true;
					}

					json_object_object_add(json, prefix_str, json_paths);
				} else {
					/* VTY detail output */
					for (pi = bgp_dest_get_bgp_path_info(dest); pi;
					     pi = pi->next) {
						route_vty_out_detail_header(vty, bgp, dest, p, NULL,
									    afi, SAFI_UNREACH, NULL,
									    false);
						route_vty_out_detail(vty, bgp, dest, p, pi, afi,
								     SAFI_UNREACH,
								     RPKI_NOT_BEING_USED, NULL);
						count++;
						has_paths = true;
					}
				}

				if (has_paths)
					prefix_count++;
			}

			if (use_json) {
				vty_json(vty, json);
			} else {
				vty_out(vty,
					"\nDisplayed %d routes and %d total paths\n",
					prefix_count, count);
			}
			return;
		}

		/* Summary view */
		if (!use_json) {
			/* Print table header with status code legends (same as ipv4 unicast) */
			vty_out(vty,
				"BGP table version is %" PRIu64
				", local router ID is %pI4, vrf id %u\n",
				table->version, &bgp->router_id, bgp->vrf_id);
			vty_out(vty, "Default local pref %u, local AS %u\n",
				bgp->default_local_pref, bgp->as);
			/* coverity[non_const_printf_format_string] - format strings are compile-time constants */
			vty_out(vty, BGP_UNREACH_SHOW_SCODE_HEADER);
			vty_out(vty, BGP_SHOW_OCODE_HEADER);
			vty_out(vty, BGP_SHOW_RPKI_HEADER);

			/* SAFI_UNREACH specific information */
			vty_out(vty,
				"Note: Unreachability routes are informational only and not installed in RIB/FIB\n");
			vty_out(vty, "Reason: Unreachability reason code\n");
			vty_out(vty, "Reporter: BGP router ID of the original reporter\n\n");

			/* Column header - use macros to match standard BGP style */
			/* coverity[non_const_printf_format_string] - format strings are compile-time constants */
			if (afi == AFI_IP)
				vty_out(vty, BGP_UNREACH_SHOW_HEADER);
			else
				vty_out(vty, BGP_UNREACH_SHOW_HEADER_WIDE);
		}

		int prefix_count = 0; /* Count unique prefixes */
		for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
			const struct prefix *p = bgp_dest_get_prefix(dest);
			char buf[PREFIX2STR_BUFFER];
			bool first_path = true;
			int prefix_path_count = 0;
			int multi_path_count = 0;
			json_object *json_route_for_prefix = NULL;
			bool has_paths = false;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
				struct bgp_path_info_extra_unreach *unreach_data = NULL;

				if (pi->extra && pi->extra->unreach)
					unreach_data = pi->extra->unreach;

				count++; /* Count total paths/entries */
				prefix_path_count++;
				has_paths = true;

				/* Count multipath routes */
				if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
					multi_path_count++;

				if (use_json) {
					/* Add JSON output for unreachability routes */
					json_object *json_route = NULL;
					json_object *json_paths = NULL;
					json_object *json_path = NULL;
					char prefix_str[PREFIX2STR_BUFFER];

					/* Get or create route object for this prefix */
					prefix2str(p, prefix_str, sizeof(prefix_str));
					json_route = json_object_object_get(json, prefix_str);
					if (!json_route) {
						json_route = json_object_new_object();
						json_object_string_add(json_route, "prefix",
								       prefix_str);
						json_paths = json_object_new_array();
						json_object_object_add(json_route, "paths",
								       json_paths);
						json_object_object_add(json, prefix_str, json_route);
					} else {
						json_paths = json_object_object_get(json_route,
										    "paths");
					}

					/* Create path object - matching VTY summary columns and unicast JSON */
					json_path = json_object_new_object();

					/* Add metric */
					if (pi->attr)
						json_object_int_add(json_path, "metric",
								    pi->attr->med);

					/* Add local pref (if present) */
					if (pi->attr &&
					    (pi->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)))
						json_object_int_add(json_path, "locPrf",
								    pi->attr->local_pref);

					/* Add weight */
					if (pi->attr)
						json_object_int_add(json_path, "weight",
								    pi->attr->weight);

					/* Add reason (only what's shown in VTY) */
					if (unreach_data && unreach_data->has_reason_code) {
						const char *reason_str = bgp_unreach_reason_str(
							unreach_data->reason_code);
						json_object_string_add(json_path, "reason",
								       reason_str);
					}

					if (unreach_data) {
						char reporter_ip[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &unreach_data->reporter,
							  reporter_ip, sizeof(reporter_ip));
						json_object_string_add(json_path, "reporter",
								       reporter_ip);
						json_object_int_add(json_path, "reporterAs",
								    unreach_data->reporter_as);
					}

					/* Add path as string (AS path + origin, matching VTY display) */
					if (pi->attr && pi->attr->aspath) {
						char path_str[256];
						const char *aspath_str =
							aspath_print(pi->attr->aspath);
						const char *origin_str = "?";
						if (pi->attr->origin == BGP_ORIGIN_IGP)
							origin_str = "i";
						else if (pi->attr->origin == BGP_ORIGIN_EGP)
							origin_str = "e";

						snprintf(path_str, sizeof(path_str), "%s %s",
							 aspath_str ? aspath_str : "", origin_str);
						json_object_string_add(json_path, "path", path_str);
					}

					/* Add origin */
					if (pi->attr) {
						const char *origin_str = "?";
						if (pi->attr->origin == BGP_ORIGIN_IGP)
							origin_str = "i";
						else if (pi->attr->origin == BGP_ORIGIN_EGP)
							origin_str = "e";
						json_object_string_add(json_path, "origin",
								       origin_str);
					}

					/* Add status flags */
					json_object_boolean_add(json_path, "valid",
								CHECK_FLAG(pi->flags,
									   BGP_PATH_VALID));
					json_object_boolean_add(json_path, "best",
								CHECK_FLAG(pi->flags,
									   BGP_PATH_SELECTED));
					json_object_boolean_add(json_path, "stale",
								CHECK_FLAG(pi->flags,
									   BGP_PATH_STALE));
					json_object_boolean_add(json_path, "multipath",
								CHECK_FLAG(pi->flags,
									   BGP_PATH_MULTIPATH));

					/* Add pathFrom */
					if (pi->peer && pi->peer->sort == BGP_PEER_IBGP)
						json_object_string_add(json_path, "pathFrom",
								       "internal");
					else if (pi->peer && pi->peer->sort == BGP_PEER_EBGP)
						json_object_string_add(json_path, "pathFrom",
								       "external");

					/* Add lastUpdate */
					{
						time_t tbuf = time(NULL) -
							      (monotime(NULL) - pi->uptime);
						char timebuf[64];
						json_object *json_last_update =
							json_object_new_object();
						json_object_int_add(json_last_update, "epoch", tbuf);
						json_object_string_add(json_last_update, "string",
								       ctime_r(&tbuf, timebuf));
						json_object_object_add(json_path, "lastUpdate",
								       json_last_update);
					}

					/* Add extendedCommunity if present */
					if (pi->attr && bgp_attr_get_ecommunity(pi->attr)) {
						json_object *json_ecomm = json_object_new_object();
						json_object_string_add(json_ecomm, "string",
								       bgp_attr_get_ecommunity(
									       pi->attr)
									       ->str);
						json_object_object_add(json_path,
								       "extendedCommunity",
								       json_ecomm);
					}

					/* Add "from" object */
					if (pi->peer) {
						json_object *json_from = json_object_new_object();
						if (pi->peer->hostname)
							json_object_string_add(json_from, "hostname",
									       pi->peer->hostname);
						if (pi->peer->conf_if)
							json_object_string_add(json_from,
									       "interface",
									       pi->peer->conf_if);
						else
							json_object_string_addf(json_from, "peerId",
										"%pSU",
										&pi->peer->connection
											 ->su);
						json_object_string_addf(json_from, "routerId",
									"%pI4",
									&pi->peer->remote_id);
						json_object_object_add(json_path, "from", json_from);
					}

					json_object_array_add(json_paths, json_path);

					/* Save reference for adding counts after loop */
					json_route_for_prefix = json_route;
				} else {
					char reporter_str[32] = "-";
					char aspath_str[256] = "";
					const char *reason_str = "";
					char origin_str[2] = "";

					if (unreach_data) {
						char reporter_ip[INET_ADDRSTRLEN];
						inet_ntop(AF_INET, &unreach_data->reporter,
							  reporter_ip, sizeof(reporter_ip));
						snprintf(reporter_str, sizeof(reporter_str), "%s/%u",
							 reporter_ip, unreach_data->reporter_as);

						if (unreach_data->has_reason_code) {
							reason_str = bgp_unreach_reason_str(
								unreach_data->reason_code);
						}
					}

					/* Get AS path if available */
					if (pi->attr && pi->attr->aspath) {
						const char *aspath_tmp =
							aspath_print(pi->attr->aspath);
						if (aspath_tmp) {
							snprintf(aspath_str, sizeof(aspath_str),
								 "%s", aspath_tmp);
						}
					}

					/* Get origin code */
					if (pi->attr) {
						if (pi->attr->origin == BGP_ORIGIN_IGP)
							snprintf(origin_str, sizeof(origin_str),
								 "i");
						else if (pi->attr->origin == BGP_ORIGIN_EGP)
							snprintf(origin_str, sizeof(origin_str),
								 "e");
						else if (pi->attr->origin == BGP_ORIGIN_INCOMPLETE)
							snprintf(origin_str, sizeof(origin_str),
								 "?");
					}

					/* Generate status codes (similar to route_vty_short_status_out) */
					/* RPKI validation state - skip for now (needs hook) */
					vty_out(vty, " ");

					/* Route status display */
					if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
						vty_out(vty, "R");
					else if (CHECK_FLAG(pi->flags, BGP_PATH_STALE))
						vty_out(vty, "S");
					else if (bgp_path_suppressed(pi))
						vty_out(vty, "s");
					else if (CHECK_FLAG(pi->flags, BGP_PATH_VALID) &&
						 !CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
						vty_out(vty, "*");
					else
						vty_out(vty, " ");

					/* Selected/Best path */
					if (CHECK_FLAG(pi->flags, BGP_PATH_HISTORY))
						vty_out(vty, "h");
					else if (CHECK_FLAG(pi->flags, BGP_PATH_UNSORTED))
						vty_out(vty, "u");
					else if (CHECK_FLAG(pi->flags, BGP_PATH_DAMPED))
						vty_out(vty, "d");
					else if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
						vty_out(vty, ">");
					else if (CHECK_FLAG(pi->flags, BGP_PATH_MULTIPATH))
						vty_out(vty, "=");
					else
						vty_out(vty, " ");

					/* Internal route */
					if (pi->peer && (pi->peer->as) &&
					    (pi->peer->as == pi->peer->local_as))
						vty_out(vty, "i");
					else
						vty_out(vty, " ");

					/* Print route line with columns:
					 * Network, Metric, LocPrf, Weight, Reason, Reporter, Path
					 * Use different widths for IPv4 vs IPv6 (Network column only)
					 * Only show prefix for first path, blanks for subsequent paths */
					const char *prefix_display =
						first_path ? prefix2str(p, buf, sizeof(buf)) : "";

					if (afi == AFI_IP) {
						/* IPv4 format */
						if (pi->attr &&
						    (pi->attr->flag &
						     ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
							vty_out(vty,
								" %-18s %7u %7u %7u %-19s %-17s %s %s\n",
								prefix_display, pi->attr->med,
								pi->attr->local_pref,
								pi->attr->weight, reason_str,
								reporter_str, aspath_str,
								origin_str);
						} else {
							vty_out(vty,
								" %-18s %7u        %7u %-19s %-17s %s %s\n",
								prefix_display,
								pi->attr ? pi->attr->med : 0,
								pi->attr ? pi->attr->weight : 0,
								reason_str, reporter_str,
								aspath_str, origin_str);
						}
					} else {
						/* IPv6 format - wider Network column */
						if (pi->attr &&
						    (pi->attr->flag &
						     ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
							vty_out(vty,
								" %-48s %7u %7u %7u %-19s %-17s %s %s\n",
								prefix_display, pi->attr->med,
								pi->attr->local_pref,
								pi->attr->weight, reason_str,
								reporter_str, aspath_str,
								origin_str);
						} else {
							vty_out(vty,
								" %-48s %7u        %7u %-19s %-17s %s %s\n",
								prefix_display,
								pi->attr ? pi->attr->med : 0,
								pi->attr ? pi->attr->weight : 0,
								reason_str, reporter_str,
								aspath_str, origin_str);
						}
					}

					/* Mark that we've printed the first path */
					first_path = false;
				}
			}

			/* Add route-level fields */
			if (use_json && json_route_for_prefix) {
				json_object_int_add(json_route_for_prefix, "pathCount",
						    prefix_path_count);
				json_object_int_add(json_route_for_prefix, "multiPathCount",
						    multi_path_count);

				/* Add flags object */
				json_object *json_flags = json_object_new_object();
				struct bgp_path_info *pi_check;
				bool has_bestpath = false;
				for (pi_check = bgp_dest_get_bgp_path_info(dest); pi_check;
				     pi_check = pi_check->next) {
					if (CHECK_FLAG(pi_check->flags, BGP_PATH_SELECTED)) {
						has_bestpath = true;
						break;
					}
				}
				json_object_string_add(json_flags, "bestPathExists",
						       has_bestpath ? "true" : "false");
				json_object_object_add(json_route_for_prefix, "flags", json_flags);

				/* Add advertisedTo */
				json_object *json_adv_to = NULL;
				struct peer *peer;
				struct listnode *node, *nnode;
				/* coverity[non_const_printf_format_string:SUPPRESS] */
				for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
					if (bgp_adj_out_lookup(peer, dest, 0)) {
						if (!json_adv_to)
							json_adv_to = json_object_new_object();
						json_object *json_peer = json_object_new_object();
						if (peer->hostname)
							json_object_string_add(json_peer, "hostname",
									       peer->hostname);
						if (peer->conf_if)
							json_object_object_add(json_adv_to,
									       peer->conf_if,
									       json_peer);
						else {
							char peer_str[SU_ADDRSTRLEN];
							sockunion2str(&peer->connection->su,
								      peer_str, sizeof(peer_str));
							json_object_object_add(json_adv_to,
									       peer_str, json_peer);
						}
					}
				}
				if (json_adv_to)
					json_object_object_add(json_route_for_prefix,
							       "advertisedTo", json_adv_to);
			}

			if (has_paths)
				prefix_count++;
		}

		if (use_json) {
			/* Add numPrefixes (consistent with unicast) */
			json_object_int_add(json, "numPrefixes", prefix_count);
			vty_json(vty, json);
		} else {
			if (count == 0)
				vty_out(vty, "No unreachability information\n");
			else
				vty_out(vty,
					"\nDisplayed %d routes and %d total paths\n",
					prefix_count, count);
		}
	}
}

/* Check if prefix matches the configured UNREACH advertisement filter.
 * Returns true if the prefix should be advertised as UNREACH NLRI.
 */
bool bgp_prefix_matches_unreach_filter(struct bgp *bgp, afi_t afi, const struct prefix *p)
{
	if (!bgp || !p)
		return false;

	/* No filter configured - don't advertise */
	if (!bgp->unreach_adv_prefix[afi])
		return false;

	/* Check if prefix matches the configured filter */
	return prefix_match(bgp->unreach_adv_prefix[afi], p);
}

void bgp_unreach_zebra_announce(struct bgp *bgp, struct interface *ifp,
				struct prefix *prefix, bool withdraw)
{
	struct bgp_unreach_nlri unreach;
	afi_t afi;

	if (!bgp || !ifp || !prefix)
		return;

	if (prefix->family == AF_INET) {
		afi = AFI_IP;
	} else if (prefix->family == AF_INET6) {
		afi = AFI_IP6;
		/* Skip link-local addresses - not routable */
		if (IN6_IS_ADDR_LINKLOCAL(&prefix->u.prefix6)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("Skip link-local %pFX on %s", prefix, ifp->name);
			return;
		}
	} else {
		return;
	}

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Processing %s %pFX on %s (withdraw=%d)",
			   afi == AFI_IP ? "IPv4" : "IPv6", prefix, ifp->name, withdraw);

	if (withdraw) {
		bgp_unreach_info_delete(bgp, afi, prefix);

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("Withdraw unreachability for %pFX on %s", prefix, ifp->name);
	} else {
		/* Check if prefix matches the configured advertisement filter.
		 * Only create UNREACH in local RIB if it matches.
		 */
		if (!bgp_prefix_matches_unreach_filter(bgp, afi, prefix)) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug("Skip UNREACH for %pFX on %s - does not match advertisement filter",
					   prefix, ifp->name);
			return;
		}

		memset(&unreach, 0, sizeof(unreach));
		prefix_copy(&unreach.prefix, prefix);

		unreach.reporter = bgp->router_id;
		unreach.has_reporter = true;
		unreach.reporter_as = bgp->as;
		unreach.has_reporter_as = true;

		unreach.reason_code = BGP_UNREACH_REASON_LOCAL_LINK_DOWN;
		unreach.has_reason_code = true;

		unreach.timestamp = time(NULL);
		unreach.has_timestamp = true;

		if (bgp_unreach_info_add(bgp, afi, &unreach, NULL) < 0) {
			zlog_warn("Failed to inject unreachability for %pFX on %s",
				  prefix, ifp->name);
			return;
		}

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug("Injected unreachability for %pFX on %s",
				   prefix, ifp->name);
	}
}

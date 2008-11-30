/*
 * ieee80215_lib.h
 *
 * Copyright (C) 2007, 2008 Siemens AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Written by:
 * Pavel Smolenskiy <pavel.smolenskiy@gmail.com>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 */

#ifndef IEEE80215_LIB_H
#define IEEE80215_LIB_H

#ifdef __KERNEL__

#include <linux/skbuff.h>	/**< For the sk_buff structure and helpers */
#include <linux/crc-itu-t.h>

#include <net/ieee80215/const.h>

/**************************************************************************
 * PHY data unit:
 *        ,----------------------------------------------------------------.
 * Octets |     4    |  1  |               1                    | variable |
 *        |----------|-----|------------------------------------|----------|
 * Desc.  | preamble | SFD | Frame length(7 bit), 1bit reserved |   PSDU   |
 *        `----------------------------------------------------------------'
 **************************************************************************/
#define DEF_SFD		0xa7
#define DEF_FLEN_MPDU	0x5
struct ieee80215_PPDU {
	u8	preamble[4];
	u8	sfd;
	u8	flen;
} __attribute__ ((packed));
typedef struct ieee80215_PPDU ieee80215_PPDU_t;

/**< Maximum overhead to whole frame added by PPDU */
#define IEEE80215_MAX_PHY_OVERHEAD	0x6

/**
 * \brief MAC Generic addresses field structure
 *
 * A MAC generic addressess field common structure.
 * If _16bit address specified, then _64bit address is ommited.
 * If _64bit address specified, then _16bit address is ommited.
 * If address mode is NO_ADDR, then all strucure is 0 size len.
 */
union ieee80215_addr {
	u16	_16bit;		/**< Short address */
	u64	_64bit;		/**< Extended address */
};
typedef union ieee80215_addr ieee80215_addr_t;

/**
 * \brief device address structure
 *
 * Structure describe the IEEE 802.15.4 address pair.
 * Used to specify mac address or coordinator address.
 * if _16bit is 0xfffe, then address is in _64bit.
 */
struct ieee80215_dev_address {
	u16	panid;		/**< Current PanID */
	u16	_16bit;		/**< Device 16bit short address, 0xfffe if no */
	u64	_64bit;		/**< Extended 64bit device address */
};
typedef struct ieee80215_dev_address ieee80215_dev_addr_t;

/**
 * \brief GTS characteristics type field
 *
 * Used in frames to send out to/receive from the media
 */
struct ieee80215_gts_char {
	u8	len:4,		/**< GTS length */
		dir:1,		/**< GTS direction */
		type:1,		/**< characteristics type */
		rsv:2;		/**< reserved */
} __attribute__ ((packed));
typedef struct ieee80215_gts_char ieee80215_gts_char_t;

/**
 * \brief MAC frame control field structure
 *
 * Frame control field structure
 */
struct ieee80215_fc {
	u16	type:3,		/**< MAC frame type, see IEEE80215_TYPE_* */
		security:1,	/**< Security enabled */
		pend:1,		/**< Pending frame */
		ack_req:1,	/**< Ack request */
		intra_pan:1,	/**< Intra Pan*/
		r1:2,		/**< Reserved */
		dst_amode:2,	/**< Destination addressing mode */
		r2:2,		/**< Reserved */
		src_amode:2;	/**< Source addressing mode */
} __attribute__ ((packed));
typedef struct ieee80215_fc ieee80215_fc_t;

#define IEEE80215_TYPE_BEACON	0x0	/**< Frame is beacon */
#define	IEEE80215_TYPE_DATA	0x1	/**< Frame is data */
#define IEEE80215_TYPE_ACK	0x2	/**< Frame is acknowledgment */
#define IEEE80215_TYPE_MAC_CMD	0x3	/**< Frame is MAC command */
#define IEEE80215_TYPE_RSV_4	0x4	/**< Reserved */
#define IEEE80215_TYPE_RSV_7	0x7	/**< Reserved */

/**< Possible addressing mode values */
#define IEEE80215_AMODE_NOPAN	0x0	/**< PAN identifier and address field are not present. */
#define IEEE80215_AMODE_RSV	0x1	/**< Reserved */
#define IEEE80215_AMODE_16BIT	0x2	/**< Address field contains a 16 bit short address. */
#define IEEE80215_AMODE_64BIT	0x3	/**< Address field contains a 64 bit extended address.*/

/**< TxOptions */
#define IEEE80215_ACK		0x1	/**< Acknowledged transmission */
#define IEEE80215_GTS		0x2	/** GTS transmission */
#define IEEE80215_INDIRECT	0x4	/** Indirect transmission */
#define IEEE80215_SEC_ENABLE	0x8	/** Security enabled transmission */

/**
 * \brief MAC beacon superframe specification field strucutre
 *
 * Super frame specification field
 */
struct ieee80215_sff {
	u16	b_order:4,	/**< Beacon order */
		s_order:4,	/**< Superframe order */
		fcap_slot:4,	/**< Final CAP Slot */
		bat_life_ext:1,	/**< Battery life extension */
		r1:1,		/**< Reserved */
		pan_coord:1,	/**< PAN coordinator */
		a_permit:1;	/**< Association permit */
} __attribute__ ((packed));
typedef struct ieee80215_sff ieee80215_sff_t;

/**
 * \brief GTS specification field strucutre
 *
 * GTS specification field
 */
struct ieee80215_gts_spec {
	u8	desc_count:3,	/**< GTS descriptor count */
		r1:4,		/**< Reserved */
		permit:1;	/**< GTS permit */
} __attribute__ ((packed));
typedef struct ieee80215_gts_spec ieee80215_gts_spec_t;

/**
 * \brief GTS Direction field strucutre
 *
 * GTS direction field
 */
struct ieee80215_gts_dir {
	u8	mask:7,		/**< GTS Direction mask */
		r:1;		/**< Reserved */
} __attribute__ ((packed));
typedef struct ieee80215_gts_dir ieee80215_gts_dir_t;

/**
 * \brief GTS list field strucutre
 *
 * GTS list field
 */
struct ieee80215_gts_list {
	u16	_16bit;		/**< Device short address */
	u8	starting_slot:4,/**< GTS starting slot */
		len:4;		/**< GTS length */
} __attribute__ ((packed));
typedef struct ieee80215_gts_list ieee80215_gts_list_t;

/**
 * \brief GTS Information field structure
 *
 * GTS information fields
 */
struct ieee80215_gts_frame {
	ieee80215_gts_spec_t	spec;	/**< GTS specification */
	ieee80215_gts_dir_t	dir;	/**< GTS directions */
} __attribute__ ((packed));
typedef struct ieee80215_gts_frame ieee80215_gts_frame_t;

/**
 * \brief Pending address specification field structure
 *
 * Pending address specification field
 */
struct ieee80215_paddr_spec {
	u8	_16bit_pend:3,		/**< Number of short address pending */
		r1:1,			/**< Reserved */
		_64bit_pend:3,		/**< Number of extended address pending */
		r2:1;			/**< Reserved */
} __attribute__ ((packed));
typedef struct ieee80215_paddr_spec ieee80215_paddr_spec_t;

/**
 * \brief Pending address list fields structure
 *
 * Pending address list fields
 */
struct ieee80215_paddr {
	ieee80215_paddr_spec_t	addr_spec;	/**< Specification field */
} __attribute__ ((packed));
typedef struct ieee80215_paddr ieee80215_paddr_t;

/**
 * @brief MAC's MHR header
 *
 * MHR - Mac header. Contain frame control field, sequence number and addressing
 * field(if required)
 */
struct ieee80215_mhr {
	ieee80215_fc_t	fc;	/**< Frame control field */
	u8		seq;	/**< sequence number */
};
typedef struct ieee80215_mhr ieee80215_mhr_t;

/**
 * @brief MAC's MFR
 *
 * MFR - Mac footer. Contain FCS.
 */
struct ieee80215_mfr {
	u16	fcs;	/**< Frame check summ */
};
typedef struct ieee80215_mfr ieee80215_mfr_t;

/**
 * \brief Beacon frame payload structure
 *
 * Beacon frame payload format
 */
struct ieee80215_beacon_payload {
	ieee80215_sff_t sff;	/**< superframe specification */
#if 0
	ieee80215_gts_frame_t	*gts;	/**< GTS fields */
	ieee80215_paddr_t	*paddr;	/**< pending address fields */
#endif
};
typedef struct ieee80215_beacon_payload ieee80215_beacon_payload_t;

/******************************************************************************/
/* MAC's Command Frame Formats, added into General MAC frame as payload */
/******************************************************************************/

/**
 * \brief Capability information field structure
 */
struct ieee80215_cmd_cap {
	u8	alt_pan:1,		/**< Alternate PAN coordinator */
		dev_type:1,		/**< Device type */
		power_src:1,		/**< Power source */
		rxon:1,			/**< Receiver on when idle */
		rsv:2,			/**< Reserved */
		cap_sec:1,		/**< Security capability */
		addr_alloc:1;		/**< Allocate address */
} __attribute__ ((packed));
typedef struct ieee80215_cmd_cap ieee80215_cmd_cap_t;

/**
 * \brief Association request command format
 */
struct ieee80215_cmd_associate_req {
	u8			cmd_id;	/**< Command frame identifier */
	ieee80215_cmd_cap_t	cap;	/**< Capability information */
} __attribute__ ((packed));
typedef struct ieee80215_cmd_associate_req ieee80215_cmd_associate_req_t;

/**
 * \brief Association response command format
 */
struct ieee80215_cmd_associate_resp {
	u8	cmd_id;		/**< Command frame identifier */
	u16	_16bit;		/**< Short address */
	u8	status;		/**< Association status */
} __attribute__ ((packed));
typedef struct ieee80215_cmd_associate_resp ieee80215_cmd_associate_resp_t;

/**
 * \brief Disassociation notification command format
 */
struct ieee80215_cmd_disassociate_notify {
	u8	cmd_id;	/**< Command frame identifier */
	u8	reason;	/**< Disassociation reason */
} __attribute__ ((packed));
typedef struct ieee80215_cmd_disassociate_notify ieee80215_cmd_disassociate_notify_t;

/**
 * \brief Generic request/notification command format
 *
 * Used for:
 * \li Data request
 * \li PAN ID notification
 * \li Orphan notification
 * \li Beacon request
 */
struct ieee80215_cmd_generic_req {
	u8	cmd_id;	/**< Command frame identifier */
} __attribute__ ((packed));
typedef struct ieee80215_cmd_generic_req ieee80215_cmd_generic_req_t;

/**
 * \brief Coordinator realignment command
 */
struct ieee80215_cmd_realign {
	u8	cmd_id;		/**< Command frame identifier */
	u16	pan_id;		/**< PAN identifier */
	u16	c_16bit;	/**< Coordinator short address */
	u8	lch;		/**< logical channel */
	u16	_16bit;	/**< short address */
} __attribute__ ((packed));
typedef struct ieee80215_cmd_realign ieee80215_cmd_realign_t;

/**
 * \brief GTS request command
 */
struct ieee80215_cmd_gts_req {
	u8			cmd_id;	/**< Command frame identifier */
	ieee80215_gts_char_t	c;	/**< GTS characteristics */
} __attribute__ ((packed));
typedef struct ieee80215_cmd_gts_req ieee80215_cmd_gts_req_t;

/* MAC's Command Frames Identifiers */
#define IEEE80215_ASSOCIATION_REQ		0x01
#define IEEE80215_ASSOCIATION_PERM		0x02
#define IEEE80215_DISASSOCIATION_NOTIFY		0x03
#define IEEE80215_DATA_REQ			0x04
#define IEEE80215_PANID_CONFLICT_NOTIFY		0x05
#define IEEE80215_ORPHAN_NOTIFY			0x06
#define IEEE80215_BEACON_REQ			0x07
#define IEEE80215_COORD_REALIGN_NOTIFY		0x08
#define IEEE80215_GTS_REQ			0x09
#define IEEE80215_GTS_ALLOC			0x0a
#define IEEE80215_DATA				0x0b
#define IEEE80215_RESERVED_ff			0xff

struct zb_nwk_fc {
	u16	type:2,
		ver:4,
		route_disc:2,
		r1:1,
		sec:1,
		r2:6;
} __attribute__ ((packed));
typedef struct zb_nwk_fc zb_nwk_fc_t;

#define ZB_PACK_FC(__h,t,rd,s) do {__h->type=t;__h->ver=ZB_NWK_VER;__h->route_disc=rd;__h->sec=s;}while(0);

struct zb_npdu_head {
	zb_nwk_fc_t fc;
	u16	dst;
	u16	src;
	u8	radius;
	u8	seq;
	u8	payload[0];
} __attribute__ ((packed));
typedef struct zb_npdu_head zb_npdu_head_t;

#define ZB_PACK_HEAD(__h,d,s,r,sq) do {__h->dst=d;__h->src=s;__h->radius=r;__h->seq=sq;}while(0);

#define ZB_NWK_FRAME_OVERHEAD (sizeof(zb_npdu_head_t))

/**
 * @brief MPDU frame format
 *
 * MAC MPDU format.
 */
struct ieee80215_mpdu {
	struct sk_buff *skb;

	unsigned long	timestamp;
	u8		lq;		/* link quality */
	u8		type;		/* buf type */
	u8		retries:4,
			filtered:1,
			ack_send:1,
			gts:1;
	u8		nwk_handle;
	u8		aps_handle;
	bool		use_csma_ca;

	ieee80215_mhr_t		*mhr;		/**< FC and seq */
	u16			*d_panid;	/**< Destination PanID */
	ieee80215_addr_t	*da;		/**< DST addressing fields */
	u16			*s_panid;	/**< Source PanID, eq to d_panid if intrapan */
	ieee80215_addr_t	*sa;		/**< SRC addressing fields */

	union {
		ieee80215_cmd_generic_req_t *g;
		ieee80215_cmd_associate_req_t *areq;
		ieee80215_cmd_associate_resp_t *aresp;
		ieee80215_cmd_disassociate_notify_t *dn;
		ieee80215_cmd_realign_t *r;
		ieee80215_cmd_gts_req_t *gts;
		ieee80215_beacon_payload_t *b;
		/* ZB NWK layer payload */
		zb_npdu_head_t *h;
		u8 *msdu;
	} p;	/**< Payload */

#if 0
	these must be in the userspace

	struct {
		zb_apdu_head_t	*ah;	/**< APDU head */
		zb_apdu_t	a;	/**< APDU */
	} ph;
#endif
	ieee80215_mfr_t	*mfr;		/**< MFR */

	int (*on_confirm)(void *obj, struct sk_buff *skb, int code);

};
typedef struct ieee80215_mpdu ieee80215_mpdu_t;

static inline void __print_mpdu(ieee80215_mpdu_t *mpdu)
{
	printk(KERN_INFO "mpdu = 0x%p, len = %u, real_len = %u, head = 0x%p, data = 0x%p, end = 0x%p, tail = 0x%p\n",
	       mpdu, mpdu->skb->len, mpdu->skb->data_len, mpdu->skb->head, mpdu->skb->data, mpdu->skb->end, mpdu->skb->tail);
}

typedef struct sk_buff_head ieee80215_mpdu_head_t;

#define mpdu_to_skb(mpdu) (mpdu->skb)
static inline ieee80215_mpdu_t* skb_to_mpdu(struct sk_buff *skb)
{
	caddr_t *ptr;
	ptr = (caddr_t*)&skb->cb[0];
	return (ieee80215_mpdu_t*)*ptr;
}

static __inline__ u16 ieee80215_crc_itu(u8 *data, u8 len)
{
	u16 crc;
	u32 reg;

	reg = 0;
	crc = crc_itu_t(0, data, len-2);
	crc = crc_itu_t(crc, (u8*)&reg, 2);
	return crc;
}

void __kfree_mpdu(ieee80215_mpdu_t *mpdu);
static inline void kfree_mpdu(ieee80215_mpdu_t *mpdu)
{
	if (unlikely(!mpdu)) {
		printk(KERN_ERR "%s(): NULL arg\n", __FUNCTION__);
		return;
	}

	if (likely(atomic_read(&mpdu->skb->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&mpdu->skb->users)))
		return;
	kfree_skb(mpdu->skb);
	__kfree_mpdu(mpdu);
	return;
}

ieee80215_mpdu_t *__alloc_mpdu(unsigned int size, gfp_t gfp_mask, int node);
static inline ieee80215_mpdu_t *alloc_mpdu(unsigned int size, gfp_t priority)
{
	ieee80215_mpdu_t *mpdu;
	caddr_t *ptr;

	mpdu = __alloc_mpdu(size, priority, -1);
	if (!mpdu) {
		printk(KERN_ERR "Unable to allocate mpdu\n");
		return NULL;
	}
	mpdu->skb = alloc_skb(size, priority);
	ptr = (caddr_t*)&mpdu->skb->cb[0];
	*ptr = (caddr_t)mpdu;
	return mpdu;
}

/**
 *	__dev_alloc_mpdu - allocate an mpduuff for receiving
 *	@length: length to allocate
 *	@gfp_mask: get_free_pages mask, passed to alloc_mpdu
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory.
 */
static inline ieee80215_mpdu_t *__dev_alloc_mpdu(unsigned int length,
					      gfp_t gfp_mask)
{
	ieee80215_mpdu_t *mpdu = alloc_mpdu(length + IEEE80215_MAX_PHY_OVERHEAD,
					    gfp_mask);
	if (likely(mpdu))
		skb_reserve(mpdu_to_skb(mpdu), IEEE80215_MAX_PHY_OVERHEAD);
	return mpdu;
}

/**
 *	__mac_alloc_mpdu - allocate an pdu for sending
 *	@length: length to allocate
 *	@gfp_mask: get_free_pages mask, passed to alloc_mpdu
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory.
 */
static inline ieee80215_mpdu_t *__mac_alloc_mpdu(unsigned int length,
		gfp_t gfp_mask)
{
	ieee80215_mpdu_t *mpdu = alloc_mpdu(length + IEEE80215_MAX_PHY_OVERHEAD +
		IEEE80215_MAX_FRAME_OVERHEAD + 2/* for mfr */, gfp_mask);
	if (likely(mpdu))
		skb_reserve(mpdu_to_skb(mpdu), IEEE80215_MAX_PHY_OVERHEAD +
			IEEE80215_MAX_FRAME_OVERHEAD);
	return mpdu;
}

/**
 *	__nwk_alloc_mpdu - allocate an pdu for sending
 *	@length: length to allocate
 *	@gfp_mask: get_free_pages mask, passed to alloc_mpdu
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory.
 */
static inline ieee80215_mpdu_t *__nwk_alloc_mpdu(unsigned int length,
		gfp_t gfp_mask)
{
	ieee80215_mpdu_t *mpdu = alloc_mpdu(length + IEEE80215_MAX_PHY_OVERHEAD +
					    IEEE80215_MAX_FRAME_OVERHEAD +
					    ZB_NWK_FRAME_OVERHEAD + 2, /* for mfr */
					    gfp_mask);
	if (likely(mpdu))
		skb_reserve(mpdu_to_skb(mpdu), IEEE80215_MAX_PHY_OVERHEAD +
				IEEE80215_MAX_FRAME_OVERHEAD +
				ZB_NWK_FRAME_OVERHEAD);
	return mpdu;
}

/**
 *	dev_alloc_mpdu - allocate an mpduuff for receiving
 *	@length: length to allocate
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory. Although this function
 *	allocates memory it can be called from an interrupt.
 */
static inline ieee80215_mpdu_t *dev_alloc_mpdu(unsigned int length)
{
	return __dev_alloc_mpdu(length, GFP_ATOMIC);
}

/**
 *	mac_alloc_mpdu - allocate an pdu for sending
 *	@length: length to allocate
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory. Although this function
 *	allocates memory it can be called from an interrupt.
 */
static inline ieee80215_mpdu_t *mac_alloc_mpdu(unsigned int length)
{
	return __mac_alloc_mpdu(length, GFP_ATOMIC);
}

/**
 *	nwk_alloc_mpdu - allocate an pdu for sending
 *	@length: length to allocate
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory. Although this function
 *	allocates memory it can be called from an interrupt.
 */
static inline ieee80215_mpdu_t *nwk_alloc_mpdu(unsigned int length)
{
	return __nwk_alloc_mpdu(length, GFP_ATOMIC);
}

ieee80215_mpdu_t *mpdu_clone(ieee80215_mpdu_t *mpdu);

#endif /*__KERNEL__*/

#endif /* IEEE80215_LIB_H */

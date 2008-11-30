/*
 * IEEE802.15.4-2003 specification
 * Physical interface.
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
 * Maxim Osipov <maxim.osipov@siemens.com>
 */

#ifndef IEEE80215_PHY_H
#define IEEE80215_PHY_H

#ifdef __KERNEL__
#include <linux/types.h>	/* For u{8,16,32} types */
#include <linux/skbuff.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#else
#include <stdint.h>
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

/******************************************************************************/
/* PHY constants */
/******************************************************************************/
/** The maximum PSDU size (in octets) the PHY shall be able to receive,
 * 127 octets
 */
#define IEEE80215_MAX_PHY_PACKET_SIZE	127

/** RX-to-TX or TX-to-RX maximum turnaround time in symbol periods */
#define IEEE80215_TURNAROUND_TIME 	12

/******************************************************************************/
/* PAN Information Base (PIB), PHY attribute identifiers */
/* See IEEE802.15.4-2003 draft, Table 19 */
/******************************************************************************/
/**
 * The RF channel to use for all following transmissions and receptions
 * (Integer, 0-26)
 */
#define IEEE80215_PHY_CURRENT_CHANNEL		0x00

/**
 * The 5 most significant bits (MSBs) (b27,... ,b31) of phyChannelsSupported
 * shall be reserved and set to 0, and the 27 LSBs (b0,b1, ... b26) shall
 * indicate the status (1=available, 0=unavailable) for each of the 27 valid
 * channels (bk shall indicate the status of channel k) (Bitmap)
 */
#define IEEE80215_PHY_CHANNELS_SUPPORTED	0x01

/**
 * The 2 MSBs represent the tolerance on the transmit power:
 *
 * 00 = +- 1 dB
 * 01 = +- 3 dB
 * 02 = +- 6 dB
 *
 * The 6 LSBs represent a signed integer in twos-complement format,
 * corresponding to the nominal transmit power of the device in decibels
 * relative to 1 mW. The lowest value of phyTransmitPower shall be interpreted
 * as less than or equal -32 dBm (Bitmap, 0x00-0xBF)
 */
#define IEEE80215_PHY_TRANSMIT_POWER	0x02

/** The CCA mode (Integer, 1-3) */
#define IEEE80215_PHY_CCA_MODE		0x03

#define IEEE80215_CCA_ED		0x1
#define IEEE80215_CCA_CS		0x2
#define IEEE80215_CCA_CSED		0x3

/******************************************************************************/
/* PAN Information Base (PIB), attribute ranges */
/* See IEEE802.15.4-2003 draft, Table 19 */
/******************************************************************************/
#define IEEE80215_PHY_CURRENT_CHANNEL_MIN	0x0
#define IEEE80215_PHY_CURRENT_CHANNEL_MAX	0x1a

#define IEEE80215_PHY_CHANNELS_SUPPORTED_MIN	0x0
#define IEEE80215_PHY_CHANNELS_SUPPORTED_MAX	0x7FFFFFF

#define IEEE80215_PHY_TRANSMIT_POWER_MIN	0x0
#define IEEE80215_PHY_TRANSMIT_POWER_MAX	0xbf

#define IEEE80215_PHY_CCA_MODE_MIN		0x1
#define IEEE80215_PHY_CCA_MODE_MAX		0x3

#ifdef __KERNEL__
/******************************************************************************/
/* PHY's PAN Information Base (PIB) */
/******************************************************************************/
struct ieee80215_phy_pib {
	u8	curr_channel;		/**< phyCurrentChannel */
	u32	supp_channels;		/**< phyChannelsSupported */
	u16	trans_power;		/**< phyTransmitPower */
	u8	cca_mode;		/**< phyCCAMode */
};

typedef struct ieee80215_phy_pib ieee80215_phy_pib_t;
#endif

struct ieee80215_plme_pib {
	int attr_type;
	union {
		u8	curr_channel;
		u32	supp_channels;
		u16	trans_power;
		u8	cca_mode;
	} attr;
};

typedef struct ieee80215_plme_pib ieee80215_plme_pib_t;

#ifdef __KERNEL__
struct ieee80215_phy;

/**
 * \brief Hardware driver interface description structure
 *
 * Supplied by the ieee802.15.4 compliant device driver on init.
 */
struct ieee80215_dev_ops {
	char	*name;	/**< Device name */
	void	*priv;
	u64	_64bit;
	void (*set_channel)(struct ieee80215_phy *phy, u8 channel);	/**< Set channel */
	void (*ed)(struct ieee80215_phy *phy);				/**< Read energy detection level */
	void (*set_state)(struct ieee80215_phy *phy, u8 flag);		/**< Change transceiver state */
	void (*xmit)(struct ieee80215_phy *phy, u8 *ppdu, size_t len);	/**< Send out data */
	void (*cca)(struct ieee80215_phy *phy, u8 mode);		/**< Perform CCA */
};
typedef struct ieee80215_dev_ops ieee80215_dev_op_t;

typedef enum {
	PHY_IDLE	= 0x0,
	PHY_RX_ON	= 0x1,
	PHY_TRX_OFF	= 0x2,
	PHY_TX_ON	= 0x4,
	PHY_BUSY_RX	= 0x8,
	PHY_BUSY_TX	= 0x10,
	PHY_BUSY	= 0x20,
} phy_state_t;

/**
 * \brief PHY layer structure
 */
struct ieee80215_phy {
	char			*name;		/**< Current PHY name */
	void			*priv;		/**< Private PHY data, link to MAC */
	phy_state_t		state;		/**< Phy state */
	phy_state_t		pending_state;
	ieee80215_phy_pib_t	pib;		/**< PIB */
	ieee80215_plme_pib_t	pib_attr;	/**< PIB values to exchange between MAC and PHY */

	struct sk_buff		*cmd_q;		/**< PHY requests queue */
	struct sk_buff		cmd;		/**< Static command to PHY */
	u8			s_idx;
	u8			s_len;
	u8			rbuf[IEEE80215_MAX_PHY_PACKET_SIZE];
	u8			r_idx;

	struct workqueue_struct	*worker;
	struct work_struct	data_request;
	struct work_struct	cca_request;
	struct work_struct	ed_request;
	struct work_struct	get_request;
	struct work_struct	set_trx_state_request;
	struct work_struct	set_request;

	struct ieee80215_dev_ops	*dev_op;

#if 0
	/* I see no reason why we need lock here at all,
	and we definitely don't need to export this interface:
	*/

	struct mutex		lock;
	int (*phy_lock)(struct ieee80215_phy *phy);
	void (*phy_unlock)(struct ieee80215_phy *phy);
#endif

	/**< PHY PD-SAP entry */
	int (*pd_data_request)(struct ieee80215_phy *phy, struct sk_buff *skb);

	/**< PHY PLME-SAP entry */
	int (*plme_cca_request)(struct ieee80215_phy *phy);
	int (*plme_ed_request)(struct ieee80215_phy *phy);
	int (*plme_get_request)(struct ieee80215_phy *phy, int pib_attr);
	int (*plme_set_trx_state_request)(struct ieee80215_phy *phy, int state);
	int (*plme_set_request)(struct ieee80215_phy *phy, ieee80215_plme_pib_t a);

	/* device interface, callbacks */
	void (*set_channel_confirm)(struct ieee80215_phy *phy, u8 status);
	void (*ed_confirm)(struct ieee80215_phy *phy, u8 status, u8 level);
	void (*set_state_confirm)(struct ieee80215_phy *phy, u8 status);
	void (*xmit_confirm)(struct ieee80215_phy *phy, u8 status);
	void (*cca_confirm)(struct ieee80215_phy *phy, u8 status);
	void (*receive_block)(struct ieee80215_phy *phy, unsigned int len, const char *buf, int ppduLQ);
	void (*receive_stream)(struct ieee80215_phy *phy, char c, int ppduLQ);
};
typedef struct ieee80215_phy ieee80215_phy_t;

ieee80215_phy_t* ieee80215_phy_alloc(const char *dev_name);
void ieee80215_phy_free(ieee80215_phy_t *phy);
int ieee80215_phy_init(ieee80215_phy_t *phy);
int ieee80215_phy_close(ieee80215_phy_t *phy);

#endif /* __KERNEL__ */

#endif

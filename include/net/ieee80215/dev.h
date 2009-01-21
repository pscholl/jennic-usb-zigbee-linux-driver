/*
 * IEEE802.15.4-2003 specification
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
 */
#ifndef IEEE80215_DEV_H
#define IEEE80215_DEV_H

#include <linux/skbuff.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/const.h>

struct ieee80215_pib {
	int type;
	u32 val;
};

#define IEEE80215_PIB_CURCHAN	0 /* Current channel, u8 6.1.2 */
#define IEEE80215_PIB_CHANSUPP	1 /* Channel mask, u32 6.1.2 */
#define IEEE80215_PIB_TRPWR	2 /* Transmit power, u8 6.4.2  */
#define IEEE80215_PIB_CCAMODE	3 /* CCA mode, u8 6.7.9 */

struct ieee80215_dev {
	char	*name;
	int	extra_tx_headroom; /* headroom to reserve for tx skb */
	void	*priv;		/* driver-specific data */
	u32	channel_mask;
	u8	current_channel;
};

struct ieee80215_ops {
	struct module	*owner;
	phy_status_t (*tx)(struct ieee80215_dev *dev, struct sk_buff *skb);
	phy_status_t (*cca)(struct ieee80215_dev *dev);
	phy_status_t (*ed)(struct ieee80215_dev *dev, u8 *level);
	phy_status_t (*set_trx_state)(struct ieee80215_dev *dev, phy_status_t state);
	phy_status_t (*set_channel)(struct ieee80215_dev *dev, int channel);
	u32 flags; /* Flags for device to set */
	// FIXME: PIB get/set ???
};

/* Checksum is in hardware and is omitted from packet */
#define IEEE80215_OPS_OMIT_CKSUM	(1 << 0)
						   
#ifdef __KERNEL__
struct ieee80215_priv {
	struct ieee80215_dev	hw;
	struct ieee80215_ops	*ops;
	struct net_device	*master;
	struct list_head	slaves;
	/* This one is used for scanning and other
	 * jobs not to be interfered with serial driver */
	struct workqueue_struct	*dev_workqueue;
};

#define ieee80215_to_priv(_hw)	container_of(_hw, struct ieee80215_priv, hw)

#endif

struct ieee80215_dev *ieee80215_alloc_device(void);
int ieee80215_register_device(struct ieee80215_dev *dev, struct ieee80215_ops *ops);
void ieee80215_unregister_device(struct ieee80215_dev *dev);
void ieee80215_free_device(struct ieee80215_dev *dev);
struct ieee80215_mac * ieee80215_get_mac_bydev(struct net_device *dev);

// FIXME: move to correct places:
void ieee80215_rx(struct ieee80215_dev *dev, struct sk_buff *skb);

int ieee80215_pib_set(struct ieee80215_dev *hw, struct ieee80215_pib *pib);
int ieee80215_pib_get(struct ieee80215_dev *hw, struct ieee80215_pib *pib);

#endif

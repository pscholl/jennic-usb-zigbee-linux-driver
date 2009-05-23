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
#ifndef IEEE802154_DEV_H
#define IEEE802154_DEV_H

#include <linux/skbuff.h>
#include <net/ieee802154/phy.h>
#include <net/ieee802154/const.h>

struct ieee802154_pib {
	int type;
	u32 val;
};

#define IEEE802154_PIB_CURCHAN	0 /* Current channel, u8 6.1.2 */
#define IEEE802154_PIB_CHANSUPP	1 /* Channel mask, u32 6.1.2 */
#define IEEE802154_PIB_TRPWR	2 /* Transmit power, u8 6.4.2  */
#define IEEE802154_PIB_CCAMODE	3 /* CCA mode, u8 6.7.9 */

struct ieee802154_dev {
	const char *name;
	int	extra_tx_headroom; /* headroom to reserve for tx skb */
	void	*priv;		/* driver-specific data */
	u32	channel_mask;
	u8	current_channel;
	u32 flags; /* Flags for device to set */
	struct device *parent;
};

/* Checksum is in hardware and is omitted from packet */
#define IEEE802154_OPS_OMIT_CKSUM	(1 << 0)


struct ieee802154_ops {
	struct module	*owner;
	phy_status_t (*tx)(struct ieee802154_dev *dev, struct sk_buff *skb);
	phy_status_t (*cca)(struct ieee802154_dev *dev);
	phy_status_t (*ed)(struct ieee802154_dev *dev, u8 *level);
	phy_status_t (*set_trx_state)(struct ieee802154_dev *dev, phy_status_t state);
	phy_status_t (*set_channel)(struct ieee802154_dev *dev, int channel);
	/* FIXME: PIB get/set ??? */
};

#ifdef __KERNEL__
#define IEEE802154_MAC_CMD_SCAN		0

struct ieee802154_priv {
	struct ieee802154_dev	hw;
	struct ieee802154_ops	*ops;
	struct net_device	*master;
	struct list_head	slaves;
	spinlock_t		slaves_lock;
	/* This one is used for scanning and other
	 * jobs not to be interfered with serial driver */
	struct workqueue_struct	*dev_workqueue;
	/* MAC BSN field */
	u8 bsn;
	/* MAC BSN field */
	u8 dsn;
};

#define ieee802154_to_priv(_hw)	container_of(_hw, struct ieee802154_priv, hw)

#endif

struct ieee802154_dev *ieee802154_alloc_device(void);
int ieee802154_register_device(struct ieee802154_dev *dev, struct ieee802154_ops *ops);
void ieee802154_unregister_device(struct ieee802154_dev *dev);
void ieee802154_free_device(struct ieee802154_dev *dev);

int ieee802154_add_slave(struct ieee802154_dev *hw, const u8 *addr);
/* void ieee802154_del_slave(struct ieee802154_dev *hw, struct net_device *slave); */
void ieee802154_drop_slaves(struct ieee802154_dev *hw);

void ieee802154_rx(struct ieee802154_dev *dev, struct sk_buff *skb, u8 lqi);
void ieee802154_rx_irqsafe(struct ieee802154_dev *dev, struct sk_buff *skb, u8 lqi);

int ieee802154_pib_set(struct ieee802154_dev *hw, struct ieee802154_pib *pib);
int ieee802154_pib_get(struct ieee802154_dev *hw, struct ieee802154_pib *pib);

int ieee802154_slave_register_notifier(struct net_device *dev, struct notifier_block *nb);
int ieee802154_slave_unregister_notifier(struct net_device *dev, struct notifier_block *nb);
int ieee802154_slave_event(struct net_device *dev, int event, void *data);

#define IEEE802154_NOTIFIER_BEACON		0x0

void ieee802154_set_pan_id(struct net_device *dev, u16 panid);
#endif


/*
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */
#ifndef MAC802154_H
#define MAC802154_H

struct ieee802154_priv {
	struct ieee802154_dev	hw;
	struct ieee802154_ops	*ops;
	/* As in mac80211 slaves list is modified:
	 * 1) under the RTNL
	 * 2) protected by slaves_mtx;
	 * 3) in an RCU manner
	 *
	 * So atomic readers can use any of this protection methods
	 */
	struct list_head	slaves;
	struct mutex		slaves_mtx;
	/* This one is used for scanning and other
	 * jobs not to be interfered with serial driver */
	struct workqueue_struct	*dev_workqueue;
};

#define ieee802154_to_priv(_hw)	container_of(_hw, struct ieee802154_priv, hw)

void ieee802154_drop_slaves(struct ieee802154_dev *hw);

void ieee802154_subif_rx(struct ieee802154_dev *hw, struct sk_buff *skb);

struct ieee802154_phy_cb {
	u8 lqi;
	u8 chan;
};

static inline struct ieee802154_phy_cb *phy_cb(struct sk_buff *skb)
{
	return (struct ieee802154_phy_cb *)skb->cb;
}


extern struct ieee802154_mlme_ops mac802154_mlme;

int ieee802154_mlme_scan_req(struct net_device *dev,
		u8 type, u32 channels, u8 duration);

int ieee802154_process_cmd(struct net_device *dev, struct sk_buff *skb);
int ieee802154_send_beacon_req(struct net_device *dev);

struct ieee802154_priv *ieee802154_slave_get_priv(struct net_device *dev);

/* FIXME: this interface should be rethought ! */
struct notifier_block;
int ieee802154_slave_register_notifier(struct net_device *dev,
		struct notifier_block *nb);
int ieee802154_slave_unregister_notifier(struct net_device *dev,
		struct notifier_block *nb);
int ieee802154_slave_event(struct net_device *dev,
		int event, void *data);
#define IEEE802154_NOTIFIER_BEACON		0x0

#endif

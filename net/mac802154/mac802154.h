/*
 * Copyright (C) 2007, 2008, 2009 Siemens AG
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

#include <linux/spinlock.h>

struct ieee802154_priv {
	struct ieee802154_dev	hw;
	struct ieee802154_ops	*ops;

	struct wpan_phy *phy;

	int open_count;
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

struct ieee802154_sub_if_data {
	struct list_head list; /* the ieee802154_priv->slaves list */

	struct ieee802154_priv *hw;
	struct net_device *dev;

	rwlock_t mib_lock;

	u16 pan_id;
	u16 short_addr;

	u8 chan;
	u8 page;

	/* MAC BSN field */
	u8 bsn;
	/* MAC BSN field */
	u8 dsn;
};

void ieee802154_drop_slaves(struct ieee802154_dev *hw);
struct net_device *ieee802154_add_iface(struct wpan_phy *phy);

void ieee802154_subif_rx(struct ieee802154_dev *hw, struct sk_buff *skb);

extern struct ieee802154_mlme_ops mac802154_mlme;

int ieee802154_mlme_scan_req(struct net_device *dev,
		u8 type, u32 channels, u8 page, u8 duration);

int ieee802154_process_cmd(struct net_device *dev, struct sk_buff *skb);
int ieee802154_send_beacon_req(struct net_device *dev);

struct ieee802154_priv *ieee802154_slave_get_priv(struct net_device *dev);

#endif

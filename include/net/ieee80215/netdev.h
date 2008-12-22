/*
 * IEEE80215.4 net device
 *
 * Copyright 2008 Siemens AG
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
 */

#ifndef IEEE80215_NETDEV_H
#define IEEE80215_NETDEV_H
#include <linux/netdevice.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/phy.h>
//#include <net/ieee80215/mac.h>

struct ieee80215_netdev_priv {
	struct list_head list;
	struct ieee80215_mac *mac;
	struct net_device *dev;
	struct sock *sk;
	struct net_device_stats stats;
};

struct ieee80215_mnetdev_priv {
	struct ieee80215_priv *hw;
	struct list_head interfaces;
	struct net_device *dev;
	struct net_device_stats stats;
};

int ieee80215_register_netdev_master(struct ieee80215_priv *hw);
void ieee80215_unregister_netdev_master(struct ieee80215_priv *hw);

// FIXME: this header should be probably separated, as it contains both driver-specific and stack specific things
int ieee80215_add_slave(struct ieee80215_dev *hw, const u8 *addr);
void ieee80215_del_slave(struct ieee80215_dev *hw, struct ieee80215_netdev_priv *ndp);

// FIXME: this clearly should be moved somewhere else
extern struct proto ieee80215_raw_prot;
extern struct proto ieee80215_dgram_prot;
void ieee80215_raw_deliver(struct net_device *dev, struct sk_buff *skb);

#endif


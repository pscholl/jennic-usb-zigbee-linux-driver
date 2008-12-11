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
#include <net/ieee80215/phy.h>

struct ieee80215_netdev_priv {
	struct list_head list;
	struct ieee80215_mac *mac;
	struct net_device *dev;
	struct sock *sk;
};

struct ieee80215_mnetdev_priv {
	struct ieee80215_dev_ops *dev_ops;
	struct list_head interfaces;
	struct net_device *dev;
};
int ieee80215_register_netdev_master(struct ieee80215_phy * phy,
					struct ieee80215_dev_ops *dev_ops);
int ieee80215_register_netdev(struct ieee80215_dev_ops *dev_ops, struct net_device *mdev);
int ieee80215_net_cmd(struct ieee80215_phy *phy, u8 command, u8 status, u8 data);
int ieee80215_net_rx(struct ieee80215_phy *phy, u8 *data, ssize_t len);

#endif

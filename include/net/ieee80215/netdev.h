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
#include <net/ieee80215/af_ieee80215.h>

int ieee80215_register_netdev_master(struct ieee80215_priv *hw);
void ieee80215_unregister_netdev_master(struct ieee80215_priv *hw);

// FIXME: this header should be probably separated, as it contains both driver-specific and stack specific things
void ieee80215_subif_rx(struct ieee80215_dev *hw, struct sk_buff *skb);
struct ieee80215_priv *ieee80215_slave_get_hw(struct net_device *dev);

struct ieee80215_addr;
struct net_device *ieee80215_get_dev(struct net *net, struct ieee80215_addr *sa);

// FIXME: should be dropped in favour of MIB getting
u16 ieee80215_dev_get_pan_id(struct net_device *dev);
u16 ieee80215_dev_get_short_addr(struct net_device *dev);
void ieee80215_dev_set_pan_id(struct net_device *dev, u16 val);
void ieee80215_dev_set_short_addr(struct net_device *dev, u16 val);
void ieee80215_dev_set_channel(struct net_device *dev, u8 chan);

struct ieee80215_phy_cb {
	u8 lqi;
	u8 chan;
};

#define PHY_CB(skb)	((struct ieee80215_phy_cb *)(skb)->cb)


struct ieee80215_mac_cb {
	struct ieee80215_phy_cb phy;
	struct ieee80215_addr sa;
	struct ieee80215_addr da;
	u8 flags;
	u8 seq;
};
#define MAC_CB(skb)	((struct ieee80215_mac_cb *)(skb)->cb)

#define MAC_CB_FLAG_TYPEMASK		((1 << 3) - 1)

#define MAC_CB_FLAG_ACKREQ		(1 << 3)
#define MAC_CB_FLAG_SECEN		(1 << 4)
#define MAC_CB_FLAG_INTRAPAN		(1 << 5)

#define MAC_CB_IS_ACKREQ(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_ACKREQ)
#define MAC_CB_IS_SECEN(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_SECEN)
#define MAC_CB_IS_INTRAPAN(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_INTRAPAN)
#define MAC_CB_TYPE(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_TYPEMASK)

#endif


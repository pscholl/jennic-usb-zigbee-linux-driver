/*
 * IEEE802154.4 net device
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

#ifndef IEEE802154_NETDEV_H
#define IEEE802154_NETDEV_H
#include <linux/netdevice.h>
#include <net/ieee802154/dev.h>
#include <net/ieee802154/phy.h>
#include <net/ieee802154/af_ieee802154.h>

int ieee802154_register_netdev_master(struct ieee802154_priv *hw);
void ieee802154_unregister_netdev_master(struct ieee802154_priv *hw);

/* FIXME: this header should be probably separated, as it contains both driver-specific and stack specific things */
void ieee802154_subif_rx(struct ieee802154_dev *hw, struct sk_buff *skb);
struct ieee802154_priv *ieee802154_slave_get_hw(struct net_device *dev);

struct ieee802154_addr;
struct net_device *ieee802154_get_dev(struct net *net, struct ieee802154_addr *sa);

/* FIXME: should be dropped in favour of MIB getting */
u16 ieee802154_dev_get_pan_id(struct net_device *dev);
u16 ieee802154_dev_get_short_addr(struct net_device *dev);
void ieee802154_dev_set_pan_id(struct net_device *dev, u16 val);
void ieee802154_dev_set_short_addr(struct net_device *dev, u16 val);
void ieee802154_dev_set_channel(struct net_device *dev, u8 chan);

struct ieee802154_phy_cb {
	u8 lqi;
	u8 chan;
};

#define PHY_CB(skb)	((struct ieee802154_phy_cb *)(skb)->cb)


struct ieee802154_mac_cb {
	struct ieee802154_phy_cb phy;
	struct ieee802154_addr sa;
	struct ieee802154_addr da;
	u8 flags;
	u8 seq;
};
#define MAC_CB(skb)	((struct ieee802154_mac_cb *)(skb)->cb)

#define MAC_CB_FLAG_TYPEMASK		((1 << 3) - 1)

#define MAC_CB_FLAG_ACKREQ		(1 << 3)
#define MAC_CB_FLAG_SECEN		(1 << 4)
#define MAC_CB_FLAG_INTRAPAN		(1 << 5)

#define MAC_CB_IS_ACKREQ(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_ACKREQ)
#define MAC_CB_IS_SECEN(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_SECEN)
#define MAC_CB_IS_INTRAPAN(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_INTRAPAN)
#define MAC_CB_TYPE(skb)		(MAC_CB(skb)->flags & MAC_CB_FLAG_TYPEMASK)

struct ieee802154_mlme_ops {
	int (*assoc_req)(struct net_device *dev, struct ieee802154_addr *addr, u8 channel, u8 cap);
	int (*assoc_resp)(struct net_device *dev, struct ieee802154_addr *addr, u16 short_addr, u8 status);
	int (*disassoc_req)(struct net_device *dev, struct ieee802154_addr *addr, u8 reason);
	int (*start_req)(struct net_device *dev, struct ieee802154_addr *addr, u8 channel,
			     u8 bcn_ord, u8 sf_ord, u8 pan_coord, u8 blx,
			     u8 coord_realign);
	int (*scan_req)(struct net_device *dev, u8 type, u32 channels, u8 duration);

	/*
	 * FIXME: these should become the part of PIB/MIB interface.
	 * However we still don't have IB interface of any kind
	 */
	u16 (*get_pan_id)(struct net_device *dev);
	u16 (*get_short_addr)(struct net_device *dev);
	u8 (*get_dsn)(struct net_device *dev);
};

#define IEEE802154_MLME_OPS(dev)	((struct ieee802154_mlme_ops *) dev->ml_priv)

extern struct ieee802154_mlme_ops ieee802154_mlme;

#endif


/*
 * An interface between IEEE802.15.4 device and rest of the kernel.
 *
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
 * Maxim Osipov <maxim.osipov@siemens.com>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#ifndef IEEE802154_NETDEVICE_H
#define IEEE802154_NETDEVICE_H

/*
 * A control block of skb passed between the ARPHRD_IEEE802154 device
 * and other stack parts.
 */
struct ieee802154_mac_cb {
	u8 lqi;
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

#define IEEE802154_MAC_SCAN_ED		0
#define IEEE802154_MAC_SCAN_ACTIVE	1
#define IEEE802154_MAC_SCAN_PASSIVE	2
#define IEEE802154_MAC_SCAN_ORPHAN	3

/*
 * This should be located at net_device->ml_priv
 */
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
	u8 (*get_bsn)(struct net_device *dev);
};

#define IEEE802154_MLME_OPS(dev)	((struct ieee802154_mlme_ops *) dev->ml_priv)

#endif



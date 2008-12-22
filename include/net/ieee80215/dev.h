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

struct ieee80215_dev {
	char	*name;
	int	extra_tx_headroom; /* headroom to reserve for tx skb */
	void	*priv;		/* driver-specific data */
};

struct ieee80215_ops {
	struct module	*owner;
	phy_status_t (*tx)(struct ieee80215_dev *dev, struct sk_buff *skb);
	phy_status_t (*cca)(struct ieee80215_dev *dev);
	phy_status_t (*ed)(struct ieee80215_dev *dev, u8 *level);
	phy_status_t (*set_trx_state)(struct ieee80215_dev *dev, phy_status_t state);
	// FIXME: PIB get/set ???
};

#ifdef __KERNEL__
struct ieee80215_priv {
	struct ieee80215_dev	hw;
	struct ieee80215_ops	*ops;
	struct net_device	*master;
	struct list_head	slaves;
};

#define ieee80215_to_priv(_hw)	container_of(_hw, struct ieee80215_priv, hw)

#endif

struct ieee80215_dev *ieee80215_alloc_device(void);
int ieee80215_register_device(struct ieee80215_dev *dev, struct ieee80215_ops *ops);
void ieee80215_unregister_device(struct ieee80215_dev *dev);
void ieee80215_free_device(struct ieee80215_dev *dev);

// FIXME: move to correct places:
void ieee80215_rx(struct ieee80215_dev *dev, struct sk_buff *skb);
#define IEEE80215_ADDR_LEN	8

#endif

/*
 * IEEE80215.4 MAC layer receive part.
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
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rculist.h>

#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>

#define DBG_DUMP(data, len) { \
	int i; \
	pr_debug("file %s: function: %s: data: len %d:\n", __FILE__, __FUNCTION__, len); \
	for(i = 0; i < len; i++) {\
		pr_debug("%02x: %02x\n", i, (data)[i]); \
	} \
}

void ieee80215_rx(struct ieee80215_dev *dev, struct sk_buff *skb)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(dev);

	BUG_ON(!skb);

	skb->iif = skb->dev->ifindex;

	skb_reset_mac_header(skb);

	skb->protocol = htons(ETH_P_IEEE80215);

	ieee80215_subif_rx(dev, skb);

	skb->dev = priv->master;
	netif_rx(skb);
}

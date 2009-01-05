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
	struct ieee80215_netdev_priv *ndp;
	unsigned char *head;
	unsigned int head_off, tail_off;

	BUG_ON(!skb);

	skb->iif = skb->dev->ifindex;

	if (skb->len < /*3 + 4 + 2*/ 3 + 8 + 8 + 2)
		goto out_master;

	/*
	 * We parse headers on our origin SKB, changing pointers.
	 * Then we can restore them back just before passing the SKB
	 * to netif_rx(master) for delivery.
	 */

	// FIXME: correct address checking
	head_off = 3 + IEEE80215_ADDR_LEN + IEEE80215_ADDR_LEN;
	head = skb->data;
	skb_pull(skb, head_off);
	DBG_DUMP(head+3+IEEE80215_ADDR_LEN, 8);

	// FIXME: check CRC if necessary
	tail_off = 2;
	skb_trim(skb, skb->len - tail_off); // CRC

	list_for_each_entry_rcu(ndp, &priv->slaves, list)
	{
		struct sk_buff *skb2 = NULL;
		DBG_DUMP(ndp->dev->dev_addr, 8);

		// FIXME: correct address checking
		if (memcmp(head + 3 + IEEE80215_ADDR_LEN , ndp->dev->dev_addr, IEEE80215_ADDR_LEN) &&
		    memcmp(head + 3 + IEEE80215_ADDR_LEN , ndp->dev->broadcast, IEEE80215_ADDR_LEN))
			continue;

		skb2 = skb_clone(skb, GFP_ATOMIC);
		skb_reset_mac_header(skb2);

		skb2->dev = ndp->dev;
		skb2->protocol = htons(ETH_P_IEEE80215);
		netif_rx(skb2);
	}

	skb_push(skb, head_off);
	skb_put(skb, tail_off);

out_master:
	skb->dev = priv->master;
	skb->protocol = htons(ETH_P_IEEE80215_MAC);
	netif_rx(skb);
}

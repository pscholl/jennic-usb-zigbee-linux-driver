/* 
 * MAC commands interface
 *
 * Copyright 2007, 2008 Siemens AG
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
 * Sergey Lapin <sergey.lapin@siemens.com>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/mac_cmd.h>
#include <net/ieee80215/mac_def.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/nl.h>

static int ieee80215_cmd_assoc_req(struct sk_buff *skb)
{
	u8 cap;

	if (skb->len != 2)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_LONG ||
	    MAC_CB(skb)->sa.pan_id != IEEE80215_PANID_BROADCAST)
		return -EINVAL;

	// FIXME: check that we allow incoming ASSOC requests by consulting MIB

	cap = skb->data[1];

	return ieee80215_nl_assoc_indic(skb->dev, &MAC_CB(skb)->sa, cap);
}

int ieee80215_process_cmd(struct net_device *dev, struct sk_buff *skb)
{
	u8 cmd;

	if (skb->len < 1) {
		pr_warning("Uncomplete command frame!\n");
		goto drop;
	}

	cmd = *(skb->data);
	pr_debug("Command %02x on device %s\n", cmd, dev->name);

	switch (cmd) {
	case IEEE80215_CMD_ASSOCIATION_REQ:
		ieee80215_cmd_assoc_req(skb);
		break;
	default:
		pr_debug("Frame type is not supported yet\n");
		goto drop;
	}


	kfree_skb(skb);
	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

int ieee80215_send_cmd(struct net_device *dev, struct ieee80215_addr *addr,
		const u8 *buf, int len)
{
	struct sk_buff *skb;
	int err;

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb_reset_network_header(skb);

	err = dev_hard_header(skb, dev, ETH_P_IEEE80215, addr, NULL, len);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}

	skb_reset_mac_header(skb);
	memcpy(skb_put(skb, len), buf, len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IEEE80215);

	return dev_queue_xmit(skb);
}


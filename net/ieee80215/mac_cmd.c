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
#include <net/ieee80215/mac_def.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/nl.h>
#include <net/ieee80215/beacon.h>

static int ieee80215_cmd_beacon_req(struct sk_buff *skb)
{
	struct ieee80215_addr saddr; /* jeez */
	int flags = 0;
	if (skb->len != 1)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_NONE ||
	    MAC_CB(skb)->da.addr_type != IEEE80215_ADDR_SHORT ||
	    MAC_CB(skb)->da.pan_id != IEEE80215_PANID_BROADCAST ||
	    MAC_CB(skb)->da.short_addr != IEEE80215_ADDR_BROADCAST)
		return -EINVAL;


	/* 7 bytes of MHR and 1 byte of command frame identifier
	 * We have no information in this command to proceed with.
	 * we need to submit beacon as answer to this. */

	return ieee80215_send_beacon(skb->dev, &saddr, ieee80215_dev_get_pan_id(skb->dev),
			NULL, 0, flags, NULL);
}

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

static int ieee80215_cmd_assoc_resp(struct sk_buff *skb)
{
	u8 status;
	u16 short_addr;

	if (skb->len != 4)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_LONG ||
	    MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_LONG ||
	    !(MAC_CB(skb)->flags & MAC_CB_FLAG_INTRAPAN))
		return -EINVAL;

	// FIXME: check that we requested association ?

	status = skb->data[3];
	short_addr = skb->data[1] | (skb->data[2] << 8);
	pr_info("Received ASSOC-RESP status %x, addr %hx\n", status, short_addr);
	if (status) {
		ieee80215_dev_set_short_addr(skb->dev, IEEE80215_ADDR_BROADCAST);
		ieee80215_dev_set_pan_id(skb->dev, IEEE80215_PANID_BROADCAST);
	} else
		ieee80215_dev_set_short_addr(skb->dev, short_addr);

	return ieee80215_nl_assoc_confirm(skb->dev, short_addr, status);
}

static int ieee80215_cmd_disassoc_notify(struct sk_buff *skb)
{
	u8 reason;

	if (skb->len != 2)
		return -EINVAL;

	if (skb->pkt_type != PACKET_HOST)
		return 0;

	if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_LONG ||
	    (MAC_CB(skb)->da.addr_type != IEEE80215_ADDR_LONG &&
	     MAC_CB(skb)->da.addr_type != IEEE80215_ADDR_SHORT) ||
	    MAC_CB(skb)->sa.pan_id != MAC_CB(skb)->da.pan_id)
		return -EINVAL;

	reason = skb->data[1];

	// FIXME: checks if this was our coordinator and the disassoc us
	// FIXME: if we device, one should receive ->da and not ->sa
	// FIXME: the status should also help

	return ieee80215_nl_disassoc_indic(skb->dev, &MAC_CB(skb)->sa, reason);
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
	case IEEE80215_CMD_ASSOCIATION_RESP:
		ieee80215_cmd_assoc_resp(skb);
		break;
	case IEEE80215_CMD_DISASSOCIATION_NOTIFY:
		ieee80215_cmd_disassoc_notify(skb);
		break;
	case IEEE80215_CMD_BEACON_REQ:
		ieee80215_cmd_beacon_req(skb);
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

int ieee80215_send_beacon_req(struct net_device *dev)
{
	struct ieee80215_addr addr;
	struct ieee80215_addr saddr;
	u8 cmd = IEEE80215_CMD_BEACON_REQ;
	addr.addr_type = IEEE80215_ADDR_SHORT;
	addr.short_addr = IEEE80215_ADDR_BROADCAST;
	addr.pan_id = IEEE80215_PANID_BROADCAST;
	saddr.addr_type = IEEE80215_ADDR_NONE;
	return ieee80215_send_cmd(dev, &addr, &saddr, &cmd, 1);
}

int ieee80215_send_cmd(struct net_device *dev,
		struct ieee80215_addr *addr, struct ieee80215_addr *saddr,
		const u8 *buf, int len)
{
	struct sk_buff *skb;
	int err;
	struct ieee80215_priv *hw = ieee80215_slave_get_hw(dev);

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb_reset_network_header(skb);

	MAC_CB(skb)->flags = IEEE80215_FC_TYPE_MAC_CMD | MAC_CB_FLAG_ACKREQ;
	MAC_CB(skb)->seq = hw->dsn;
	err = dev_hard_header(skb, dev, ETH_P_IEEE80215, addr, saddr, len);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}

	skb_reset_mac_header(skb);
	memcpy(skb_put(skb, len), buf, len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IEEE80215);
	hw->dsn++;

	return dev_queue_xmit(skb);
}


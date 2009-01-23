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

/* Beacon frame format per specification is the followinf:
 * Standard MAC frame header:
 * FC (2) SEQ (1) 
 * Addressing (4-20)
 * Beacon fields:
 * <Superframe specification> (2)
 * <GTS> (?)
 * <Pending address> (?)
 * <Beacon payload> (?)
 * FCS (2)
 *
 * Superframe specification:
 * bit   Value
 * 15    Association permit
 * 14    PAN coordinator
 * 13    Reserved
 * 12    Battery life extension
 * 8-11  Final CAP slot
 * 4-7   Superframe order
 * 0-3   Beacon order
 *
 * GTS:
 * <GTS specification> (1)
 * <GTS directions> (0-1)
 * <GTS list> (?)
 *
 * Pending address:
 * <Pending address specification> (1)
 * <Pending address list (?)
 *
 * GTS specification:
 * bit   Value
 * 7     GTS permit
 * 3-6   Reserved
 * o-2   GTS descriptor count
 *
 * Pending address specification:
 * bit   Value
 * 7     Reserved
 * 4-6   Number of extended addresses pendinf
 * 3     Reserved
 * 0-2   Number of short addresses pending
 * */

#define IEEE80215_BEACON_SF_BO_BEACONLESS	(15 << 0)
#define IEEE80215_BEACON_SF_SO(x)		(x << 4)
#define IEEE80215_BEACON_SF_SO_INACTIVE		IEEE80215_BEACON_SF_SO(15)
#define IEEE80215_BEACON_SF_PANCOORD		(1 << 14)
#define IEEE80215_BEACON_SF_CANASSOC		(1 << 15)
#define IEEE80215_BEACON_GTS_COUNT(x)		(x << 0)
#define IEEE80215_BEACON_GTS_PERMIT		(1 << 7)

struct ieee80215_address_list {
	struct list_head list;
	struct ieee80215_addr addr;
};
/*
 * @dev device
 * @addr destination address
 * @saddr source address
 * @buf beacon payload
 * @len beacon payload size
 * @pan_coord - if we're PAN coordinator while sending this frame
 * @gts_permit - wheather we allow GTS requests
 * @al address list to be provided in beacon
*/

int ieee80215_send_beacon(struct net_device *dev,
		struct ieee80215_addr *addr, struct ieee80215_addr *saddr,
		const u8 *buf, int len, bool pan_coord,
		bool can_assoc, bool gts_permit, struct ieee80215_address_list *al)
{
	struct sk_buff *skb;
	int err;
	u16 sf;
	u8 gts;
	u8 pa_spec;

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb_reset_network_header(skb);

	MAC_CB(skb)->flags = IEEE80215_FC_TYPE_BEACON;
	err = dev_hard_header(skb, dev, ETH_P_IEEE80215, addr, saddr, len);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}
	skb_reset_mac_header(skb);

	/* Superframe */
	sf = IEEE80215_BEACON_SF_BO_BEACONLESS;
	sf |= IEEE80215_BEACON_SF_SO_INACTIVE;
	if(pan_coord)
		sf |= IEEE80215_BEACON_SF_PANCOORD;

	if(can_assoc)
		sf |= IEEE80215_BEACON_SF_CANASSOC;
	memcpy(skb_put(skb,  sizeof(sf)), &sf, sizeof(sf));

	/* TODO GTS */
	gts = 0;

	if(gts_permit)
		gts |= IEEE80215_BEACON_GTS_PERMIT;
	memcpy(skb_put(skb, sizeof(gts)), &gts, sizeof(gts));

	/* FIXME pending address */
	pa_spec = 0;
	memcpy(skb_put(skb, sizeof(pa_spec)), &pa_spec, sizeof(pa_spec));


	memcpy(skb_put(skb, len), buf, len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IEEE80215);

	return dev_queue_xmit(skb);
}


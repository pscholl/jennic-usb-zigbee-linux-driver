/*
 * MAC beacon interface
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
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/if_arp.h>
#include <linux/list.h>

#include <net/ieee802154/af_ieee802154.h>
#include <net/ieee802154/nl802154.h>
#include <net/ieee802154/mac802154.h>
#include <net/ieee802154/mac_def.h>
#include <net/ieee802154/netdevice.h>

#include "mac802154.h"
#include "beacon.h"

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
 * 0-2   GTS descriptor count
 *
 * Pending address specification:
 * bit   Value
 * 7     Reserved
 * 4-6   Number of extended addresses pendinf
 * 3     Reserved
 * 0-2   Number of short addresses pending
 * */

#define IEEE802154_BEACON_SF_BO_BEACONLESS	(15 << 0)
#define IEEE802154_BEACON_SF_SO(x)		((x & 0xf) << 4)
#define IEEE802154_BEACON_SF_SO_INACTIVE	IEEE802154_BEACON_SF_SO(15)
#define IEEE802154_BEACON_SF_PANCOORD		(1 << 14)
#define IEEE802154_BEACON_SF_CANASSOC		(1 << 15)
#define IEEE802154_BEACON_GTS_COUNT(x)		(x << 0)
#define IEEE802154_BEACON_GTS_PERMIT		(1 << 7)
#define IEEE802154_BEACON_PA_SHORT(x)		((x & 7) << 0)
#define IEEE802154_BEACON_PA_LONG(x)		((x & 7) << 4)

/* Flags parameter */
#define IEEE802154_BEACON_FLAG_PANCOORD		(1 << 0)
#define IEEE802154_BEACON_FLAG_CANASSOC		(1 << 1)
#define IEEE802154_BEACON_FLAG_GTSPERMIT		(1 << 2)

struct ieee802154_address_list {
	struct list_head list;
	struct ieee802154_addr addr;
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
 *
 * TODO:
 * For a beacon frame, the sequence number field shall specify a BSN.
 * Each coordinator shall store its current
 * BSN value in the MAC PIB attribute macBSN and initialize it to
 * a random value.
 * The algorithm for choosing a random number is out of the scope
 * of this standard. The coordinator shall copy the value of the macBSN
 * attribute into the sequence number field of a beacon frame,
 * each time one is generated, and shall then increment macBSN by one.
 *
*/


int ieee802154_send_beacon(struct net_device *dev,
		struct ieee802154_addr *saddr,
		u16 pan_id, const u8 *buf, int len,
		int flags, struct list_head *al)
{
	struct sk_buff *skb;
	int err;
	u16 sf;
	u8 gts;
	u8 pa_spec;
	int addr16_cnt;
	int addr64_cnt;
	struct ieee802154_addr addr;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb_reset_network_header(skb);

	mac_cb(skb)->flags = IEEE802154_FC_TYPE_BEACON;
	mac_cb(skb)->seq = ieee802154_mlme_ops(dev)->get_bsn(dev);

	addr.addr_type = IEEE802154_ADDR_NONE;
	err = dev_hard_header(skb, dev, ETH_P_IEEE802154, &addr, saddr, len);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}
	skb_reset_mac_header(skb);

	/* Superframe */
	sf = IEEE802154_BEACON_SF_BO_BEACONLESS;
	sf |= IEEE802154_BEACON_SF_SO_INACTIVE;
	if (flags & IEEE802154_BEACON_FLAG_PANCOORD)
		sf |= IEEE802154_BEACON_SF_PANCOORD;

	if (flags & IEEE802154_BEACON_FLAG_CANASSOC)
		sf |= IEEE802154_BEACON_SF_CANASSOC;
	memcpy(skb_put(skb,  sizeof(sf)), &sf, sizeof(sf));

	/* TODO GTS */
	gts = 0;

	if (flags & IEEE802154_BEACON_FLAG_GTSPERMIT)
		gts |= IEEE802154_BEACON_GTS_PERMIT;
	memcpy(skb_put(skb, sizeof(gts)), &gts, sizeof(gts));

	/* FIXME pending address */
	addr16_cnt = 0;
	addr64_cnt = 0;

	pa_spec = IEEE802154_BEACON_PA_LONG(addr64_cnt) |
		IEEE802154_BEACON_PA_SHORT(addr16_cnt);
	memcpy(skb_put(skb, sizeof(pa_spec)), &pa_spec, sizeof(pa_spec));

	memcpy(skb_put(skb, len), buf, len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IEEE802154);

	return dev_queue_xmit(skb);
}

/* at entry to this function we need skb->data to point to start
 * of beacon field and MAC frame already parsed into MAC_CB */

int parse_beacon_frame(struct sk_buff *skb, u8 *buf,
		int *flags, struct list_head *al)
{
	int offt = 0;
	u8 gts_spec;
	u8 pa_spec;
	struct ieee802154_pandsc *pd;
	u16 sf = skb->data[0] + (skb->data[1] << 8);

	pd = kzalloc(sizeof(struct ieee802154_pandsc), GFP_KERNEL);

	/* Filling-up pre-parsed values */
	pd->lqi = mac_cb(skb)->lqi;
	pd->sf = sf;
	/* FIXME: make sure we do it right */
	memcpy(&pd->addr, &mac_cb(skb)->da, sizeof(struct ieee802154_addr));

	/* Supplying our nitifiers with data */
	ieee802154_slave_event(skb->dev, IEEE802154_NOTIFIER_BEACON, pd);
	ieee802154_nl_beacon_indic(skb->dev, pd->addr.pan_id,
			pd->addr.short_addr);
	/* FIXME: We don't cache PAN descriptors yet */
	kfree(pd);

	offt += 2;
	gts_spec = skb->data[offt++];
	/* FIXME !!! */
	if ((gts_spec & 7) != 0) {
		pr_debug("We still don't parse GTS part properly");
		return -ENOTSUPP;
	}
	pa_spec = skb->data[offt++];
	/* FIXME !!! */
	if (pa_spec != 0) {
		pr_debug("We still don't parse PA part properly");
		return -ENOTSUPP;
	}

	*flags = 0;

	if (sf & IEEE802154_BEACON_SF_PANCOORD)
		*flags |= IEEE802154_BEACON_FLAG_PANCOORD;

	if (sf & IEEE802154_BEACON_SF_CANASSOC)
		*flags |= IEEE802154_BEACON_FLAG_CANASSOC;
	BUG_ON(skb->len - offt < 0);
	/* FIXME */
	if (buf && (skb->len - offt > 0))
		memcpy(buf, skb->data + offt, skb->len - offt);
	return 0;
}


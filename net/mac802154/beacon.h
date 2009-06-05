/*
 * beacon.h
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
 */

#ifndef IEEE802154_BEACON_H
#define IEEE802154_BEACON_H

/* Per spec; optimizations are needed */
struct ieee802154_pandsc {
	struct list_head	list;
	struct ieee802154_addr	addr; /* Contains panid */
	int			channel;
	u16			sf;
	bool			gts_permit;
	u8			lqi;
/* FIXME: Aging of stored PAN descriptors is not decided yet,
 * because no PAN descriptor storage is implemented yet */
	u32			timestamp;
};

int parse_beacon_frame(struct sk_buff *skb, u8 * buf,
		int *flags, struct list_head *al);

int ieee802154_send_beacon(struct net_device *dev,
		struct ieee802154_addr *saddr,
		u16 pan_id, const u8 *buf, int len,
		int flags, struct list_head *al);

#endif /* IEEE802154_BEACON_H */


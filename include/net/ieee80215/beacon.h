/*
 * beacon.h
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
 * Pavel Smolenskiy <pavel.smolenskiy@gmail.com>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 */

#ifndef IEEE80215_BEACON_H
#define IEEE80215_BEACON_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "af_ieee80215.h"

/* Per spec; optimizations are needed */
struct ieee80215_pandsc {
	struct list_head	list;
	struct ieee80215_addr	addr; /* Contains panid */
	int			channel;
	u16			sf;
	bool			gts_permit;
	u8			lqi;
	u32			timestamp; /* FIXME */
	bool			security;
	u8			mac_sec;
	bool			sec_fail;
};

int parse_beacon_frame(struct sk_buff *skb, u8 * buf,
		int *flags, struct list_head *al);

int ieee80215_send_beacon(struct net_device *dev, struct ieee80215_addr *saddr,
		u16 pan_id, const u8 *buf, int len,
		int flags, struct list_head *al);

#endif /* IEEE80215_BEACON_H */


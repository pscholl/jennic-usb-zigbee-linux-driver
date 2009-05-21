/*
 * IEEE 802.15.4 inteface for userspace
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

#ifndef _AF_IEEE80215_H
#define _AF_IEEE80215_H

#include <linux/socket.h> /* for sa_family_t */

enum {
	IEEE80215_ADDR_NONE = 0x0,
	/* RESERVED = 0x01, */
	IEEE80215_ADDR_SHORT = 0x2, /* 16-bit address + PANid */
	IEEE80215_ADDR_LONG = 0x3, /* 64-bit address + PANid */
};

/* address length, octets */
#define IEEE80215_ADDR_LEN	8

struct ieee80215_addr {
	int addr_type;
	u16 pan_id;
	union {
		u8 hwaddr[IEEE80215_ADDR_LEN];
		u16 short_addr;
	};
};

struct sockaddr_ieee80215 {
	sa_family_t family; /* AF_IEEE80215 */
	struct ieee80215_addr addr;
};

/* master device */
#define IEEE80215_SIOC_ADD_SLAVE		(SIOCDEVPRIVATE + 0)

#ifdef __KERNEL__
#include <linux/skbuff.h>
#include <linux/netdevice.h>
extern struct proto ieee80215_raw_prot;
extern struct proto ieee80215_dgram_prot;
void ieee80215_raw_deliver(struct net_device *dev, struct sk_buff *skb);
int ieee80215_dgram_deliver(struct net_device *dev, struct sk_buff *skb);
#endif

#endif

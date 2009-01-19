/*
 * IEEE80215.4 net device
 *
 * Copyright 2008 Siemens AG
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

#ifndef IEEE80215_MAC_CMD_H
#define IEEE80215_MAC_CMD_H

int ieee80215_process_cmd(struct net_device *dev, struct sk_buff *skb);

int ieee80215_send_cmd(struct net_device *dev, struct ieee80215_addr *addr,
		const u8 *buf, int len);

/* MAC's Command Frames Identifiers */
#define IEEE80215_CMD_ASSOCIATION_REQ		0x01
#define IEEE80215_CMD_ASSOCIATION_RESP		0x02
#define IEEE80215_CMD_DISASSOCIATION_NOTIFY	0x03
#define IEEE80215_CMD_DATA_REQ			0x04
#define IEEE80215_CMD_PANID_CONFLICT_NOTIFY	0x05
#define IEEE80215_CMD_ORPHAN_NOTIFY		0x06
#define IEEE80215_CMD_BEACON_REQ		0x07
#define IEEE80215_CMD_COORD_REALIGN_NOTIFY	0x08
#define IEEE80215_CMD_GTS_REQ			0x09

#endif

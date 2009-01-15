/*
 * IEEE802.15.4-2003 specification
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
 * Maxim Osipov <maxim.osipov@siemens.com>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#ifndef IEEE80215_MAC_DEF_H
#define IEEE80215_MAC_DEF_H

#define IEEE80215_PANID_BROADCAST	0xffff
#define IEEE80215_ADDR_BROADCAST	0xffff
#define IEEE80215_ADDR_UNDEF		0xfffe

#define IEEE80215_FC_TYPE_BEACON	0x0	/* Frame is beacon */
#define	IEEE80215_FC_TYPE_DATA		0x1	/* Frame is data */
#define IEEE80215_FC_TYPE_ACK		0x2	/* Frame is acknowledgment */
#define IEEE80215_FC_TYPE_MAC_CMD	0x3	/* Frame is MAC command */

#define IEEE80215_FC_TYPE_SHIFT		0
#define IEEE80215_FC_TYPE_MASK		((1 << 3) - 1)
#define IEEE80215_FC_TYPE(x) 		((x & IEEE80215_FC_TYPE_MASK) >> IEEE80215_FC_TYPE_SHIFT)
#define IEEE80215_FC_SET_TYPE(v, x)	do {v = (((v) & ~IEEE80215_FC_TYPE_MASK) | \
						(((x) << IEEE80215_FC_TYPE_SHIFT) \
						& IEEE80215_FC_TYPE_MASK));} while(0)

#define IEEE80215_FC_SECEN		(1 << 3)
#define IEEE80215_FC_FRPEND		(1 << 4)
#define IEEE80215_FC_ACK_REQ		(1 << 5)
#define IEEE80215_FC_INTRA_PAN		(1 << 6)

#define IEEE80215_FC_SAMODE_SHIFT	14
#define IEEE80215_FC_SAMODE_MASK	(3 << IEEE80215_FC_SAMODE_SHIFT)
#define IEEE80215_FC_DAMODE_SHIFT	10
#define IEEE80215_FC_DAMODE_MASK	(3 << IEEE80215_FC_DAMODE_SHIFT)

#define IEEE80215_FC_SAMODE(x)		\
		(((x) & IEEE80215_FC_SAMODE_MASK) >> IEEE80215_FC_SAMODE_SHIFT)

#define IEEE80215_FC_DAMODE(x)		\
		(((x) & IEEE80215_FC_DAMODE_MASK) >> IEEE80215_FC_DAMODE_SHIFT)

#endif



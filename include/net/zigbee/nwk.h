/*
 * Definitions of ZigBEE NWK
 *
 * Copyright 2009 Siemens AG
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
 * Maxim Yu. Osipov  <Maksim.Osipov@siemens.com>
 */
#ifndef _NET_ZIGBEE_NWK_H
#define _NET_ZIGBEE_NWK_H
#include <linux/types.h>
#include <asm/byteorder.h>

/*
 * The General NWK frame format:
 * NWK header (8):
 *  Name Length (in octets) Value
 *  ---- ------------------ -----
 *  Frame Control       (2) See below
 *  Destination Address (2) Same as IEEE 802.15.4 MAC short address
 *  Source Address      (2) Same as IEEE 802.15.4 MAC short address
 *  Radius              (1) Range of a radius transmission
 *  Sequence Number     (1)
 * NWK Payload:
 *
 * Data Frame:
 *  Name     Length (in octets)
 *  ----     ------------------
 *  Payload  (variable)
 *
 * Command Frame:
 *  Name       Length (in octets)
 *  ----       ------------------
 *  Command id (1)
 *  Payload    (variable)
 *
 * Frame Control Fields:
 * bit   Subfield         Value
 * ---   --------         -----
 * 0-1   Frame Type       <Data/Command>
 * 2-5   Protocol Version 0x1
 * 6-7   Discover Route   <Supress/Enable/Force>
 * 9     Security         <Enabled/Disabled>
 * 10-15 Reserved
 *
 *
*/
struct nwkhdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	reserved2:6,
		security:1,
		reserved1:1,
		disc_route:2,
  		version:4,
		type:2;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u16	type:2,
  		version:4,
		disc_route:2,
		reserved1:1,
		security:1,
		reserved2:6;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__be16	daddr;
	__be16	saddr;
	__u8	radius;
	__u8	seqnum;
};

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct nwkhdr *nwk_hdr(const struct sk_buff *skb)
{
	return (struct nwkhdr *)skb_network_header(skb);
}
#endif

#endif /* _NET_ZIGBEE_NWK_H */

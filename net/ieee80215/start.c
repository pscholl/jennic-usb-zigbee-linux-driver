/*
 * MLME START
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
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/mac_def.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/nl.h>

int ieee80215_mlme_start_req(struct net_device *dev, u16 panid, u8 channel,
			     u8 bcn_ord, u8 sf_ord, u8 pan_coord, u8 blx,
			     u8 coord_realign, u8 sec)
{
	ieee80215_set_pan_id(dev, panid);
	if (pan_coord) {
		dev->priv_flags |= IFF_IEEE80215_COORD;
	} else {
		dev->priv_flags &= ~IFF_IEEE80215_COORD;
	}
	return 0;
}


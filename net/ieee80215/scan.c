/*
 * scan.c
 *
 * Description: MAC scan helper functions.
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

#include <net/ieee80215/mac_struct.h>
#include <net/ieee80215/dev.h>

/**
 * @brief MLME-SAP.Scan request
 *
 * Alloc ed_detect list for ED scan.
 *
 * @param mac current mac pointer
 * @param type type of the scan to be performed
 * @param channels 32-bit mask of requested to scan channels
 * @param duration scan duration, see ieee802.15.4-2003.pdf, page 145.
 * @return 0 if request is ok, errno otherwise.
 */
int ieee80215_mlme_scan_req(struct net_device *dev, u8 type, u32 channels, u8 duration)
{
	struct ieee80215_mac *mac = ieee80215_get_mac_bydev(dev);
	pr_debug("scanning type=%d cnannels=%d duration=%d\n", type, channels, duration);
	switch (mac->state) {
	case PEND_AS:
	case PEND_AS1:
	case PEND_PS:
	case PEND_OS:
	case PEND_OS1:
	case PEND_ED:
		scanning = 1;
		break;
	default:
		scanning = 0;
		break;
	}
	if(scanning) {
		pr_debug("Scan request while scan in progress\n");
		return -EBUSY;
	}
	if(!channels) {
		pr_debug("Nothing to scan");
		return -EINVAL;
	}
	ieee80215_clear_scan(mac);
	mac->scan.type = type;
	mac->scan.duration = duration;
	mac->scan.status = IEEE80215_IDLE;	/* Before scan */
	mac->scan.unscan_ch = channels;
	mac->f.find_a_beacon = false;
	mac->i.original_channel = mac->i.current_channel;

	switch (type) {
	case IEEE80215_SCAN_ED:
		mac->scan.ed_detect_list = kzalloc(32*sizeof(u8), GFP_KERNEL);
		if (mac->scan.ed_detect_list) {
			ieee80215_ed_scan(mac);
		} else {
			pr_info("Unable to alloc mem->scan.ed_list\n");
			return -ENOMEM;
		}
		break;
	case IEEE80215_SCAN_ACTIVE:
		mac->f.find_a_beacon = false;
		ieee80215_active_scan(mac);
		break;
	case IEEE80215_SCAN_PASSIVE:
		ieee80215_passive_scan(mac);
		break;
	case IEEE80215_SCAN_ORPHAN:
		mac->f.find_a_coord_realign = false;
		ieee80215_orphan_scan(mac);
		break;
	default:
		pr_info("Unknown scan type\n");
		return -EINVAL;
	}
	return 0;
}


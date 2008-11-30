/*
 * ieee80215_mac_scan.c
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

#include <linux/bitmap.h>
#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/const.h>
#include <net/ieee80215/mac_scan.h>

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
int ieee80215_mlme_scan_req(ieee80215_mac_t *mac, u8 type, u32 channels, u8 duration)
{
	u8 scanning;

#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, 0, DBG_INFO,
		"type = %d, channels = 0x%x, duration = %d\n",
		type, channels, duration);

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

	if (scanning) {
		dbg_print(mac, 0, DBG_INFO, "Scan request while scan in progress\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_scan_confirm(_nhle(mac), IEEE80215_SCAN_IN_PROGRESS,
			type, channels, 0, NULL, &mac->scan.desc);
#endif
		return 0;
	}

	if (!channels) {
		dbg_print(mac, SCAN, DBG_INFO, "Channel list to scan is empty\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_scan_confirm(_nhle(mac), IEEE80215_INVALID_PARAM,
			type, channels, 0, NULL, &mac->scan.desc);
#endif
		return 0;
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
			dbg_print(mac, 0, DBG_ERR, "Unable to alloc mem->scan.ed_list\n");
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mlme_scan_confirm(_nhle(mac), IEEE80215_INVALID_PARAM,
				type, channels, 0, NULL, &mac->scan.desc);
#endif
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
		dbg_print(mac, SCAN, DBG_ERR, "Unknown scan type\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_scan_confirm(_nhle(mac), IEEE80215_INVALID_PARAM,
			type, channels, 0, NULL, &mac->scan.desc);
#endif
		break;
	}
	return 0;
}

ieee80215_pan_desc_t *
ieee80215_find_pan_desc(ieee80215_mac_t *mac, ieee80215_pan_desc_t *pdesc)
{
	ieee80215_pan_desc_t *desc = NULL;
	struct list_head *it;

	if (!pdesc) {
		dbg_print(mac, 0, DBG_ERR_CRIT, "Wrong params: 0x%p, 0x%p\n",
			  mac, pdesc);
		return NULL;
	}

	spin_lock(&mac->scan.desc.lock);

	dbg_print(mac, 0, DBG_INFO,
		"mac->scan.desc.count = %u, pdesc->coord_mode = %u, pdesc->coord_addr.panid = %u\n",
		mac->scan.desc.count, pdesc->coord_mode, pdesc->coord_addr.panid);
	switch (pdesc->coord_mode) {
	case IEEE80215_AMODE_16BIT:
		dbg_print(mac, 0, DBG_INFO, "pdesc->coord_addr._16bit = 0x%x\n",
			pdesc->coord_addr._16bit);
		break;
	case IEEE80215_AMODE_64BIT:
		dbg_print(mac, 0, DBG_INFO, "pdesc->coord_addr._64bit = 0x%llx\n",
			pdesc->coord_addr._64bit);
		break;
	default:
		dbg_print(mac, 0, DBG_ERR, "Unexpected addr mode\n");
		BUG();
		break;
	}

	if (!mac->scan.desc.count) {
		dbg_print(mac, 0, DBG_INFO, "PAN descriptor list is empty\n");
		goto exit_unlock;
	}
	list_for_each(it, &mac->scan.desc.list) {
		desc = container_of(it, ieee80215_pan_desc_t, list);
		dbg_print(mac, 0, DBG_INFO,
			"desc->coord_mode = %u, desc->coord_addr.panid = %u\n",
			desc->coord_mode, desc->coord_addr.panid);
		if (desc->coord_addr.panid == pdesc->coord_addr.panid) {
			switch (pdesc->coord_mode) {
			case IEEE80215_AMODE_16BIT:
				dbg_print(mac, 0, DBG_INFO, "desc->coord_addr._16bit = 0x%x\n",
					desc->coord_addr._16bit);
				if (desc->coord_addr._16bit == pdesc->coord_addr._16bit) {
					dbg_print(mac, 0, DBG_INFO,
						"beacon already recorded\n");
					goto exit_unlock;
				}
				break;
			case IEEE80215_AMODE_64BIT:
				dbg_print(mac, 0, DBG_INFO, "desc->coord_addr._64bit = 0x%llx\n",
					desc->coord_addr._64bit);
				if (desc->coord_addr._64bit == pdesc->coord_addr._64bit) {
					dbg_print(mac, 0, DBG_INFO,
						"beacon already recorded\n");
					goto exit_unlock;
				}
				break;
			default:
				dbg_print(mac, 0, DBG_ERR, "Unexpected addr mode\n");
				BUG();
				break;
			}
		}
		desc = NULL;
	}

exit_unlock:
	spin_unlock(&mac->scan.desc.lock);
	return desc;
}

int ieee80215_add_pan_desc(ieee80215_mac_t *mac, ieee80215_pan_desc_t *pdesc)
{
	int ret;

	if (!pdesc) {
		dbg_print(mac, BEACON, DBG_ERR_CRIT, "Wrong params: 0x%p, 0x%p\n",
			   mac, pdesc);
		return -EINVAL;
	}
	switch (pdesc->coord_mode) {
		case IEEE80215_AMODE_16BIT:
		case IEEE80215_AMODE_64BIT:
			break;
		default:
			dbg_print(mac, BEACON, DBG_ERR,
				  "Unexpected coordinator address mode\n");
			return -EINVAL;
			break;
	}
	spin_lock(&mac->scan.desc.lock);
	list_add_tail(&pdesc->list, &mac->scan.desc.list);
	mac->scan.desc.count++;
	ret = mac->scan.desc.count;
	spin_unlock(&mac->scan.desc.lock);
	dbg_print(mac, 0, DBG_INFO, "mac->scan.desc.count = %u\n", ret);
	return ret;
}

int ieee80215_remove_pan_desc(ieee80215_mac_t *mac, ieee80215_pan_desc_t *pdesc)
{
	int ret;
	if (!pdesc) {
		dbg_print(mac, BEACON, DBG_ERR_CRIT, "Wrong params: 0x%p, 0x%p\n",
			   mac, pdesc);
		return -EINVAL;
	}

	if (!mac->scan.desc.count) {
		dbg_print(mac, BEACON, DBG_ERR, "PANDescriptor list is empty\n");
		return -EINVAL;
	}
	spin_lock(&mac->scan.desc.lock);
	list_del(&pdesc->list);
	mac->scan.desc.count--;
	ret = mac->scan.desc.count;
	spin_unlock(&mac->scan.desc.lock);

	return ret;
}

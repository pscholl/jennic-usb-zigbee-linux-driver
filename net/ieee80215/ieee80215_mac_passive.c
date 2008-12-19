/*
 * ieee80215_passive.c
 *
 * Description: MAC passive scan helper functions.
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
#include <net/ieee80215/netdev.h>

static void passive_scan_end_one(ieee80215_mac_t *mac)
{
	mark_channel_scanned(&mac->scan);
	ieee80215_passive_scan(mac);
}

static void passive_scan_timeout(struct work_struct *work)
{
	ieee80215_scan_t *scan = container_of(work, ieee80215_scan_t, work.work);
	ieee80215_mac_t *mac = container_of(scan, ieee80215_mac_t, scan);

#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, 0, DBG_INFO, "Finalizing PS iteration\n");
	cancel_delayed_work(&mac->scan.work);
	ieee80215_net_set_trx_state(mac, IEEE80215_TRX_OFF, passive_scan_end_one);
}

static void await_beacons(ieee80215_mac_t *mac)
{
	ieee80215_adjust_symbol_duration(mac);
	PREPARE_DELAYED_WORK(&mac->scan.work, passive_scan_timeout);
	ieee80215_set_beacon_scan_interval(mac);
	dbg_print(mac, 0, DBG_INFO, "wait beacons %u jiffies\n", mac->scan.scan_time);
	mac->scan.delta_scan = 0;
	mac->scan.start_scan = jiffies;
	schedule_delayed_work(&mac->scan.work, mac->scan.scan_time);
}

static void start_passive_scan(struct ieee80215_mac *mac);

/**
 * @brief PLME-SAP set_request confirm
 *
 * Called by phy in order to perform set_request confirm.
 * If return code is SUCCESS, init duration timer and perform beacon_request.
 *
 * @param mac pointer to current mac
 * @param code set confirm code, @see ieee80215_rcodes.
 * @param attr requested to set attribute
 */
static int passive_set_channel_confirm(struct ieee80215_mac *mac, int code, ieee80215_plme_pib_t *attr)
{
	if (code == IEEE80215_PHY_SUCCESS
		&& attr->attr_type == IEEE80215_PHY_CURRENT_CHANNEL
		&& attr->attr.curr_channel == mac->scan.current_channel) {
		dbg_print(mac, 0, DBG_INFO, "set channel: done\n");
		ieee80215_net_set_trx_state(mac, IEEE80215_RX_ON, await_beacons);
	} else {
		dbg_print(mac, 0, DBG_ERR, "set channel failed, retry\n");
		start_passive_scan(mac);
	}
	return 0;
}

/**
 * @brief Begin of active scan algorithm
 *
 * First it is necessary to set CURRENT_CHANNEL to desired one for scanning by
 * issuing set_request to phy.
 *
 * @param mac pointer to current mac
 */
static void start_passive_scan(struct ieee80215_mac *mac)
{
	ieee80215_plme_pib_t attr;

	attr.attr_type = IEEE80215_PHY_CURRENT_CHANNEL;
	attr.attr.curr_channel = mac->scan.current_channel;
	mac->plme_set_confirm = passive_set_channel_confirm;
	mac->phy->plme_set_request(mac->phy, attr);
}

/**
 * @brief Passive scan start point.
 *
 * Save current macPANId, set macPANId to 0xffff to accept all beacons.
 * Disable data_indication during ed scan. Get unscanned channel,
 * send RX_ON request to NLME-SAP. If all channels were scanned, confirm
 * scan to NHLE-SAP.
 *
 * @param mac pointer to current mac
 */
int ieee80215_passive_scan(struct ieee80215_mac *mac)
{
	int ch;

	ch = get_curr_channel(&mac->scan);
	if (ch == -1 || mac->scan.desc.count == 7/*IEEE80215_PDESC_LIMIT*/) {
		dbg_print(mac, 0, DBG_INFO, "Passive scan is done\n");
		if (mac->f.find_a_beacon) {
			mac->scan.status = IEEE80215_SUCCESS;
		} else {
			mac->scan.status = IEEE80215_NO_BEACON;
		}
		ieee80215_set_pib(mac, IEEE80215_PANID, &mac->scan.tmp_panid);
		switch (mac->original_state) {
		case WAIT:
			ieee80215_set_state(mac, ZP);
			break;
		case ACTIVE:
			ieee80215_restore_state(mac);
			break;
		default:
			dbg_print(mac, 0, DBG_ERR,
				"finishing PS in not right state\n");
			break;
		}
		/* restore saved panid: */
		write_lock(&mac->pib.lock);
		mac->pib.dev_addr.panid = mac->scan.tmp_panid;
		write_unlock(&mac->pib.lock);

#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_scan_confirm(_nhle(mac),
			mac->scan.status,
			mac->scan.type,
			mac->scan.unscan_ch,
			mac->scan.result_size,
			mac->scan.ed_detect_list,
			&mac->scan.desc);
#endif
	} else {
		if (mac->state != PEND_PS) {
			dbg_print(mac, 0, DBG_INFO, "Passive scan first iteration\n");
			ieee80215_set_state(mac, PEND_PS);
			/* to receive all beacons: */
			write_lock(&mac->pib.lock);
			mac->scan.tmp_panid = mac->pib.dev_addr.panid;
			mac->pib.dev_addr.panid = 0xffff;
			write_unlock(&mac->pib.lock);
		}
		mac->scan.current_channel = ch;
		mac->i.current_channel = ch;
		start_passive_scan(mac);
	}
	return 0;
}


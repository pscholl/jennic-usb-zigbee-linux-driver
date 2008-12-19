/*
 * ieee80215_ed.c
 *
 * Description: MAC ED scan helper functions.
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
#include <net/ieee80215/mac.h>
#include <net/ieee80215/const.h>
#include <net/ieee80215/mac_scan.h>
#include <net/ieee80215/netdev.h>

static void ed_measure_end(ieee80215_mac_t *mac)
{
	u8 ch = mac->scan.current_channel;

	if (mac->scan.status) {
		if (mac->scan.ed_detect_list[ch] < ZB_ED_EDGE) {
			set_bit(ch, (unsigned long *)&mac->scan.channels_below_threshold);
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
			dbg_print(mac, SCAN_ED, DBG_INFO,
				"channel %d seems to be free: energy level is 0x%x\n",
				ch, mac->scan.ed_detect_list[ch]);
			dbg_print(mac, SCAN_ED, DBG_INFO, "updated channels_below_threshold: 0x%x\n",
				mac->scan.channels_below_threshold);
		} else {
			dbg_print(mac, SCAN_ED, DBG_INFO,
				"channel %d seems to be busy: energy level is 0x%x\n",
				ch, mac->scan.ed_detect_list[ch]);
		}
	} else {
		dbg_print(mac, SCAN_ED, DBG_ERR, "failed to scan channel %d\n", ch);
	}

	mac->i.current_channel = mac->i.original_channel;
	mark_channel_scanned(&mac->scan);
	ieee80215_ed_scan(mac);
}

/**
 * @brief PLME-SAP ed_request confirm entry
 *
 * Called by phy in order to confirm ed_request. As we do several ed requests
 * on dedicated channel, only maximum ed value is recorded. If scan is near to
 * duration limit, do not perform ed request anymore. The approximate nature
 * to duration limit is called as delta between delayed work expiration value
 * and current jiffies value. If delta is less than ed request/confirm time
 * ed requests is not performed anymore.
 *
 * @param mac current mac pointer
 * @param code ed request confirm code, @see ieee80215_rcodes
 * @param ret ed mesurement value
 */
static int ieee80215_plme_ed_iter(struct ieee80215_mac *mac, int code, int ret)
{
	if (IEEE80215_PHY_SUCCESS == code) {
		mac->scan.status = 1; /* current channel scan success */
		mac->scan.ed_detect_list[mac->scan.current_channel] =
			max((u8)ret, (u8)mac->scan.ed_detect_list[mac->scan.current_channel]);
	}

	/* duration period is not over? run again */
	if (jiffies - mac->scan.start_scan < mac->scan.scan_time) {
		mac->phy->plme_ed_request(mac->phy);
	} else {
		dbg_print(mac, 0, DBG_INFO, "channel %u scan is finished\n",
			mac->scan.current_channel);
		ieee80215_net_set_trx_state(mac, IEEE80215_TRX_OFF, ed_measure_end);
	}
	return 0;
}

static void ed_measure_start(ieee80215_mac_t *mac)
{
	ieee80215_adjust_symbol_duration(mac);
	mac->scan.delta_scan = 0;
	mac->scan.status = 0; /* current channel scan is not done */
	mac->scan.start_scan = jiffies;
	ieee80215_set_beacon_scan_interval(mac);
	mac->plme_ed_confirm = ieee80215_plme_ed_iter;
	mac->phy->plme_ed_request(mac->phy);
}

/**
 * @brief PLME-SAP set_request confirm
 *
 * Called by phy in order to perform set_request confirm.
 * If return code is SUCCESS, init duration timer and perform ed_request to phy.
 *
 * @param mac pointer to current mac
 * @param code set confirm code, @see ieee80215_rcodes.
 * @param attr requested to set attribute
 */
static int ieee80215_ed_pend(ieee80215_mac_t *mac, int code, ieee80215_plme_pib_t *attr)
{
	if (code == IEEE80215_PHY_SUCCESS
		&& attr->attr_type == IEEE80215_PHY_CURRENT_CHANNEL
		&& attr->attr.curr_channel == mac->scan.current_channel) {
		ieee80215_net_set_trx_state(mac, IEEE80215_RX_ON, ed_measure_start);
		return 0;
	}
	dbg_print(mac, 0, DBG_ERR, "PHY set request failed, going to next channel\n");
	mark_channel_scanned(&mac->scan);
	ieee80215_ed_scan(mac);
	return 0;
}

static void _ed_done(ieee80215_mac_t *mac)
{
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_scan_confirm(_nhle(mac), mac->scan.status,
		mac->scan.type, mac->scan.unscan_ch, mac->scan.result_size,
		mac->scan.ed_detect_list, &mac->scan.desc);
#endif
	kfree(mac->scan.ed_detect_list);
	mac->scan.ed_detect_list = NULL;
}

/**
 * @brief ED scan start point.
 *
 * Disable data_indication during ed scan. Get unscanned channel,
 * send RX_ON request to NLME-SAP. If all channels were scanned, confirm
 * scan to NHLE-SAP.
 *
 * @param mac pointer to current mac
 */
int ieee80215_ed_scan(struct ieee80215_mac *mac)
{
	int ch;
	ieee80215_plme_pib_t attr;

	ieee80215_set_state(mac, PEND_ED);

	ch = get_curr_channel(&mac->scan);
	if (ch == -1) {
		/* end of channel scanning */
		dbg_print(mac, SCAN_ED, DBG_ALL, "Channel list end\n");
		ieee80215_restore_state(mac);
		mac->scan.status = IEEE80215_SUCCESS;
		if (ieee80215_should_rxon(mac)) {
			ieee80215_net_set_trx_state(mac, IEEE80215_RX_ON, _ed_done);
		} else {
			_ed_done(mac);
		}
		return 0;
	}

	dbg_print(mac, SCAN_ED, DBG_ALL, "Channel: %d\n", ch);

	mac->scan.current_channel = ch;
	mac->i.current_channel = ch;

	attr.attr_type = IEEE80215_PHY_CURRENT_CHANNEL;
	attr.attr.curr_channel = mac->scan.current_channel;
	mac->plme_set_confirm = ieee80215_ed_pend;
	mac->phy->plme_set_request(mac->phy, attr);
	return 0;
}


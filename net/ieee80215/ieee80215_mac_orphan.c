/*
 * ieee80215_orphan.c
 *
 * Description: MAC orphan scan helper functions.
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
#include <net/ieee80215/lib.h>
#include <net/ieee80215/const.h>
#include <net/ieee80215/mac_scan.h>
#include <net/ieee80215/beacon.h>

static void ieee80215_orphan_iter_next(ieee80215_mac_t *mac)
{
	mark_channel_scanned(&mac->scan);
	ieee80215_orphan_scan(mac);
	return;
}

static void ieee80215_orphan_scan_iter_end(struct work_struct *work)
{
	ieee80215_scan_t *scan = container_of(work, ieee80215_scan_t, work.work);
	ieee80215_mac_t *mac = container_of(scan, ieee80215_mac_t, scan);

#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, SCAN_ORPHAN, DBG_INFO, "Finalizing OS iteration\n");
	cancel_delayed_work(&mac->scan.work);
	set_trx_state(mac, IEEE80215_TRX_OFF, ieee80215_orphan_iter_next);
}

static void ieee80215_orphan_await_orphan(ieee80215_mac_t *mac)
{
	dbg_print(mac, SCAN_ORPHAN, DBG_INFO, "RX_ON is on, waiting beacons\n");
	PREPARE_DELAYED_WORK(&mac->scan.work, ieee80215_orphan_scan_iter_end);
	ieee80215_adjust_symbol_duration(mac);
	ieee80215_set_beacon_scan_interval(mac);
	mac->scan.delta_scan = 0;
	mac->scan.start_scan = jiffies;
	schedule_delayed_work(&mac->scan.work, mac->scan.scan_time);
}

static int ieee80215_orphan_scan_confirm(void *obj, struct sk_buff *skb, int code)
{
	struct ieee80215_mac *mac = obj;

	dbg_print(mac, SCAN_ORPHAN, DBG_INFO, "code = 0x%x\n", code);
	if (IEEE80215_PHY_SUCCESS == code) {
		dbg_print(mac, SCAN_ORPHAN, DBG_INFO, "set RX_ON\n");
		set_trx_state(mac, IEEE80215_RX_ON, ieee80215_orphan_await_orphan);
	} else {
		ieee80215_orphan_iter_next(mac);
	}
	return 0;
}

static void ieee80215_orphan_mesure_start(struct ieee80215_mac *mac)
{
	ieee80215_mpdu_t *mpdu;

	mpdu = ieee80215_create_orphan_cmd(mac);
	if (!mpdu) {
		dbg_print(mac, SCAN_ORPHAN, DBG_ERR, "unable to create orphan notification\n");
		ieee80215_orphan_iter_next(mac);
		return;
	}
	mpdu->on_confirm = ieee80215_orphan_scan_confirm;
	skb_queue_head(&mac->to_network, mpdu_to_skb(mpdu));
	/*mac->phy->pd_data_request(mac->phy, mpdu_to_skb(mpdu));*/
	ieee80215_csma_ca_start(mac);
}

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
static int ieee80215_orphan_pend(struct ieee80215_mac *mac, int code,
	ieee80215_plme_pib_t *attr)
{
	if (code == IEEE80215_PHY_SUCCESS
		&& attr->attr_type == IEEE80215_PHY_CURRENT_CHANNEL
		&& attr->attr.curr_channel == mac->scan.current_channel) {
		dbg_print(mac, SCAN_ORPHAN, DBG_INFO, "Orphan pending, set complete, enabling rx\n");
		set_trx_state(mac, IEEE80215_TX_ON, ieee80215_orphan_mesure_start);
		return 0;
	}
	dbg_print(mac, SCAN_ORPHAN, DBG_ERR, "PHY set request failed, going to next channel\n");
	ieee80215_orphan_iter_next(mac);
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
static void ieee80215_orphan_start_scan(struct ieee80215_mac *mac)
{
	ieee80215_plme_pib_t attr;

	attr.attr_type = IEEE80215_PHY_CURRENT_CHANNEL;
	attr.attr.curr_channel = mac->scan.current_channel;
	mac->plme_set_confirm = ieee80215_orphan_pend;
	mac->phy->plme_set_request(mac->phy, attr);
}

static void ieee80215_orphan_scan_end(ieee80215_mac_t *mac)
{
	ieee80215_set_pib(mac, IEEE80215_PANID, (u8*)&mac->scan.tmp_panid);
	ieee80215_restore_state(mac);
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_scan_confirm(_nhle(mac), mac->scan.status,
		mac->scan.type, mac->scan.unscan_ch,
		mac->scan.result_size,
		mac->scan.ed_detect_list,
		&mac->scan.desc);
#endif
}

/**
 * @brief Orphan scan start point.
 *
 * Save current macPANId, set macPANId to 0xffff to accept all beacons.
 * Disable data_indication during ed scan. Get unscanned channel,
 * send RX_ON request to NLME-SAP. If all channels were scanned, confirm
 * scan to NHLE-SAP.
 *
 * @param mac pointer to current mac
 */
int ieee80215_orphan_scan(struct ieee80215_mac *mac)
{
	int ch;

	ch = get_curr_channel(&mac->scan);
	if(ch == -1 || mac->f.find_a_coord_realign) {
		dbg_print(mac, SCAN_ORPHAN, DBG_INFO, "Orphan scan is complete, cleanuping\n");
		if (!mac->f.find_a_coord_realign)
			mac->scan.status = IEEE80215_NO_BEACON;
		set_trx_state(mac, IEEE80215_TRX_OFF, ieee80215_orphan_scan_end);
		return 0;
	}

	if (PEND_OS != mac->state) {
		/* first iteration */
		ieee80215_set_state(mac, PEND_OS);
	}
	mac->scan.current_channel = ch;
	mac->i.current_channel = ch;
	ieee80215_orphan_start_scan(mac);
	return 0;
}


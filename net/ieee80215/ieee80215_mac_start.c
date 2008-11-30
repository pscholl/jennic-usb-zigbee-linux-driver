/*
 * ieee80215_mac_start.c
 *
 * Description: MAC Start helper functions.
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
#include <net/ieee80215/beacon.h>

static void ieee80215_start_await(ieee80215_mac_t *mac)
{
	struct sk_buff *skb;

	skb = skb_peek(&mac->to_network);
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, START, DBG_INFO, "send beacon\n");
	/*mac->phy->pd_data_request(mac->phy, skb);*/
	ieee80215_csma_ca_start(mac);
}

static void start_confirm(ieee80215_mac_t *mac)
{
	ieee80215_set_state(mac, ACTIVE);
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_SUCCESS);
#endif
}

static int ieee80215_start_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;
	u32 btx;

	dbg_print(mac, START, DBG_INFO, "code = 0x%x\n", code);

	if (code != IEEE80215_PHY_SUCCESS) {
		dbg_print(mac, START, DBG_ERR, "Unable to transmit data\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), code);
#endif
		return 0;
	}

	PREPARE_DELAYED_WORK(&mac->bwork, ieee80215_superframe_end);
	ieee80215_set_pib(mac, IEEE80215_BEACON_TX_TIME, (void*)&jiffies);
	schedule_delayed_work(&mac->bwork, mac->sf_time);

	ieee80215_bsn_inc(mac);
	dbg_print(mac, START, DBG_INFO, "Beacon has been sent\n");

	ieee80215_get_pib(mac, IEEE80215_BEACON_TX_TIME, &btx);
	if ((jiffies - btx) < mac->totaltime) {
		dbg_print(mac, START, DBG_INFO, "there are slots after beacon\n");
		set_trx_state(mac, IEEE80215_RX_ON, start_confirm);
	} else {
		dbg_print(mac, START, DBG_INFO, "After beacon no slots left\n");
		start_confirm(mac);
	}
	return 0;
}

static int ieee80215_start_pend(ieee80215_mac_t *mac, int code, ieee80215_plme_pib_t *attr)
{
	ieee80215_mpdu_t *mpdu;

	if (attr->attr_type != IEEE80215_PHY_CURRENT_CHANNEL
		|| attr->attr.curr_channel != mac->i.current_channel
		|| code != IEEE80215_PHY_SUCCESS) {
		dbg_print(mac, START, DBG_ERR, "PHY set request failed\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), code);
#endif
		return 0;
	}

	ieee80215_set_beacon_interval(mac);
	ieee80215_set_superframe_params(mac);

	if (mac->f.sec_enable) {
		/* TODO */
	}

	if (mac->pib.superframe_order == 0xf) {
		dbg_print(mac, START, DBG_INFO, "starting beaconless network\n");
		set_trx_state(mac, IEEE80215_RX_ON, start_confirm);
		return 0;
	}

	dbg_print(mac, START, DBG_INFO, "Beacon enabled network\n");

	if (mac->pib.beacon_tx_time) {
		dbg_print(mac, START, DBG_INFO,
			"Mac is already transmiting a beacon defer till next sf\n");
		return 0;
	}

	mpdu = ieee80215_create_beacon(mac);
	if (!mpdu) {
		dbg_print(mac, START, DBG_ERR, "Unable to create beacon\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_FRAME_TOO_LONG);
#endif
		return 0;
	}
	mpdu->on_confirm = ieee80215_start_confirm;
	mpdu->use_csma_ca = 0;
	skb_queue_head(&mac->to_network, mpdu_to_skb(mpdu));
	set_trx_state(mac, IEEE80215_TX_ON, ieee80215_start_await);
	return 0;
}

static void ieee80215_start_a_pan(ieee80215_mac_t *mac)
{
	ieee80215_plme_pib_t attr;

	attr.attr_type = IEEE80215_PHY_CURRENT_CHANNEL;
	attr.attr.curr_channel = mac->i.current_channel;

	mac->plme_set_confirm = ieee80215_start_pend;
	mac->phy->plme_set_request(mac->phy, attr);
}

static int ieee80215_start_realign_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;

	if (code == IEEE80215_PHY_SUCCESS) {
		dbg_print(mac, START, DBG_INFO, "Realign broadcasted, realign a PAN\n");
		ieee80215_start_a_pan(mac);
	} else {
		dbg_print(mac, START, DBG_ERR, "Unable to broadcast realign\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), code);
#endif
	}
	return 0;
}

int ieee80215_mlme_start_req(ieee80215_mac_t *mac, u16 pan_id, u8 lch, u8 b_order,
	u8 s_order, bool pan_coord, bool bat_life_ext, bool realign, bool sec_enable)
{
	if (lch > 26) {
		dbg_print(mac, START, DBG_ERR,
			"channel must be in range of 0..26, while %d supplied\n", lch);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	if (b_order > 15) {
		dbg_print(mac, START, DBG_ERR,
			"Beacon order must be in range of 0..15, while %d supplied\n", b_order);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	if (s_order > 15) {
		dbg_print(mac, START, DBG_ERR,
			"Superframe order must be in range of 0..15, while %d supplied\n", s_order);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	if (s_order > b_order) {
		dbg_print(mac, START, DBG_ERR,
			"Superframe order must be less than a beacon order: %d %d\n", s_order, b_order);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	if (mac->pib.dev_addr._16bit == 0xffff) {
		dbg_print(mac, START, DBG_ERR, "No short address specified\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_NO_SHORT_ADDRESS);
#endif
		return 0;
	}

	if (realign) {
		ieee80215_mpdu_t *msg;

		if (!mac->i.i_pan_coord) {
			dbg_print(mac, START, DBG_ERR, "Realign on non-started PAN\n");
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mlme_start_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
			return 0;
		}

		dbg_print(mac, START, DBG_INFO, "Changing params of a PAN,"
			" pan_id: %d, bo: %d, so: %d, sec: %d, ble: %d\n",
			pan_id, b_order, s_order, sec_enable, bat_life_ext);

		mac->i.bo = b_order;
		mac->i.sfo = s_order;
		if (pan_coord) {
			mac->i.panid = pan_id;
			mac->i.original_channel = lch;
		}
		mac->f.sec_enable = sec_enable;

		msg = ieee80215_create_realign_cmd(mac, NULL, lch);
		if (!msg) {
			dbg_print(mac, START, DBG_ERR, "Unable to allocate memory\n");
			BUG();
		}
		msg->on_confirm = ieee80215_start_realign_confirm;
		skb_queue_head(&mac->to_network, mpdu_to_skb(msg));
		ieee80215_csma_ca_start(mac);
		return 0;
	}

	dbg_print(mac, START, DBG_INFO,
		"pan_id: %d, bo: %d, so: %d, sec: %d, ble: %d\n",
		pan_id, b_order, s_order, sec_enable, bat_life_ext);
	mac->pib.beacon_order = b_order;
	mac->pib.superframe_order = s_order;

	if (pan_coord) {
		mac->pib.dev_addr.panid = pan_id;
		mac->i.current_channel = lch;
		mac->i.i_pan_coord = 1;
	}
	mac->f.sec_enable = sec_enable;
	ieee80215_start_a_pan(mac);
	return 0;
}


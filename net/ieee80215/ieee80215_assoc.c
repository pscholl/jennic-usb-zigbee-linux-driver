/*
 * ieee80215_assoc.c
 *
 * Description: IEEE 802.15.4 MAC association primitives
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

#include <linux/timer.h>
#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/const.h>
#include <net/ieee80215/beacon.h>

static void assoc_done_trx_set(ieee80215_mac_t *mac)
{
	u16 addr16;

	addr16 = mac->pib.dev_addr._16bit;
#warning FIXME debug
#if 0
	dbg_print(mac, ASSOC, DBG_INFO, "status = 0x%x\n", mac->assoc_status);
#endif
	if (IEEE80215_SUCCESS == mac->assoc_status) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO,
			"associated, assigned addr16 = 0x%x\n", addr16);
#endif
		ieee80215_set_state(mac, ACTIVE);
	} else {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO, "not associated\n");
#endif
		ieee80215_restore_state(mac);
	}
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_associate_confirm(_nhle(mac), addr16, mac->assoc_status);
#endif
}

int ieee80215_assoc_perm_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

#warning FIXME debug
#if 0
	dbg_print(mac, ASSOC, DBG_INFO, "state = %s\n", s_states[mac->state]);
#endif
	dump_mpdu(mac, mpdu);

	if (ZA != mac->state) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO, "unexpected association response\n");
#endif
		return 0;
	}

	mac->assoc_status = mpdu->p.aresp->status;
#warning FIXME debug
#if 0
	dbg_print(mac, ASSOC, DBG_INFO, "aresp status: %d\n", mpdu->p.aresp->status);
#endif

	if (mac->assoc_status == IEEE80215_SUCCESS) {
		write_lock(&mac->pib.lock);
		mac->pib.dev_addr._16bit = le16_to_cpu(mpdu->p.aresp->_16bit);
		if (IEEE80215_AMODE_16BIT == mpdu->mhr->fc.src_amode) {
			mac->pib.coord._16bit = le16_to_cpu(mpdu->sa->_16bit);
#warning FIXME debug
#if 0
			dbg_print(mac, ASSOC, DBG_INFO, "coord16 = 0x%x\n", mac->pib.coord._16bit);
#endif
		} else if (IEEE80215_AMODE_64BIT == mpdu->mhr->fc.src_amode) {
			mac->pib.coord._64bit = le64_to_cpu(mpdu->sa->_64bit);
#warning FIXME debug
#if 0
			dbg_print(mac, ASSOC, DBG_INFO, "coord64 = 0x%x\n", mac->pib.coord._64bit);
#endif
		} else {
#warning FIXME debug
#if 0
			dbg_print(mac, ASSOC, DBG_ERR, "unexpected coord addr mode = %u\n",
				mpdu->mhr->fc.src_amode);
#endif
		}
		write_unlock(&mac->pib.lock);
	} else {
		write_lock(&mac->pib.lock);
		mac->pib.dev_addr.panid = 0xffff;
		mac->pib.dev_addr._16bit = 0xffff;
		mac->pib.coord._16bit = IEEE80215_COORD_SHORT_ADDRESS_DEF;
		mac->pib.coord._64bit = IEEE80215_COORD_EXT_ADDRESS_DEF;
		write_unlock(&mac->pib.lock);
	}
	/* trx must be set before processing cmd */
	assoc_done_trx_set(mac);
	return 0;
}

static void assoc_timeout(struct work_struct *work)
{
	ieee80215_mac_t *mac;
	mac = container_of(work, ieee80215_mac_t, associate_timeout.work);

	if (!mac->assoc_pending) {
		return;
	}
	mac->assoc_pending = false;
#warning FIXME debug
#if 0
	dbg_print(mac, ASSOC, DBG_INFO, "no association response\n");
#endif
	mac->assoc_status = IEEE80215_NO_DATA;
	write_lock(&mac->pib.lock);
	mac->pib.dev_addr.panid = 0xffff;
	mac->pib.dev_addr._16bit = 0xffff;
	mac->pib.coord._16bit = IEEE80215_COORD_SHORT_ADDRESS_DEF;
	mac->pib.coord._64bit = IEEE80215_COORD_EXT_ADDRESS_DEF;
	write_unlock(&mac->pib.lock);
	if (ieee80215_should_rxon(mac)) {
		set_trx_state(mac, IEEE80215_RX_ON, assoc_done_trx_set);
	} else {
		set_trx_state(mac, IEEE80215_TRX_OFF, assoc_done_trx_set);
	}
}

int ieee80215_assoc_extract_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	if (code == IEEE80215_PHY_SUCCESS) {
		if (mpdu->mhr->fc.pend) {
			unsigned long tmp;
			PREPARE_DELAYED_WORK(&mac->associate_timeout, assoc_timeout);
			tmp = IEEE80215_SLOW_SERIAL_FIXUP * usecs_to_jiffies(IEEE80215_MAX_FRAME_RESP_TIME * mac->symbol_duration);
#warning FIXME debug
#if 0
			dbg_print(mac, ASSOC, DBG_INFO, "wait %lu jiffies for data from peer\n", tmp);
#endif
			schedule_delayed_work(&mac->associate_timeout, tmp);
		} else {
			mac->assoc_pending = false;
#warning FIXME debug
#if 0
			dbg_print(mac, ASSOC, DBG_INFO, "Assoc extract confirmed, no data pending\n");
#endif
			ieee80215_restore_state(mac);
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, code);
#endif
		}
	} else {
		mac->assoc_pending = false;
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO, "Processing failed, code = %d\n", code);
#endif
		ieee80215_restore_state(mac);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, code);
#endif
	}
	return 0;
}

void ieee80215_assoc_wait_confirm(struct work_struct *work)
{
	ieee80215_mac_t *mac;
	ieee80215_dev_addr_t a;
	ieee80215_mpdu_t *msg;

	mac = container_of(work, ieee80215_mac_t, associate_request.work);

	if (ieee80215_slotted(mac) && mac->f.track_beacon) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO, "No assoc response\n");
#endif
		cancel_delayed_work(&mac->associate_request);
		ieee80215_restore_state(mac);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, IEEE80215_NO_DATA);
#endif
		return;
	}
#warning FIXME debug
#if 0
	dbg_print(mac, ASSOC, DBG_INFO, "request data from coordinator\n");
#endif

	read_lock(&mac->pib.lock);
	a.panid = mac->pib.dev_addr.panid;
	if (mac->pib.coord._16bit == 0xfffe) {
		a._64bit = mac->pib.coord._64bit;
	} else {
		a._16bit = mac->pib.coord._16bit;
	}
	read_unlock(&mac->pib.lock);
	msg = ieee80215_create_data_request_cmd(mac, &a);
	if (!msg) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_ERR, "Unable to create data request cmd\n");
#endif
		cancel_delayed_work(&mac->associate_request);
		ieee80215_restore_state(mac);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, IEEE80215_NO_DATA);
#endif
		return;
	}
	msg->on_confirm = ieee80215_assoc_extract_confirm;
	mac->assoc_pending = true;
	skb_queue_head(&mac->to_network, mpdu_to_skb(msg));
	ieee80215_csma_ca_start(mac);
}

int ieee80215_assoc_cmd_confirm(void *obj, struct sk_buff *skb, int code)
{
	struct ieee80215_mac *mac = obj;

	if (code == IEEE80215_PHY_SUCCESS) {
		unsigned long assoc_wait_time;

		PREPARE_DELAYED_WORK(&mac->associate_request, ieee80215_assoc_wait_confirm);
		if (ieee80215_slotted(mac)) {
			u8 bo;
			u32 bi;
			ieee80215_get_pib(mac, IEEE80215_BEACON_ORDER, &bo);
			bi = IEEE80215_BASE_SFD*(1<<bo)*mac->symbol_duration;
			assoc_wait_time = usecs_to_jiffies(32*bi);
		} else {
			assoc_wait_time = usecs_to_jiffies(IEEE80215_RESPONSE_WAIT_TIME*
					mac->symbol_duration);
		}
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_ALL, "Wait %lu jiffies\n", assoc_wait_time);
#endif
		schedule_delayed_work(&mac->associate_request, assoc_wait_time);
	} else {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO,
			"Association failed, code = 0x%x\n", code);
#endif
		ieee80215_restore_state(mac);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, code);
#endif
	}
	return 0;
}

int ieee80215_assoc_start(struct ieee80215_mac *mac, int code,
			  ieee80215_plme_pib_t *a)
{
#warning FIXME debug
#if 0
	dbg_print(mac, ASSOC, DBG_INFO, "code = %d\n", code);
#endif
	if (code == IEEE80215_PHY_SUCCESS) {
		/* Do the sending now */
		ieee80215_csma_ca_start(mac);
	} else {
		struct sk_buff *msg;

		ieee80215_restore_state(mac);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, IEEE80215_INVALID_PARAM);
#endif

		msg = skb_dequeue(&mac->to_network);
		if (!msg) {
#warning FIXME debug
#if 0
			dbg_print(mac, ASSOC, DBG_ERR, "no data\n");
#endif
			return 0;
		}
		kfree_mpdu(skb_to_mpdu(msg));
	}
	return 0;
}

int ieee80215_mlme_assoc_req(ieee80215_mac_t *mac, u8 lch, u16 c_panid,
	ieee80215_dev_addr_t *crd, u8 cap_info, bool sec_enable)
{
	ieee80215_plme_pib_t pa;
	ieee80215_mpdu_t *msg;
	ieee80215_dev_addr_t ca;
	u8 rxon;

	rxon = cap_info & (1 << 3);

	if (lch > IEEE80215_PHY_CURRENT_CHANNEL_MAX) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_ERR, "channel is out of range\n");
#endif
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}
	if (crd) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO,
			"Association request to given address: "
			"[16bit]:0x%x, [64bit]:0x%x, ch: 0x%x, panid: 0x%x, cap: 0x%x\n",
			crd->_16bit, crd->_64bit, lch, c_panid, cap_info);
#endif
		crd->panid = c_panid;
	} else {
		ieee80215_get_pib(mac, IEEE80215_COORD_EXTENDED_ADDRESS, (u8*)&ca);
		ieee80215_get_pib(mac, IEEE80215_COORD_SHORT_ADDRESS, (u8*)&ca);
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_INFO,
			"Association request to: [16bit]: %lu, [64bit]: %llu\n",
     			ca._16bit, ca._64bit);
		dbg_print(mac, ASSOC, DBG_INFO, " ch: 0x%x, panid: 0x%x, cap: 0x%x\n",
			lch, c_panid, cap_info);
#endif
		if (ca._16bit >= 0xfffe && ca._64bit == IEEE80215_COORD_EXT_ADDRESS_DEF) {
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
			dbg_print(mac, ASSOC, DBG_ERR, "No coordinator address assigned\n");
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, IEEE80215_NO_SHORT_ADDRESS);
#endif
			return 0;
		}
		ca.panid = c_panid;
		crd = &ca;
	}

#warning FIXME debug
#if 0
	dbg_print(mac, ASSOC, DBG_INFO, "Mac state: %d, %s\n",
		mac->state, s_states[mac->state]);
#endif

	switch (mac->state) {
		case ZP:
		case YA:
			break;
		default:
#warning FIXME debug
#if 0
			dbg_print(mac, ASSOC, DBG_ERR, "Inappropriate state: %d, %s\n",
				  mac->state, s_states[mac->state]);
#endif
			return 0;
			break;
	}

	if (lch > IEEE80215_PHY_CURRENT_CHANNEL_MAX) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_ERR, "Channel is out of scope\n");
#endif
		return 0;
	}

	if (c_panid == IEEE80215_PANID_MAX) {
#warning FIXME debug
#if 0
		dbg_print(mac, ASSOC, DBG_ERR, "PANid must not be broadcast\n");
#endif
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
		return 0;
	}

	write_lock(&mac->pib.lock);
	mac->pib.dev_addr.panid = c_panid;
	if (crd) {
		mac->pib.coord._64bit = crd->_64bit;
		mac->pib.coord._16bit = crd->_16bit;
	}
	if(mac->pib.coord._16bit == 0xfffe) {
		mac->i.cam = IEEE80215_AMODE_64BIT;
	} else {
		mac->i.cam = IEEE80215_AMODE_16BIT;
	}
	write_unlock(&mac->pib.lock);
	mac->f.sec_enable = sec_enable;

	mac->i.current_channel = lch;
	/* adjusting to current superframe structure */
	ieee80215_set_beacon_interval(mac);
	ieee80215_set_superframe_params(mac);
	ieee80215_set_state(mac, ZA);
	ieee80215_set_pib(mac, IEEE80215_RXON_WHEN_IDLE, &rxon);

	msg = ieee80215_create_assoc_cmd(mac, crd, cap_info);
	if (!msg) {
		dbg_print(mac, ASSOC, DBG_ERR, "unable to create assoc request\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_confirm(_nhle(mac), 0xffff, IEEE80215_ERROR);
#endif
		return 0;
	}
	msg->use_csma_ca = true;
	msg->on_confirm = ieee80215_assoc_cmd_confirm;
	skb_queue_head(&mac->to_network, mpdu_to_skb(msg));

	pa.attr_type = IEEE80215_PHY_CURRENT_CHANNEL;
	pa.attr.curr_channel = lch;
	mac->plme_set_confirm = ieee80215_assoc_start;
	mac->phy->plme_set_request(mac->phy, pa);
	return 0;
}

int ieee80215_mlme_assoc_reply(ieee80215_mac_t *mac,
	ieee80215_dev_addr_t *adev, u8 status, bool sec_enable)
{
	ieee80215_mpdu_t *aresp;

	mac->f.sec_enable = sec_enable;
	aresp = ieee80215_create_assocresp_cmd(mac, adev, status);
	if (!aresp) {
		dbg_print(mac, ASSOC, DBG_ERR, "Unable to create assoc response cmd\n");
		return 0;
	}

	dbg_print(mac, ASSOC, DBG_INFO, "Queue aresp cmd to transaction queue\n");
	skb_queue_tail(&mac->tr64, mpdu_to_skb(aresp));
	dbg_print(mac, ASSOC, DBG_INFO, "tr64 queue len = %u\n", skb_queue_len(&mac->tr64));
	return 0;
}

/* Orphan association */
int ieee80215_mlme_orphan_resp(ieee80215_mac_t *mac, ieee80215_dev_addr_t *addr,
	bool assoc_member, bool sec_enable)
{
	ieee80215_addr_t ad;
	ieee80215_mpdu_t *msg;

	dbg_print(mac, ASSOC, DBG_INFO, "assoc_member = %u\n", assoc_member);

	if (!assoc_member) {
		return 0;
	}

	mac->f.sec_enable = sec_enable;
	/* FIXME: */
	ad._64bit = addr->_64bit;
	msg = ieee80215_create_realign_cmd(mac, &ad, mac->i.current_channel);
	if (!msg) {
		dbg_print(mac, ASSOC, DBG_ERR, "Unable to create coord realign cmd\n");
		return 0;
	}
	skb_queue_head(&mac->to_network, mpdu_to_skb(msg));
	ieee80215_csma_ca_start(mac);
	return 0;
}


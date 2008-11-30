/*
 * ieee80215_disassoc.c
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

#if 0
int ieee80215_disassoc_cmd_expire(void *obj, ieee80215_mpdu_t *mpdu)
{
	ieee80215_mac_t *mac = obj;

	cancel_delayed_work(&mac->disassociate_request);
	dbg_print(mac, DISASSOC, DBG_ERR, "Disassoc cmd expires\n");
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_disassoc_confirm(_nhle(mac), IEEE80215_TRANSACTION_EXPIRED);
#endif
	kfree_mpdu(mac->msg);
	mac->msg = NULL;
	ieee80215_restore_msg(mac);
	return 0;
}
#endif

static int ieee80215_disassoc_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;

	if (code == IEEE80215_PHY_SUCCESS) {
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
		dbg_print(mac, DISASSOC, DBG_INFO, "Disassoc confirm success\n");
		code =  IEEE80215_SUCCESS;
	} else {
		dbg_print(mac, DISASSOC, DBG_ERR, "Unable to send data out\n");
	}
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_disassoc_confirm(_nhle(mac), code);
#endif
#if 0
	if (mac->i.i_pan_coord) {
		if (ieee80215_mpdu_in_trq(mpdu, &mac->tr16)) {
			dbg_print(mac, DISASSOC, DBG_INFO, "Unlink mpdu from tr16\n");
			mpdu_unlink(mpdu, &mac->tr16);
		} else if (ieee80215_mpdu_in_trq(mpdu, &mac->tr64)) {
			dbg_print(mac, DISASSOC, DBG_INFO, "Unlink mpdu from tr64\n");
			mpdu_unlink(mpdu, &mac->tr64);
		} else {
			dbg_print(mac, DISASSOC, DBG_INFO, "not in trq\n");
		}
	}
#endif
	return 0;
}

int ieee80215_mlme_disassoc_req(ieee80215_mac_t *mac,
	ieee80215_dev_addr_t *addr, u8 reason, bool sec_enable)
{
	u16 coord16;
	u64 coord64;
	ieee80215_mpdu_t *msg;

	mac->f.sec_enable = sec_enable;

	read_lock(&mac->pib.lock);
	coord16 = mac->pib.coord._16bit;
	coord64 = mac->pib.coord._64bit;
	read_unlock(&mac->pib.lock);

	if (coord64 == IEEE80215_COORD_EXT_ADDRESS_DEF && coord16 >= 0xfffe) {
		dbg_print(mac, DISASSOC, DBG_ERR, "Device is not associated\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_disassoc_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	dbg_print(mac, DISASSOC, DBG_INFO, "reason = 0x%x\n", reason);

	if (!addr && reason == IEEE80215_KICK_DEV) {
		dbg_print(mac, DISASSOC, DBG_ERR, "invalid params\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_disassoc_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	if (addr) {
		coord64 = addr->_64bit;
	}

	msg = ieee80215_create_disassoc_cmd(mac, reason, coord64);
	if (!msg) {
		return 0;
	}
	msg->on_confirm = ieee80215_disassoc_confirm;

#if 0
	if (ieee80215_slotted(mac)) {
		if (mac->i.i_pan_coord) {
			if (skb_queue_len(&mac->tr64) > mac->i.max_trq) {
#warning FIXME indication/confurm
#if 0
				_nhle(mac)->mlme_disassoc_confirm(_nhle(mac), IEEE80215_TRANSACTION_OVERFLOW);
#endif
			} else {
				mpdu_queue_tail(&mac->tr64, msg);
			}
			return ret;
		}
	}
#endif
	skb_queue_head(&mac->to_network, mpdu_to_skb(msg));
	ieee80215_csma_ca_start(mac);
	return 0;
}


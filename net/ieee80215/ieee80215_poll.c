/*
 * ieee80215_poll.c
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

void ieee80215_poll_timeout(struct work_struct *work)
{
	ieee80215_mac_t *mac;

	mac = container_of(work, ieee80215_mac_t, poll_request.work);
	mac->poll_pending = false;
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, POLL, DBG_INFO, "No data on poll req received\n");
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_poll_confirm(_nhle(mac), IEEE80215_NO_DATA);
#endif
}

int ieee80215_poll_confirm(void *obj, struct sk_buff *skb, int code)
{
	struct ieee80215_mac *mac = obj;

	if (code == IEEE80215_PHY_SUCCESS) {
		unsigned long tmp;

		PREPARE_DELAYED_WORK(&mac->poll_request, ieee80215_poll_timeout);
		tmp = IEEE80215_SLOW_SERIAL_FIXUP * usecs_to_jiffies(IEEE80215_MAX_FRAME_RESP_TIME * mac->symbol_duration);
		dbg_print(mac, POLL, DBG_INFO, "wait %lu jiffies for data from peer\n", tmp);
		schedule_delayed_work(&mac->poll_request, tmp);
	} else {
		mac->poll_pending = false;
		dbg_print(mac, POLL, DBG_INFO, "code = 0x%x\n", code);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_poll_confirm(_nhle(mac), code);
#endif
	}
	return 0;
}

int ieee80215_mlme_poll_req(ieee80215_mac_t *mac, ieee80215_dev_addr_t *crd, bool sec_enable)
{
	ieee80215_mpdu_t *msg;

	dbg_print(mac, POLL, DBG_INFO,
		"panid = 0x%x, 16bit = 0x%x, 64bit = 0x%llx, sec_enable = %u\n",
		crd->panid, crd->_16bit, crd->_64bit, sec_enable);

	mac->f.sec_enable = sec_enable;

	msg = ieee80215_create_data_request_cmd(mac, crd);
	if (!msg) {
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_poll_confirm(_nhle(mac), IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}
	msg->on_confirm = ieee80215_poll_confirm;
	mac->poll_pending = true;
	skb_queue_head(&mac->to_network, mpdu_to_skb(msg));
	ieee80215_csma_ca_start(mac);
	return 0;
}


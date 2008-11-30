/*
 * ieee80215_mac_data.c
 *
 * Description: MAC data transmission helper functions.
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
#include <net/ieee80215/mac_scan.h>
#include <net/ieee80215/const.h>

int ieee80215_mpdu_in_trq(struct sk_buff *skb, struct sk_buff_head *queue)
{
	struct sk_buff *tr_mpdu;

	for (tr_mpdu = queue->next; tr_mpdu != (struct sk_buff *)queue; tr_mpdu = tr_mpdu->next) {
		if (tr_mpdu == skb) {
			return 1;
		}
	}
	return 0;
}

int ieee80215_data_req_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, DATA, DBG_INFO, "code = %u\n", code);
	if (code == IEEE80215_PHY_SUCCESS) {
		code = IEEE80215_SUCCESS;
	}
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mcps_data_confirm(_nhle(mac), skb, code);
#endif
	return 0;
}

/**
 * \brief MCPS-SAP.data_request
 *
 * Called by local SSCS in order to send some data.
 *
 * \param mac pointer to current mac
 * \param src source pointer information(addr mode, panid, addr)
 * \param dst destination pointer information(addr mode, panid, addr)
 * \param mpdu actual mpdu
 * \param tx_opt transmission option
 * \return errno
 */
int ieee80215_mcps_data_request(ieee80215_mac_t *mac, ieee80215_dev_addr_t *src,
                                ieee80215_dev_addr_t *dst, struct sk_buff *skb, u8 tx_opt)
{
	int with_ack;
	int gts;
	int indirect;
	int sec_enable;
	ieee80215_gts_info_t *r_gts = NULL;
	ieee80215_gts_char_t gc;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	if (tx_opt > 0xf) {
		dbg_print(mac, DATA, DBG_ERR, "TX options exceeds it's limit\n");
		BUG();
	}

	with_ack = tx_opt&0x1;
	gts = (tx_opt>>1)&0x1;
	indirect = (tx_opt>>2)&0x1;
	sec_enable = (tx_opt>>3)&0x1;

	if (gts || !dst || !mac->i.i_pan_coord) {
		indirect = 0;
		tx_opt &= ~((tx_opt>>2)&0x1);
	}

	if (gts) {
		ieee80215_dev_addr_t *addr;

		if (mac->i.i_pan_coord) {
			gc.dir = 0; /* Transmit only */
			addr = dst;
		} else {
			gc.dir = 1; /* Receive only */
			addr = src;
		}
		r_gts = ieee80215_find_gts(mac, addr->_16bit, &gc);
		if (!r_gts) {
			dbg_print(mac, DATA, DBG_ERR, "No valid GTS\n");
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mcps_data_confirm(_nhle(mac), skb, IEEE80215_INVALID_GTS);
#endif
			goto exit_err;
		}
	}

	dbg_print(mac, DATA, DBG_INFO,
		"src = 0x%p, dst = 0x%p, mpdu = 0x%p, with_ack = %u, sec_enable = %u\n",
		src, dst, mpdu, with_ack, sec_enable);

	dbg_print(mac, DATA, DBG_INFO,
		"src->panid = %u, src->_16bit = %x, src->_64bit = %llx\n",
		src->panid, src->_16bit, src->_64bit);

	dbg_print(mac, DATA, DBG_INFO,
		"dst->panid = %u, dst->_16bit = %x, dst->_64bit = %llx\n",
		dst->panid, dst->_16bit, dst->_64bit);

	dbg_print(mac, DATA, DBG_INFO,
		"mpdu->users = %u, mpdu->skb->len = %u, mpdu->sa = 0x%p, mpdu->da = 0x%p, mpdu->p.h = 0x%p\n",
		atomic_read(&skb->users), skb->len, mpdu->sa, mpdu->da, mpdu->p.h);

	if (skb->len && (mpdu->sa || mpdu->da)) {
		/* if we have mpdu constructed, do not create new */

		if (0xfffe == src->_16bit) {
			mpdu->sa->_64bit = cpu_to_le64(src->_64bit);
		} else {
			mpdu->sa->_16bit = cpu_to_le16(src->_16bit);
			dbg_print(mac, DATA, DBG_INFO,
				"mpdu->sa->_16bit = %x, mpdu->p.h->src = %x\n",
				mpdu->sa->_16bit, mpdu->p.h->src);
		}

		if (0xfffe == dst->_16bit) {
			mpdu->da->_64bit = cpu_to_le64(dst->_64bit);
		} else {
			mpdu->da->_16bit = cpu_to_le16(dst->_16bit);
			dbg_print(mac, DATA, DBG_INFO,
				"mpdu->da->_16bit = %x, mpdu->p.h->dst = %x\n",
				mpdu->da->_16bit, mpdu->p.h->dst);
		}

		dbg_print(mac, DATA, DBG_INFO, "mpdu->mhr = 0x%p\n", mpdu->mhr);
		mpdu->mhr->fc.ack_req = with_ack;

		dbg_print(mac, DATA, DBG_INFO, "mpdu->mfr = 0x%p\n", mpdu->mfr);
		mpdu->mfr->fcs = ieee80215_crc_itu(skb->data, skb->len);
	} else {
		dbg_print(mac, DATA, DBG_INFO, "create new mpdu\n");
		ieee80215_create_mcps_data_req(mac, src, dst, skb, with_ack, sec_enable);

		dbg_print(mac, DATA, DBG_INFO,
			"mpdu->users = %u, mpdu->skb->len = %u, mpdu->sa = 0x%p, mpdu->da = 0x%p, mpdu->p.h = 0x%p\n",
			atomic_read(&skb->users), skb->len, mpdu->sa, mpdu->da, mpdu->p.h);
		dbg_print(mac, DATA, DBG_INFO,
			"mpdu->sa->_16bit = %x, mpdu->p.h->src = %x\n",
			mpdu->sa->_16bit, mpdu->p.h->src);
		dbg_print(mac, DATA, DBG_INFO,
			"mpdu->da->_16bit = %x, mpdu->p.h->dst = %x\n",
			mpdu->da->_16bit, mpdu->p.h->dst);

		dbg_print(mac, DATA, DBG_INFO, "mpdu->mhr = 0x%p, mpdu->mfr = 0x%p\n", mpdu->mhr, mpdu->mfr);
	}

	if (gts && r_gts) {
		dbg_print(mac, DATA, DBG_INFO,
			"GTS transmission, gts, ss: %d, len: %d\n",
			r_gts->starting_slot, r_gts->c.len);
		if (skb->len > r_gts->c.len*mac->i.symbols_per_slot) {
			dbg_print(mac, DATA, DBG_ERR,
				"Data len does not fit into gts len: %d %d\n",
				skb->len, r_gts->c.len*mac->i.symbols_per_slot);
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mcps_data_confirm(_nhle(mac), skb, IEEE80215_FRAME_TOO_LONG);
#endif
			goto exit_err;
		}
		mpdu->gts = 1;
		skb_queue_tail(r_gts->gts_q, skb);
		return 0;
	}

	if (indirect) {
		dbg_print(mac, DATA, DBG_INFO, "indirect\n");
		/* since we don't know max_store_trans, skip check
		if (skb_queue_len(&mac->tr.tr_q) >= mac->max_store_trans) {
			_nhle(mac)->mcps_data_confirm(_nhle(mac), mpdu, IEEE80215_TRANSACTION_OVERFLOW);
			goto exit_err;
		}
		*/
		if (0xfffe == dst->_16bit) {
			skb_queue_head(&mac->tr64, skb);
			dbg_print(mac, DATA, DBG_INFO, "tr64 queue len = %u\n",
				skb_queue_len(&mac->tr64));
		} else {
			skb_queue_head(&mac->tr16, skb);
			dbg_print(mac, DATA, DBG_INFO, "tr16 queue len = %u\n",
				skb_queue_len(&mac->tr16));
		}
		return 0;
	}

	/* If this is not a gts or indirect transfer, we should send it now using csma-ca */
	dbg_print(mac, DATA, DBG_INFO, "not gts, not indirect\n");

	mpdu->on_confirm = ieee80215_data_req_confirm;
	skb_queue_head(&mac->to_network, skb);
	ieee80215_csma_ca_start(mac);
	return 0;
exit_err:
	kfree_mpdu(mpdu);
	return 0;
}


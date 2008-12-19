/*
 * ieee80215_mac_lib.c
 *
 * Description: IEEE 802.15.4 MAC helper functions (csma-ca, scanning).
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

#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/mac.h>
#include <net/ieee80215/netdev.h>

int ieee80215_cmp_addr(ieee80215_dev_addr_t *addr1, ieee80215_dev_addr_t *addr2)
{
	if (0xfffe == addr1->_16bit || 0xfffe == addr2->_16bit)
		return addr1->_64bit - addr2->_64bit;
	else
		return addr1->_16bit - addr2->_16bit;
}

void ieee80215_adjust_symbol_duration(ieee80215_mac_t *mac)
{
	if (0 == mac->i.current_channel)
		mac->symbol_duration = IEEE80215_868MHZ_1SYM_TIME;
		mac->pib.ack_wait_duration = IEEE80215_ACK_WAIT_DURATION_MAX;
	if (mac->i.current_channel > 0 && mac->i.current_channel <= 10)
		mac->symbol_duration = IEEE80215_915MHZ_1SYM_TIME;
		mac->pib.ack_wait_duration = IEEE80215_ACK_WAIT_DURATION_MAX;
	if (mac->i.current_channel > 10) {
		mac->symbol_duration = IEEE80215_2450MHZ_1SYM_TIME;
		mac->pib.ack_wait_duration = IEEE80215_ACK_WAIT_DURATION_MIN;
	}

#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	pr_debug("channel: %d, symbol_duration: %d microseconds, ack_wait_duration: %d symbols\n",
		mac->i.current_channel, mac->symbol_duration, mac->pib.ack_wait_duration);

	if (mac->pib.bat_life_ext) {
		if (mac->i.current_channel <= 10)
			mac->pib.bat_life_ext_period = 8;
		else
			mac->pib.bat_life_ext_period = 6;
		dbg_print(mac, 0, DBG_INFO, "bat_life_ext_period: %d\n", mac->pib.bat_life_ext_period);
	}
}

int ieee80215_in_scanning(ieee80215_mac_t *mac)
{
	switch(mac->state) {
	case PEND_AS:
	case PEND_AS1:
	case PEND_PS:
	case PEND_OS:
	case PEND_OS1:
	case ED:
		return 1;
		break;
	default:
		break;
	}
	return 0;
}

/**
 * Examine mpdu, and decide of should we ignore it or not.
 */
int ieee80215_ignore_mpdu(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	int ret = 0;	/* do not ignore by default */

	dbg_print(mac, 0, DBG_INFO, "mpdu = 0x%p\n", skb_to_mpdu(skb));
	switch (mac->state) {
	case PEND_AS:
	case PEND_AS1:
	case PEND_PS:
		dbg_print(mac, CORE, DBG_INFO,
			  "In Active/Passive scan mode, accept only beacons\n");
		if (skb_to_mpdu(skb)->mhr->fc.type != IEEE80215_TYPE_BEACON)
			ret = 1;
		break;
	case PEND_OS:
	case PEND_OS1:
		dbg_print(mac, CORE, DBG_INFO,
			  "In Orphan scan mode, accept only coord realign cmd's\n");
		if (skb_to_mpdu(skb)->mhr->fc.type != IEEE80215_TYPE_MAC_CMD ||
			skb_to_mpdu(skb)->p.g->cmd_id != IEEE80215_COORD_REALIGN_NOTIFY)
			ret = 1;
		break;
	case WAIT:
	case ED:
		dbg_print(mac, CORE, DBG_INFO, "[%s]: ignore frame\n",
			 s_states[mac->state]);
		ret = 1;
		break;
	case ZA:
		if (skb_to_mpdu(skb)->mhr->fc.type == IEEE80215_TYPE_DATA) {
			dbg_print(mac, 0, DBG_INFO,
				"Device in assoc state, data frames not allowed\n");
			ret = 1;
			break;
		}
		if (skb_to_mpdu(skb)->mhr->fc.type == IEEE80215_TYPE_ACK ||
			skb_to_mpdu(skb)->mhr->fc.type == IEEE80215_TYPE_BEACON) {
			ret = 0;
			break;
		}
		switch (skb_to_mpdu(skb)->p.g->cmd_id) {
		case IEEE80215_ASSOCIATION_PERM:
			ret = 0;
			break;
		default:
			dbg_print(mac, CORE, DBG_INFO,
				"Device in assoc state, only assoc perm cmd allowed\n");
			ret = 1;
			break;
		}
		break;
	case YA:
		dbg_print(mac, CORE, DBG_INFO, "Coordinator not yet started\n");
		ret = 1;
		break;
	default:
		if (!mac->i.i_pan_coord) {
			if (skb_to_mpdu(skb)->mhr->fc.type == IEEE80215_TYPE_MAC_CMD) {
				switch( skb_to_mpdu(skb)->p.g->cmd_id ){
				case IEEE80215_ASSOCIATION_REQ:
				case IEEE80215_ASSOCIATION_PERM:
				case IEEE80215_DATA_REQ:
				case IEEE80215_PANID_CONFLICT_NOTIFY:
				case IEEE80215_BEACON_REQ:
				case IEEE80215_GTS_REQ:
					ret = 1;
					break;
				default:
					ret = 0;
					break;
				}
			}
		} else {
			ret = 0;
		}
		break;
	}
	dbg_print(mac, 0, DBG_INFO, "ret = %u\n", ret);
	return ret;
}

/**
 * @brief Check, if we can react on ack required frame.
 */
int ieee80215_can_process_ack(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	if (ieee80215_slotted(mac)) {
		long unsigned int time_req;

		/* time, required for process ack_req. RX-to-TX time +
		time to parse frame and send it to phy + time to recv ack frame
		on peer. */
		time_req = usecs_to_jiffies(
			(2*IEEE80215_TURNAROUND_TIME + 12) * mac->symbol_duration);

		dbg_print(mac, CORE, DBG_INFO,
			"time_req = %lu, mac->gts.active_count = %u\n",
			time_req, mac->gts.active_count);

		if (mac->gts.active_count) {
			long unsigned int slot_duration, sf_end;

			slot_duration = usecs_to_jiffies(IEEE80215_BASE_SD *
				(1<<mac->pib.superframe_order) * mac->symbol_duration);
			sf_end = mac->pib.beacon_tx_time + mac->sf_time -
				(IEEE80215_NUM_SFS - mac->i.final_cap_slot)*slot_duration;

			dbg_print(mac, CORE, DBG_INFO, "sf_end = %u\n", sf_end);

			if (jiffies + time_req >= sf_end) {
				/* We cannot process it */
				dbg_print(mac, CORE, DBG_INFO, "1\n\n");
				return 0;
			}
		} else {
			long unsigned int
				time_need,
				time_have;

			time_need = jiffies + time_req;
			time_have = mac->pib.beacon_tx_time + mac->sf_time;

			dbg_print(mac, CORE, DBG_INFO,
				"time_need = %lu, mac->pib.beacon_tx_time = %lu, mac->sf_time = %lu\n",
				time_need, mac->pib.beacon_tx_time, mac->sf_time);

			/* if (jiffies + time_req >= mac->pib.beacon_tx_time + mac->sf_time) { */
			if (time_need >= time_have) {
				dbg_print(mac, CORE, DBG_INFO,
					"time_need = %lu, time_have = %lu\n\n",
					time_need, time_have);
				/* We cannot process it */
				return 0;
			}
		}
	}
	/* non slotted, or can be processed */
	return 1;
}

#if 0
/**
 *	mpdu_queue_purge - empty a list
 *	@list: list to empty
 *
 *	Delete all buffers on an &sk_buff list. Each buffer is removed from
 *	the list and one reference dropped. This function takes the list
 *	lock and is atomic with respect to other list locking functions.
 */
void mpdu_queue_purge(ieee80215_mpdu_head_t *list)
{
	ieee80215_mpdu_t *mpdu;
	while ((mpdu = skb_dequeue(list)) != NULL)
		kfree_mpdu(mpdu);
}

/**
 *	mpdu_append	-	append a buffer
 *	@old: buffer to insert after
 *	@newsk: buffer to insert
 *	@list: list to use
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls.
 *	A buffer cannot be placed on two lists at the same time.
 */
void mpdu_append(ieee80215_mpdu_t *old, ieee80215_mpdu_t *newsk, ieee80215_mpdu_head_t *list)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__mpdu_append(old, newsk, list);
	spin_unlock_irqrestore(&list->lock, flags);
}
#endif

/******************************************************************************/
/* MAC's CSMA-CA  */
/******************************************************************************/

static int ieee80215_chnl_error(ieee80215_mac_t *mac, int code)
{
	struct sk_buff *skb;

	dbg_print(mac, 0, DBG_INFO, "code = %u\n", code);

	skb = skb_dequeue(&mac->to_network);
	if (!skb) {
		dbg_print(mac, 0, DBG_ERR, "no data\n");
		return 0;
	}
	if (!skb_to_mpdu(skb)->on_confirm) {
		dbg_print(mac, 0, DBG_ERR, "msg->on_confirm is NULL\n");
		BUG();
	}
	skb_to_mpdu(skb)->on_confirm(mac, skb, code);
	kfree_mpdu(skb_to_mpdu(skb));
	return 0;
}

static void csma_ca_data(ieee80215_mac_t *mac)
{
	struct sk_buff *skb;

	skb = skb_peek(&mac->to_network);
	if (skb) {
		dbg_print(mac, 0, DBG_INFO, "feeding data\n");
		mac->phy->pd_data_request(mac->phy, skb);
	} else {
		dbg_print(mac, 0, DBG_ERR, "no data\n");
	}
}

static int csma_ca_cca_confirm(ieee80215_mac_t *mac, int code)
{
	dbg_print(mac, CSMA, DBG_INFO, "code = %d\n", code);

	if (code == IEEE80215_IDLE) {
		dbg_print(mac, CSMA, DBG_INFO, "Channel is idle\n");
		if (ieee80215_slotted(mac)) {
			if (mac->csma_val.cw) {
				mac->csma_val.cw--;
				dbg_print(mac, CSMA, DBG_INFO, "cw: %d\n",
					mac->csma_val.cw);
				if (mac->csma_val.cw) {
					mac->phy->plme_cca_request(mac->phy);
					return 0;
				}
			}
		}
		ieee80215_net_set_trx_state(mac, IEEE80215_TX_ON, csma_ca_data);
		return 0;
	}

	pr_debug("Channel is not idle\n");
	mac->csma_val.be = min(mac->csma_val.be+1, IEEE80215_MAX_CSMA_BACKOFF_MAX);
	if (ieee80215_slotted(mac)) {
		mac->csma_val.cw = 2;
		mac->csma_val.nb++;
		mac->i.num_of_backoffs = ieee80215_calc_backoffs(mac, IEEE80215_BACKOFF(mac));
	} else {
		mac->csma_val.nb++;
		mac->i.num_of_backoffs = IEEE80215_BACKOFF(mac);
	}

	if (mac->csma_val.nb < mac->pib.max_csma_backoff) {
		schedule_delayed_work(&mac->csma_dwork, mac->i.num_of_backoffs);
		return 0;
	}

	ieee80215_chnl_error(mac, code);
	return 0;
}

static void csma_ca_cca(ieee80215_mac_t *mac)
{
	dbg_print(mac, 0, DBG_INFO, "start CCA\n");
	mac->plme_cca_confirm = csma_ca_cca_confirm;
	mac->phy->plme_cca_request(mac->phy);
}

static void csma_ca_rxon(struct work_struct *work)
{
	ieee80215_mac_t *mac;

	mac = container_of(work, ieee80215_mac_t, csma_dwork.work);
	ieee80215_net_set_trx_state(mac, IEEE80215_RX_ON, csma_ca_cca);
}

int ieee80215_csma_ca_start(ieee80215_mac_t *mac)
{
	struct sk_buff *skb;
	ieee80215_mpdu_t *msg;
	u32 tmp;

	skb = skb_peek(&mac->to_network);
	if (!skb) {
		dbg_print(mac, 0, DBG_INFO, "to_network queue is empty\n");
		return 0;
	}

	msg = skb_to_mpdu(skb);

	if (!msg->use_csma_ca) {
		dbg_print(mac, 0, DBG_INFO, "csma_ca is not used\n");
		ieee80215_net_set_trx_state(mac, IEEE80215_RX_ON, csma_ca_cca);
		return 0;
	}

	memset(&mac->csma_val, 0, sizeof(mac->csma_val));
	mac->csma_val.be = IEEE80215_MIN_BE_DEF;
	/*
	For the unslotted version of csma-ca backoff start immideatelly.
	For slotted version we should calc it first, and then defer till it's end.
	*/
	PREPARE_DELAYED_WORK(&mac->csma_dwork, csma_ca_rxon);
	if (ieee80215_slotted(mac)) {
		dbg_print(mac, 0, DBG_INFO, "slotted\n");
		mac->csma_val.cw = 2;
		if (mac->pib.bat_life_ext) {
			mac->csma_val.be = min(2, IEEE80215_MIN_BE_MIN);
		}
		mac->i.num_of_backoffs = ieee80215_calc_backoffs(mac, 0);
	} else {
		dbg_print(mac, 0, DBG_INFO, "unslotted\n");
		mac->i.num_of_backoffs = IEEE80215_BACKOFF(mac);
	}
	tmp = usecs_to_jiffies(mac->i.num_of_backoffs * IEEE80215_UNIT_BACKOFF_PERIOD * mac->symbol_duration);
	dbg_print(mac, CSMA, DBG_INFO, "backoffs = %lu, %lu jiffies\n", mac->i.num_of_backoffs, tmp);
	schedule_delayed_work(&mac->csma_dwork, tmp);
	return 0;
}

/******************************************************************************/
/* MAC's frame manipulation procedures */
/******************************************************************************/
ieee80215_mpdu_t *ieee80215_dev_alloc_mpdu(unsigned int size, gfp_t gfp_mask)
{
	ieee80215_mpdu_t *mpdu;
	mpdu = alloc_mpdu(size + IEEE80215_MAX_PHY_OVERHEAD, gfp_mask);
	if (likely(mpdu))
		skb_reserve(mpdu_to_skb(mpdu), IEEE80215_MAX_PHY_OVERHEAD);
	return mpdu;
}

void ieee80215_pack_fc_and_seq(ieee80215_mac_t *mac,
	struct sk_buff *skb, u8 sn, int type, int sec, int pend,
	int ack, int intra_pan, int damode, int samode)
{
	ieee80215_fc_t *fc;
	u16 val;

	dbg_print(mac, 0, DBG_ALL,
		"type: %d, security: %d, pend: %d, ack_req: %d, intra_pan: %d, dst addr mode: %d, src addr mode: %d\n",
		type, sec, pend, ack, intra_pan, damode, samode);

	fc = (ieee80215_fc_t*)&val;
	fc->type = type;
	fc->security = sec;
	fc->pend = pend;
	fc->ack_req = ack;
	fc->intra_pan = intra_pan;
	fc->dst_amode = damode;
	fc->src_amode = samode;
	val = cpu_to_le16(val);
	memcpy(&skb_to_mpdu(skb)->mhr->fc, &val, sizeof(val));

	skb_to_mpdu(skb)->mhr->seq = sn;
}

/**
 * @brief Fill the MHR
 */
void ieee80215_mpdu_set_addr(struct ieee80215_mac *mac,
			     struct sk_buff *skb,
			     ieee80215_dev_addr_t *src,
			     ieee80215_dev_addr_t *dst,
			     u8 seq, u8 with_ack, u8 type, u8 pend)
{
	int intra_pan = 0, dm = IEEE80215_AMODE_NOPAN, sm = IEEE80215_AMODE_NOPAN;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	if (src && dst) {
		if (src->panid == dst->panid)
			intra_pan = 1;
	}

	if (src) {
		if (src->_16bit == 0xfffe) {
			sm = IEEE80215_AMODE_64BIT;
			mpdu->sa = (ieee80215_addr_t *)skb_push(skb,sizeof(u64));
			mpdu->sa->_64bit = cpu_to_le64(src->_64bit);
		} else {
			sm = IEEE80215_AMODE_16BIT;
			mpdu->sa = (ieee80215_addr_t *)skb_push(skb,sizeof(u16));
			mpdu->sa->_16bit = cpu_to_le16(src->_16bit);
		}
		if (!intra_pan) {
			mpdu->s_panid = (u16*)skb_push(skb, sizeof(u16));
			*mpdu->s_panid = cpu_to_le16(src->panid);
		}
	}

	if (dst) {
		if (dst->_16bit == 0xfffe) {
			dm = IEEE80215_AMODE_64BIT;
			mpdu->da = (ieee80215_addr_t *)skb_push(skb,sizeof(u64));
			mpdu->da->_64bit = cpu_to_le64(dst->_64bit);
		} else {
			dm = IEEE80215_AMODE_16BIT;
			mpdu->da = (ieee80215_addr_t *)skb_push(skb,sizeof(u16));
			mpdu->da->_16bit = cpu_to_le16(dst->_16bit);
		}
		mpdu->d_panid = (u16*)skb_push(skb, sizeof(u16));
		*mpdu->d_panid = cpu_to_le16(dst->panid);
	}

	mpdu->mhr = (ieee80215_mhr_t*)skb_push(skb, sizeof(*mpdu->mhr));

	ieee80215_pack_fc_and_seq(mac, skb, seq, type,
		(mac->f.sec_enable == true?1:0), pend, with_ack, intra_pan, dm, sm);

	mpdu->timestamp = jiffies;
}

void ieee80215_calc_crc(ieee80215_mpdu_t *mpdu)
{
	mpdu->mfr = (ieee80215_mfr_t*)skb_put(mpdu_to_skb(mpdu), sizeof(*mpdu->mfr));
	mpdu->mfr->fcs = ieee80215_crc_itu(mpdu->skb->data, mpdu->skb->len);
}

/**
 * @brief Create an acknowledgement frame
 */
ieee80215_mpdu_t *ieee80215_create_ack(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_mpdu_t *mpdu, *ack;
	u8 amode, seq, pend_data;
	u16 count;

	dbg_print(mac, 0, DBG_INFO, "skb = 0x%p\n", skb);

	if (!skb) {
		dbg_print(mac, 0, DBG_ERR, "empty skb\n");
		BUG();
	}

	ack = mac_alloc_mpdu(0);
	if (!ack) {
		dbg_print(mac, 0, DBG_ERR, "unable to allocate memory\n");
		return NULL;
	}

	mpdu = skb_to_mpdu(skb);
	seq = mpdu->mhr->seq;
	amode = mpdu->mhr->fc.src_amode;
	if (IEEE80215_AMODE_16BIT == amode) {
		dbg_print(mac, 0, DBG_INFO, "address mode 16bit\n");
		count = ieee80215_pending16_count(mac, mpdu->sa->_16bit);
	} else if (IEEE80215_AMODE_64BIT == amode) {
		dbg_print(mac, 0, DBG_INFO, "address mode 64bit\n");
		count = ieee80215_pending64_count(mac, mpdu->sa->_64bit);
	} else {
		dbg_print(mac, 0, DBG_ERR, "unexpected amode = %u\n", amode);
		BUG();
	}

	pend_data = 0;
	if (count) {
		pend_data = 1;
	}

	dbg_print(mac, 0, DBG_INFO, "sequence number = %u, pend_data = %u\n", seq, pend_data);

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(ack), NULL, NULL, seq, 0, IEEE80215_TYPE_ACK, pend_data);
	ieee80215_calc_crc(ack);
	return ack;
}

ieee80215_mpdu_t* ieee80215_create_assoc_cmd(ieee80215_mac_t *mac,
	ieee80215_dev_addr_t *dst, u8 cap_info)
{
	ieee80215_mpdu_t *mpdu;
	ieee80215_dev_addr_t sa;

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_associate_req_t));
	if(!mpdu) {
		dbg_print(mac, 0, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	mpdu->type = IEEE80215_ASSOCIATION_REQ;

	sa.panid = IEEE80215_PANID_DEF;
	sa._16bit = 0xfffe;
	sa._64bit = cpu_to_le64(mac->pib.dev_addr._64bit);

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &sa, dst, ieee80215_get_dsn(mac),
				1, IEEE80215_TYPE_MAC_CMD, 0);

	/* Payload fillout */
	mpdu->p.areq = (ieee80215_cmd_associate_req_t*) skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_associate_req_t));
	mpdu->p.areq->cmd_id = IEEE80215_ASSOCIATION_REQ;
	memcpy(&mpdu->p.areq->cap, &cap_info, sizeof(cap_info));

	ieee80215_calc_crc(mpdu);

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	return mpdu;
}

/**
 * @brief Beacon request frame
 *
 * @param mac pointer to current MAC
 */
ieee80215_mpdu_t *ieee80215_create_beacon_request_cmd(ieee80215_mac_t *mac)
{
	ieee80215_mpdu_t *mpdu;
	ieee80215_dev_addr_t da;

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_generic_req_t));
	if(!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	da.panid = IEEE80215_PANID_DEF;
	da._16bit = IEEE80215_SHORT_ADDRESS_DEF;

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), NULL, &da, ieee80215_get_dsn(mac),
				0, IEEE80215_TYPE_MAC_CMD, 0);

	dbg_print(mac, CMD, DBG_INFO, "data: 0x%p, len: 0x%d\n",
		 mpdu->skb->data, mpdu->skb->len);

	/* Payload fillout */
	mpdu->p.g = (ieee80215_cmd_generic_req_t*)skb_put(mpdu_to_skb(mpdu),
		     sizeof(ieee80215_cmd_generic_req_t));

	mpdu->p.g->cmd_id = IEEE80215_BEACON_REQ;

	mpdu->type = IEEE80215_BEACON_REQ;

	ieee80215_calc_crc(mpdu);
	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);
	return mpdu;
}

static int comm_status_indication_on_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;
	ieee80215_mpdu_t *msg = skb_to_mpdu(skb);

	pr_debug("code = %u\n", code);

	if (code == IEEE80215_PHY_SUCCESS) {
		code = IEEE80215_SUCCESS;
	}
	/*
	The MLME-COMM-STATUS.indication primitive is generated by the MAC sublayer entity following
	either the MLME-ASSOCIATE.response primitive or the MLME-ORPHAN.response primitive.
	*/
#warning FIXME indication
#if 0
	_nhle(mac)->mlme_comm_status_indication(_nhle(mac), mac->pib.dev_addr.panid,
		msg->mhr->fc.src_amode, msg->sa,
		msg->mhr->fc.dst_amode, msg->da,
		code);
#endif
	return 0;
}

ieee80215_mpdu_t *ieee80215_create_assocresp_cmd(struct ieee80215_mac *mac,
	ieee80215_dev_addr_t *da, u8 status)
{
	ieee80215_mpdu_t *mpdu;
	ieee80215_dev_addr_t sa, dst;

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_associate_resp_t));
	if (!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	mpdu->type = IEEE80215_ASSOCIATION_PERM;

	sa.panid = cpu_to_le16(mac->pib.dev_addr.panid);
	sa._16bit = 0xfffe;
	sa._64bit = cpu_to_le16(mac->pib.dev_addr._64bit);

	dst.panid = sa.panid;
	dst._16bit = 0xfffe;
	dst._64bit = cpu_to_le64(da->_64bit);

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &sa, &dst,
				ieee80215_get_dsn(mac), 1, IEEE80215_TYPE_MAC_CMD, 0);

	/* Payload fillout */
	mpdu->p.aresp = (ieee80215_cmd_associate_resp_t*)skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_associate_resp_t));
	mpdu->p.aresp->cmd_id = IEEE80215_ASSOCIATION_PERM;
	mpdu->p.aresp->status = status;
	mpdu->p.aresp->_16bit = cpu_to_le16(da->_16bit);

	ieee80215_calc_crc(mpdu);
	mpdu->on_confirm = comm_status_indication_on_confirm;

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	return mpdu;
}

ieee80215_mpdu_t *ieee80215_create_disassoc_cmd(struct ieee80215_mac *mac,
		u8 reason, u64 _64bit)
{
	ieee80215_mpdu_t *mpdu;
	ieee80215_dev_addr_t sa, da;

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_disassociate_notify_t));
	if(!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	mpdu->type = IEEE80215_DISASSOCIATION_NOTIFY;

	sa.panid = cpu_to_le16(mac->pib.dev_addr.panid);
	sa._16bit = 0xfffe;
	sa._64bit = cpu_to_le64(mac->pib.dev_addr._64bit);

	da.panid = sa.panid;
	da._16bit = 0xfffe;
	if(reason == IEEE80215_KICK_DEV)
		da._64bit = cpu_to_le64(_64bit);
	else if(reason == IEEE80215_LEAVE_DEV)
		da._64bit = cpu_to_le16(mac->pib.coord._64bit);
	else {
		dbg_print(mac, CMD, DBG_ERR, "BUG(): no reason\n");
		BUG();
	}

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &sa, &da, ieee80215_get_dsn(mac), 1,
				IEEE80215_TYPE_MAC_CMD, 0);

	/* Payload fillout */
	mpdu->p.dn = (ieee80215_cmd_disassociate_notify_t*)skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_disassociate_notify_t));
	mpdu->p.dn->cmd_id = IEEE80215_DISASSOCIATION_NOTIFY;
	mpdu->p.dn->reason = reason;

	ieee80215_calc_crc(mpdu);

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	return mpdu;
}

/**
 * @brief Make data request command
 *
 * This command relevant only for !coordinator, requesting it for a data
 * fetch.
 */
ieee80215_mpdu_t *ieee80215_create_data_request_cmd(struct ieee80215_mac *mac,
				ieee80215_dev_addr_t *dst_addr)
{
	ieee80215_mpdu_t *mpdu;
	ieee80215_dev_addr_t sa;

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_generic_req_t));
	if(!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	read_lock(&mac->pib.lock);
	if (mac->pib.dev_addr._16bit >= 0xfffe) {
		if (mac->pib.dev_addr._64bit != IEEE80215_COORD_EXT_ADDRESS_DEF) {
			sa._64bit = mac->pib.dev_addr._64bit;
			sa._16bit = 0xfffe;
		}
	} else {
		sa._16bit = mac->pib.dev_addr._16bit;
	}
	sa.panid = mac->pib.dev_addr.panid;
	read_unlock(&mac->pib.lock);

	dbg_print(mac, POLL, DBG_INFO,
		"src panid = 0x%x, 16bit = 0x%x, 64bit = 0x%llx\n",
		sa.panid, sa._16bit, sa._64bit);
	dbg_print(mac, POLL, DBG_INFO,
		"dst panid = 0x%x, 16bit = 0x%x, 64bit = 0x%llx\n",
		dst_addr->panid, dst_addr->_16bit, dst_addr->_64bit);

	mpdu->type = IEEE80215_DATA_REQ;
	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &sa, dst_addr,
				ieee80215_get_dsn(mac), 1, IEEE80215_TYPE_MAC_CMD, 0);

	/* Payload fillout */
	mpdu->p.g = (ieee80215_cmd_generic_req_t*)skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_generic_req_t));
	mpdu->p.g->cmd_id = IEEE80215_DATA_REQ;

	ieee80215_calc_crc(mpdu);

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	return mpdu;
}

int ieee80215_data_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;

	dbg_print(mac, DATA, DBG_INFO, "code = %u\n", code);
	return 0;
}

/**
 * @brief PAN ID conflict notification
 *
 * @param mac pointer to current MAC
 */
ieee80215_mpdu_t *ieee80215_create_pid_con_cmd(struct ieee80215_mac *mac)
{
	ieee80215_mpdu_t *mpdu;

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_generic_req_t));
	if(!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	mpdu->type = IEEE80215_PANID_CONFLICT_NOTIFY;

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &mac->pib.dev_addr, &mac->pib.coord,
				ieee80215_get_dsn(mac), 1, IEEE80215_TYPE_MAC_CMD,0);

	/* Payload fillout */
	mpdu->p.g = (ieee80215_cmd_generic_req_t*)skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_generic_req_t));
	mpdu->p.g->cmd_id = IEEE80215_PANID_CONFLICT_NOTIFY;

	ieee80215_calc_crc(mpdu);

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	mpdu->on_confirm = ieee80215_data_confirm;

	return mpdu;
}

/**
 * @brief Orphan notification
 *
 * @param mac pointer to current MAC
 */
ieee80215_mpdu_t *ieee80215_create_orphan_cmd(struct ieee80215_mac *mac)
{
	ieee80215_mpdu_t *mpdu;
	ieee80215_dev_addr_t sa,da;

	if (mac->pib.dev_addr._16bit == 0xfffe) {
		dbg_print(mac, CMD, DBG_INFO,
			"Could not send orhpan notification with 64bit dst address\n");
		return NULL;
	}

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_generic_req_t));
	if (!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	mpdu->type = IEEE80215_ORPHAN_NOTIFY;

	sa.panid = IEEE80215_PANID_DEF;
	sa._16bit = 0xfffe;
	sa._64bit = cpu_to_le64(mac->pib.dev_addr._64bit);

	da.panid = sa.panid;
	da._16bit = IEEE80215_COORD_SHORT_ADDRESS_DEF;

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &sa, &da, ieee80215_get_dsn(mac),
				0, IEEE80215_TYPE_MAC_CMD, 0);

	/* Payload fillout */
	mpdu->p.g = (ieee80215_cmd_generic_req_t*)skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_generic_req_t));
	mpdu->p.g->cmd_id = IEEE80215_ORPHAN_NOTIFY;

	ieee80215_calc_crc(mpdu);

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	return mpdu;
}


/**
 * @brief Coordinator realigment command
 */
ieee80215_mpdu_t *ieee80215_create_realign_cmd(struct ieee80215_mac *mac,
		ieee80215_addr_t *dev_addr, u8 lch)
{
	ieee80215_mpdu_t *mpdu;
	ieee80215_dev_addr_t sa, da;

	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_realign_t));
	if (!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	mpdu->type = IEEE80215_COORD_REALIGN_NOTIFY;

	sa.panid = cpu_to_le16(mac->pib.dev_addr.panid);
	sa._16bit = 0xfffe;
	sa._64bit = cpu_to_le64(mac->pib.dev_addr._64bit);

	da.panid = IEEE80215_PANID_DEF;
	if (dev_addr) {
		da._16bit = 0xfffe;
		da._64bit = cpu_to_le64(dev_addr->_64bit);
	} else {
		da._16bit = IEEE80215_SHORT_ADDRESS_DEF;
	}

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &sa, &da, ieee80215_get_dsn(mac),
				dev_addr?1:0, IEEE80215_TYPE_MAC_CMD, 0);

	/* Payload fillout */
	mpdu->p.r = (ieee80215_cmd_realign_t*)skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_realign_t));
	mpdu->p.r->cmd_id = IEEE80215_COORD_REALIGN_NOTIFY;
	mpdu->p.r->pan_id = cpu_to_le16(mac->pib.dev_addr.panid);
	mpdu->p.r->c_16bit = cpu_to_le16(mac->pib.dev_addr._16bit);
	mpdu->p.r->lch = lch;
	if (dev_addr) {
		mpdu->p.r->_16bit = cpu_to_le16(dev_addr->_16bit);
	} else {
		mpdu->p.r->_16bit = IEEE80215_SHORT_ADDRESS_DEF;
	}

	ieee80215_calc_crc(mpdu);

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	return mpdu;
}

/**
 * @brief GTS request command
 */
ieee80215_mpdu_t *ieee80215_create_gts_request_cmd(struct ieee80215_mac *mac,
		u8 gts_id, u8 gts_len, u8 gts_dir, u8 gts_type, bool sec_enable)
{
	ieee80215_mpdu_t *mpdu;

	if (mac->pib.dev_addr._16bit == IEEE80215_SHORT_ADDRESS_DEF ||
	   mac->pib.dev_addr._16bit == IEEE80215_COORD_SHORT_ADDRESS_64BIT) {
		dbg_print(mac, CMD, DBG_ERR, "Short address must be defined!\n");
		return NULL;
	}

	if (gts_len > 0x8) {
		dbg_print(mac, CMD, DBG_ERR, "GTS length is out of the range\n");
		return NULL;
	}

	if (gts_dir > 0x1) {
		dbg_print(mac, CMD, DBG_ERR, "GTS direction is out of the range\n");
		return NULL;
	}

	if (gts_type > 0x1) {
		dbg_print(mac, CMD, DBG_ERR, "GTS characteristics type is out of the range\n");
		return NULL;
	}


	mpdu = mac_alloc_mpdu(sizeof(ieee80215_cmd_gts_req_t));
	if(!mpdu) {
		dbg_print(mac, CMD, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}

	mpdu->type = IEEE80215_GTS_REQ;

	ieee80215_mpdu_set_addr(mac, mpdu_to_skb(mpdu), &mac->pib.dev_addr, NULL,
				ieee80215_get_dsn(mac), 1, IEEE80215_TYPE_MAC_CMD, 0);

	/* Payload fillout */
	mpdu->p.gts = (ieee80215_cmd_gts_req_t*)skb_put(mpdu_to_skb(mpdu), sizeof(ieee80215_cmd_gts_req_t));
	mpdu->p.gts->cmd_id = IEEE80215_GTS_REQ;

	mpdu->p.gts->c.len = gts_len;
	mpdu->p.gts->c.dir = gts_dir;
	mpdu->p.gts->c.type = gts_type;

	ieee80215_calc_crc(mpdu);

	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);

	return mpdu;
}

/**
 * @brief Make MCPS-DATA request command
 */
int ieee80215_create_mcps_data_req(struct ieee80215_mac *mac, ieee80215_dev_addr_t *src,
				   ieee80215_dev_addr_t *dst, struct sk_buff *skb,
				   u8 with_ack, bool sec_enable)
{
	int intra_pan = 0, dm = IEEE80215_AMODE_NOPAN, sm = IEEE80215_AMODE_NOPAN;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	mpdu->type = IEEE80215_DATA;
	mpdu->mhr = (ieee80215_mhr_t*)skb_put(skb, sizeof(*mpdu->mhr));

	if (src && dst) {
		if (src->panid == dst->panid)
			intra_pan = 1;
	}

	if (src) {
		dbg_print(mac, CORE, DBG_INFO,
			"src = 0x%p, _16bit = %u, mpdu->sa = 0x%p, mpdu->s_panid = 0x%p\n",
			src, src->_16bit, mpdu->sa, mpdu->s_panid);

		if (src->_16bit == 0xfffe) {
			sm = IEEE80215_AMODE_64BIT;
			mpdu->sa = (ieee80215_addr_t *)skb_push(skb, 8);
			mpdu->sa->_64bit = cpu_to_le64(src->_64bit);
		} else {
			sm = IEEE80215_AMODE_16BIT;

			dbg_print(mac, CORE, DBG_INFO, "src111 mpdu->sa = %p\n", mpdu->sa);
			mpdu->sa = (ieee80215_addr_t *)skb_push(skb, 2);
			dbg_print(mac, CORE, DBG_INFO, "src222 mpdu->sa = %p\n", mpdu->sa);

			mpdu->sa->_16bit = cpu_to_le16(src->_16bit);
		}
		if (intra_pan) {
			mpdu->s_panid = NULL;
		} else {
			mpdu->s_panid = (u16*)skb_push(skb, 2);
			*mpdu->s_panid = cpu_to_le16(src->panid);
		}
	}

	if (dst) {
		dbg_print(mac, CORE, DBG_INFO, "dst = 0x%p\n", dst);

		if (dst->_16bit == 0xfffe) {
			dm = IEEE80215_AMODE_64BIT;
			mpdu->da = (ieee80215_addr_t *)skb_push(skb,8);
			mpdu->da->_64bit = cpu_to_le64(dst->_64bit);
		} else {
			dm = IEEE80215_AMODE_16BIT;
			mpdu->da = (ieee80215_addr_t *)skb_push(skb,2);
			mpdu->da->_16bit = cpu_to_le16(dst->_16bit);
		}
		mpdu->d_panid = (u16*)skb_push(skb, 2);
		*mpdu->d_panid = cpu_to_le16(dst->panid);
	}

	mpdu->mhr = (ieee80215_mhr_t*)skb_push(skb, sizeof(*mpdu->mhr));
	ieee80215_pack_fc_and_seq(mac, skb, ieee80215_get_dsn(mac), IEEE80215_TYPE_DATA,
		(mac->f.sec_enable == true ? 1 : 0), 0,with_ack,intra_pan,dm,sm);
	ieee80215_calc_crc(mpdu);
	mpdu->timestamp = jiffies;
	dbg_dump8(mac, CMD, DBG_INFO, mpdu->skb->data, mpdu->skb->len);
	return mpdu->skb->len;
}

static void ieee80215_pending_reset(struct ieee80215_mac *mac)
{
	dbg_print(mac, CMD, DBG_INFO,
		"state = %s, set_default_pib = %u\n",
		s_states[mac->state], mac->f.set_default_pib);

	ieee80215_mac_stop(mac);

	if (mac->f.set_default_pib) {
		ieee80215_set_pib_defaults(&mac->pib);
		mac->f.set_default_pib = false;
	}

	ieee80215_set_mac_defaults(mac);

#warning FIXME indication
#if 0
	_nhle(mac)->mlme_reset_confirm(_nhle(mac), IEEE80215_SUCCESS);
#endif
}

int ieee80215_mlme_reset_req(ieee80215_mac_t *mac, bool def_reset)
{
	dbg_print(mac, 0, DBG_INFO, "state = %s, def_reset = %d\n",
		s_states[mac->state], def_reset);
	switch (mac->state) {
	case WAIT:
	case PEND_AS:
	case PEND_AS1:
	case PEND_PS:
	case PEND_OS:
	case PEND_OS1:
	case YA:
	case ZA:
	case ZP:
	case ACTIVE:
		break;
	default:
		dbg_print(mac, 0, DBG_ERR, "discard\n");
		return -1;
		break;
	}
	ieee80215_set_state(mac, PEND_RESET);

	mac->f.set_default_pib = def_reset;
	ieee80215_net_set_trx_state(mac, IEEE80215_TRX_OFF, ieee80215_pending_reset);
	return 0;
}

void ieee80215_set_beacon_scan_interval(ieee80215_mac_t *mac)
{
	mac->scan.scan_time = usecs_to_jiffies(
		IEEE80215_BASE_SFD * ((1<<mac->scan.duration)+1) * mac->symbol_duration);
	dbg_print(mac, CMD, DBG_INFO,
		"scan duration = %u, symbol_duration = %d, scan_time = %d jiffies\n",
		mac->scan.duration, mac->symbol_duration, mac->scan.scan_time);
}

void ieee80215_set_beacon_interval(ieee80215_mac_t *mac)
{
	if (mac->pib.beacon_order == IEEE80215_BEACON_ORDER_MAX) {
		dbg_print(mac, CORE, DBG_INFO, "BO is max, non-beacon PAN\n");
		mac->pib.superframe_order = mac->pib.beacon_order;
		mac->totaltime = 0;
		mac->sf_time = 0;
		return;
	}

	mac->totaltime = usecs_to_jiffies(
		IEEE80215_BASE_SFD * (1 << mac->pib.beacon_order) * mac->symbol_duration);

	dbg_print(mac, 0, DBG_INFO, "beacon_order: %d, beacon interval: %lu jiffies\n",
		mac->pib.beacon_order, mac->totaltime);
}

void ieee80215_set_superframe_params(ieee80215_mac_t *mac)
{
	u32 sf_len;

	if (mac->pib.beacon_order == IEEE80215_BEACON_ORDER_MAX) {
		mac->pib.superframe_order = mac->pib.beacon_order;
		mac->totaltime = 0;
		mac->sf_time = 0;
		return;
	}

	mac->sf_time = usecs_to_jiffies(
		IEEE80215_BASE_SFD * (1 << mac->pib.superframe_order) * mac->symbol_duration);
	dbg_print(mac, 0, DBG_INFO, "sf_time: %lu jiffies\n", mac->sf_time);

	/* Recalc CAP len */
	sf_len = (IEEE80215_BASE_SFD*(1<<mac->pib.superframe_order));
	dbg_print(mac, CORE, DBG_INFO, "sf_len(syms): %d\n", sf_len);

	mac->i.symbols_per_slot = sf_len/IEEE80215_NUM_SFS;
	dbg_print(mac, CORE, DBG_INFO, "sym/slot (syms): %d\n", mac->i.symbols_per_slot);

	/* The CAP len calculated as SD-<beacon_slot>-<gts_occupied_slots>,
	eg. CAP len is final_cap_slot - <beacon_slot> */
	if (mac->pib.gts_permit) {
		if (!mac->i.i_pan_coord) {
			mac->gts.max_gts = 1;
			/* final_cap_slot updated via beacon */
		} else {
			mac->gts.max_gts = 7;
			mac->i.num_cap_slots = IEEE80215_NUM_SFS - mac->gts.max_gts - 1;
			mac->i.final_cap_slot = IEEE80215_NUM_SFS - mac->gts.s_ln - 1;
		}
		mac->i.cap_len = mac->i.final_cap_slot*mac->i.symbols_per_slot;
		dbg_print(mac, CORE, DBG_INFO,
			"GTS, cap_len(syms): %d, fcs(slot num): %d, gts(count): %d\n",
			mac->i.cap_len, mac->i.final_cap_slot, mac->gts.max_gts);
	} else {
		mac->i.cap_len = sf_len;
		mac->i.num_cap_slots = IEEE80215_NUM_SFS - 1;
		mac->i.final_cap_slot = mac->i.num_cap_slots;
		dbg_print(mac, CORE, DBG_INFO,
			"no GTS, cap_len(syms): %d, fcs(slot num): %d\n",
			mac->i.cap_len, mac->i.final_cap_slot);
	}
	dbg_print(mac, 0, DBG_INFO, "cap_len(syms): %d\n", mac->i.cap_len);
	dbg_print(mac, 0, DBG_INFO,
		"CAP slots(slot num): %d Max GTSs(count): %d\n",
		mac->i.num_cap_slots, mac->gts.max_gts);

	if (mac->i.cap_len < IEEE80215_MIN_CAP_LEN) {
		dbg_print(mac, CORE, DBG_INFO,
			"Beacon PAN, but cap_len(syms(: %d is less than aMinCAPLen(syms): %d\n",
			mac->i.cap_len, IEEE80215_MIN_CAP_LEN);
		mac->i.cap_len = 0;
	}
}

/**
 * @brief Calculate backoffs
 *
 * The backoffs calculated in the manner to find the nearest slot on which
 * any activities are possible.
 */
u32 ieee80215_calc_backoffs(struct ieee80215_mac *mac, u32 rnd_backoff)
{
	u8 curr_slot;
	long unsigned int start_sf, curr_time_slot, delta = 0,
		slot_duration, rnd_delta, slot_boundary;

	/* Find on which slot we are now. */
	start_sf = mac->pib.beacon_tx_time;

	curr_time_slot = (jiffies - start_sf);

	rnd_delta = usecs_to_jiffies(rnd_backoff*mac->symbol_duration);

	slot_duration = usecs_to_jiffies(IEEE80215_BASE_SD*
			(1<<mac->pib.superframe_order)*
			mac->symbol_duration);

	curr_slot = curr_time_slot/slot_duration;

	dbg_print(mac, 0, DBG_INFO,
		"b_tx: %lu, now: %lu, cts: %lu, rnd: %d, rnd_delta: %lu, curr_slot: %d, slot_duration: %lu, sf_time: %d, totaltime: %d\n",
		start_sf, jiffies, curr_time_slot, rnd_backoff, rnd_delta, curr_slot, slot_duration, mac->sf_time, mac->totaltime);

	if (curr_time_slot < mac->sf_time) {
		slot_boundary = curr_slot*slot_duration;
		/* Calculate backoff to next slot */
		/* we in SF, how much we should defer ? */
		if ((mac->pib.gts_permit && curr_slot <= mac->i.final_cap_slot)
			|| !mac->pib.gts_permit) {
			/* Defer till next slot */
			dbg_print(mac, CSMA, DBG_ALL, "In SF\n");
			delta = slot_duration*(curr_slot+1) - curr_time_slot + rnd_delta;
			dbg_print(mac, CSMA, DBG_ALL, "delta: %lu\n", delta);
			return delta;
		}
	} else if (curr_time_slot > mac->sf_time && curr_time_slot < mac->totaltime) {
		dbg_print(mac, CSMA, DBG_ALL, "Not in SF, before next beacon\n");
		delta = mac->totaltime - curr_time_slot + slot_duration;
	} else if (curr_time_slot > mac->totaltime) {
		dbg_print(mac, CSMA, DBG_ALL, "Not in SF, after next beacon\n");
		delta = mac->totaltime+slot_duration-curr_time_slot;
	} else if (curr_time_slot == mac->totaltime) {
		dbg_print(mac, CSMA, DBG_ALL, "In beacon time\n");
		delta = slot_duration;
	}
	/* Now we are on curr_slot */
	dbg_print(mac, 0, DBG_INFO,
		"We are on slot: %d, FCS: %d, delta(next sf): %lu\n",
		curr_slot, mac->i.final_cap_slot, delta);
	return delta;
}


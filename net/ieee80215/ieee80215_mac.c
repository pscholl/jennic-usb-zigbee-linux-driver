/*
 * ieee80215_mac.c
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

#include <net/ieee80215/mac.h>
#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/beacon.h>
#include <linux/timer.h>

char *s_states[] = {
	"WAIT",
	"PEND_AS",
	"PEND_AS1",
	"PEND_OS",
	"PEND_OS1",
	"PEND_PS",
	"YA",
	"ZA",
	"ZP",
	"ACTIVE",
	"B",
	"C",
	"D",
	"E",
	"F",
	"G",
	"H",
	"PEND_RESET",
	"PEND_ED",
	"ED"
};

#if 0
void ieee80215_stop_to_network(ieee80215_mac_t *mac)
{
	unsigned long flags;

	spin_lock_irqsave(&mac->to_network_lock, flags);
	mac->to_network_running = 0;
	spin_unlock_irqrestore(&mac->to_network_lock, flags);
}

void ieee80215_start_to_network(ieee80215_mac_t *mac)
{
	unsigned long flags;

	spin_lock_irqsave(&mac->to_network_lock, flags);
	mac->to_network_running = 1;
	spin_unlock_irqrestore(&mac->to_network_lock, flags);
}

void ieee80215_stop_from_network(ieee80215_mac_t *mac)
{
	unsigned long flags;

	spin_lock_irqsave(&mac->from_network_lock, flags);
	mac->from_network_running = 0;
	spin_unlock_irqrestore(&mac->from_network_lock, flags);
}

void ieee80215_start_from_network(ieee80215_mac_t *mac)
{
	unsigned long flags;

	spin_lock_irqsave(&mac->from_network_lock, flags);
	mac->from_network_running = 1;
	spin_unlock_irqrestore(&mac->from_network_lock, flags);
}
#endif

static void process_to_network_queue(ieee80215_mac_t *mac)
{
	u32 count;

	count = skb_queue_len(&mac->to_network);
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, 0, DBG_INFO, "to network queue length = %u\n", count);
	if (count && mac->to_network_running) {
		ieee80215_csma_ca_start(mac);
	}
}

static void process_from_network_queue(ieee80215_mac_t *mac)
{
	u32 count;

	count = skb_queue_len(&mac->from_network);
	dbg_print(mac, 0, DBG_INFO, "from network queue length = %u\n", count);
	if (count && mac->from_network_running) {
		queue_work(mac->worker, &mac->data_indication);
	}
}

int ieee80215_should_rxon(ieee80215_mac_t *mac)
{
	bool rxon;
	u8 curr_slot;
	u32 start_sf, curr_time_slot, slot_duration, now;

	if (mac->poll_pending || mac->assoc_pending) {
		return 1;
	}

	ieee80215_get_pib(mac, IEEE80215_RXON_WHEN_IDLE, &rxon);
	if (!rxon) {
		return 0;
	}

	if (!ieee80215_slotted(mac)) {
		return 1;
	}

	/* Find on which slot we are now. */
	ieee80215_get_pib(mac, IEEE80215_BEACON_TX_TIME, &start_sf);
	now = jiffies;
	curr_time_slot = (now - start_sf);
	slot_duration = mac->sf_time/IEEE80215_NUM_SFS;
	curr_slot = curr_time_slot/slot_duration;
	/* Now we are on curr_slot */
	dbg_print(mac, CORE, DBG_ALL, "We are on slot: %d\n", curr_slot);
	/* check, if we yet in CAP */
	if (curr_slot <= mac->i.final_cap_slot) {
		return 1;
	}
	return 0;
}

static int recv_ack(ieee80215_mac_t *mac, struct sk_buff *ack)
{
	struct sk_buff *msg;

	msg = skb_peek(&mac->to_network);
	if (!msg) {
		dbg_print(mac, 0, DBG_INFO, "no frame pending, ignore ack\n");
		return 0;
	}
	if (!skb_to_mpdu(msg)->on_confirm) {
		dbg_print(mac, 0, DBG_ERR, "msg->on_confirm is NULL\n");
		BUG();
	}

	dbg_print(mac, 0, DBG_INFO,
		"ack seq num = %u, pending frame seq num = %u\n",
		skb_to_mpdu(ack)->mhr->seq, skb_to_mpdu(msg)->mhr->seq);

	if (skb_to_mpdu(ack)->mhr->seq != skb_to_mpdu(msg)->mhr->seq) {
		dbg_print(mac, 0, DBG_INFO, "unexpected ACK\n");
		return 0;
	}

	ieee80215_dsn_inc(mac);
	cancel_delayed_work(&mac->ack_wait);

	dbg_print(mac, 0, DBG_INFO, "ack->mhr->fc.pend = %u\n",
		skb_to_mpdu(ack)->mhr->fc.pend);

	skb_to_mpdu(msg)->mhr->fc.pend = skb_to_mpdu(ack)->mhr->fc.pend; /* hack */
	skb_to_mpdu(msg)->on_confirm(mac, msg, IEEE80215_PHY_SUCCESS);
	skb_unlink(msg, &mac->to_network);
	kfree_mpdu(skb_to_mpdu(msg));

	/* if we are retransmitting acknowledged frame, cancel retransmission (CCA) */
	cancel_delayed_work(&mac->csma_dwork);
	return 0;
}

static void msg_no_ack(ieee80215_mac_t *mac)
{
	struct sk_buff *msg;

	msg = skb_peek(&mac->to_network);
	if (!msg) {
		dbg_print(mac, 0, DBG_ERR, "no frame pending\n");
		BUG();
	}
	if (!skb_to_mpdu(msg)->on_confirm) {
		dbg_print(mac, 0, DBG_ERR, "msg->on_confirm is NULL\n");
		BUG();
	}

	skb_to_mpdu(msg)->on_confirm(mac, msg, IEEE80215_NO_ACK);
	skb_unlink(msg, &mac->to_network);
	kfree_mpdu(skb_to_mpdu(msg));
	process_to_network_queue(mac);
}

static void ack_timeout(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of(work, ieee80215_mac_t, ack_wait.work);
	struct sk_buff *msg;

	dbg_print(mac, 0, DBG_INFO, "ACK wait timeout\n");

	msg = skb_peek(&mac->to_network);
	if (!msg) {
		dbg_print(mac, 0, DBG_ERR, "no frame pending\n");
		BUG();
	}

	if (skb_to_mpdu(msg)->retries > IEEE80215_MAX_FRAME_RETRIES) {
		int state;
		dbg_print(mac, 0, DBG_ERR, "no ACK for max_frame_retries times\n");
		if (ieee80215_should_rxon(mac)) {
			state = IEEE80215_RX_ON;
		} else {
			state = IEEE80215_TRX_OFF;
		}
		set_trx_state(mac, state, msg_no_ack);
	} else {
		skb_to_mpdu(msg)->retries++;
		dbg_print(mac, 0, DBG_INFO, "retries = %d, resend\n", skb_to_mpdu(msg)->retries);
#if 0
		assume GTS transmissions are not used
		if (msg->gts) {
			dbg_print(mac, 0, DBG_INFO,
				"GTS transmittion, check slice capacity\n");
			ieee80215_gts_send_frame(mac, msg);
		} else {
			ieee80215_csma_ca_start(mac);
		}
#endif
		ieee80215_csma_ca_start(mac);
	}
}

static void ieee80215_data_ack_wait(ieee80215_mac_t *mac)
{
	u16 duration;
	unsigned long j;

	PREPARE_DELAYED_WORK(&mac->ack_wait, ack_timeout);
	ieee80215_get_pib(mac, IEEE80215_ACK_WAIT_DURATION, &duration);
	j = IEEE80215_SLOW_SERIAL_FIXUP * usecs_to_jiffies(duration * mac->symbol_duration);
	dbg_print(mac, 0, DBG_INFO, "wait for ack %lu jiffies\n", j);
	schedule_delayed_work(&mac->ack_wait, j);
}

static const char* state_to_str(int state)
{
	switch (state) {
	case IEEE80215_RX_ON:
		return "RX_ON";
	case IEEE80215_TRX_OFF:
		return "TRX_OFF";
	case IEEE80215_TX_ON:
		return "TX_ON";
	default:
		return "unknown";
	}
}

static int set_trx_state_confirm(struct ieee80215_mac *mac, int code)
{
	if (IEEE80215_PHY_SUCCESS == code || mac->pending_trx_state == code) {
		dbg_print(mac, 0, DBG_INFO, "set %s: ok\n",
			state_to_str(mac->pending_trx_state));
		if (mac->pending_trx_state_func) {
			mac->pending_trx_state_func(mac);
		}
	} else {
		dbg_print(mac, 0, DBG_INFO, "set state attempt failed, retry\n");
		mac->phy->plme_set_trx_state_request(mac->phy, mac->pending_trx_state);
	}
	return 0;
}

void set_trx_state(ieee80215_mac_t *mac, int state, set_trx_state_func_t func)
{
	switch (state) {
	case IEEE80215_RX_ON:
	case IEEE80215_TRX_OFF:
	case IEEE80215_TX_ON:
		dbg_print(mac, 0, DBG_INFO, "set %s\n", state_to_str(state));
		break;
	default:
		dbg_print(mac, 0, DBG_ERR, "state 0x%x is not allowed\n", state);
		return;
	}
	mac->pending_trx_state = state;
	mac->pending_trx_state_func = func;
	mac->plme_set_trx_state_confirm = set_trx_state_confirm;
	mac->phy->plme_set_trx_state_request(mac->phy, state);
}

static void confirm_xmit(ieee80215_mac_t *mac)
{
	struct sk_buff *msg;
	int status, gts = 0;

	msg = skb_peek(&mac->to_network);
	if (!msg) {
		/* May be it was a gts transmittion ? */
		if (mac->curr_gts) {
			dbg_print(mac, DATA, DBG_ALL, "Have curr_gts\n");
			msg = skb_peek(mac->curr_gts->gts_q);
			if (msg) {
				dbg_print(mac, DATA, DBG_ALL, "Have gts data message to confirm\n");
				gts = 1;
				goto process_xmit;
			}
		}
		dbg_print(mac, 0, DBG_ERR, "queue access error\n");
		BUG();
	}
process_xmit:
	if (!skb_to_mpdu(msg)->on_confirm) {
		dbg_print(mac, 0, DBG_ERR, "msg->on_confirm is NULL\n");
		BUG();
	}
	if(skb_to_mpdu(msg)->retries >= IEEE80215_MAX_FRAME_RETRIES)
		status = IEEE80215_BUSY;
	else
		status = IEEE80215_PHY_SUCCESS;
	if (gts)
		skb_unlink(msg, mac->curr_gts->gts_q);
	else
		skb_unlink(msg, &mac->to_network);
	skb_to_mpdu(msg)->on_confirm(mac, msg, status);
	kfree_mpdu(skb_to_mpdu(msg));
	process_to_network_queue(mac);
}

#define DEFINED_CALLBACK(x) {	\
	if(unlikely(!x))	\
		return 0;	\
}

/**
 * \brief PLME-SAP.data_confirm
 *
 * Called by PHY to confirm data in response of data_request.
 *
 * \param mac pointer to current mac
 * \param code result code
 */
int ieee80215_pd_data_confirm(struct ieee80215_mac *mac, int code)
{
	struct sk_buff *msg;
	ieee80215_mpdu_t *mpdu;
	int state;

	msg = skb_peek(&mac->to_network);
	if (!msg) {
		/* May be it was a gts transmittion ? */
		if (mac->curr_gts) {
			msg = skb_peek(mac->curr_gts->gts_q);
			if (msg) {
				goto process_confirm;
			}
		}
		pr_debug("%s:%s: queue access error\n", __FILE__, __FUNCTION__);
		return -EFAULT;
	}
process_confirm:
	mpdu = skb_to_mpdu(msg);

	if (code != IEEE80215_PHY_SUCCESS) {
		mpdu->retries++;
		if (mpdu->retries >= IEEE80215_MAX_FRAME_RETRIES) {
			pr_debug("%s:%s: out of retry limit\n", __FILE__, __FUNCTION__);
			goto exit_ptr;
		}
		pr_debug("%s:%s: xmit request failed, retry\n", __FILE__, __FUNCTION__);
		DEFINED_CALLBACK(mac->phy->pd_data_request);
		mac->phy->pd_data_request(mac->phy, msg);
		return 0;
	}

	pr_debug("%s:%s: xmit request: done\n", __FILE__, __FUNCTION__);

	if (skb_to_mpdu(msg)->mhr->fc.ack_req) {
		pr_debug("%s:%s: ACK required, set RX_ON\n", __FILE__, __FUNCTION__);
		set_trx_state(mac, IEEE80215_RX_ON, ieee80215_data_ack_wait);
		return 0;
	}
	ieee80215_dsn_inc(mac);
exit_ptr:
	if (ieee80215_should_rxon(mac)) {
		state = IEEE80215_RX_ON;
	} else {
		state = IEEE80215_TRX_OFF;
	}
	set_trx_state(mac, state, confirm_xmit);
	return 0;
}

static inline void ieee80215_adjust_payload(ieee80215_mpdu_t *mpdu, u8 p_off)
{
	mpdu->p.g = (ieee80215_cmd_generic_req_t*)(mpdu->skb->data+p_off);
	mpdu->p.areq = (ieee80215_cmd_associate_req_t*)(mpdu->skb->data+p_off);
	mpdu->p.aresp = (ieee80215_cmd_associate_resp_t*)(mpdu->skb->data+p_off);
	mpdu->p.dn = (ieee80215_cmd_disassociate_notify_t*)(mpdu->skb->data+p_off);
	mpdu->p.b = (ieee80215_beacon_payload_t*)(mpdu->skb->data+p_off);
	mpdu->p.gts = (ieee80215_cmd_gts_req_t*)(mpdu->skb->data+p_off);
	mpdu->p.r = (ieee80215_cmd_realign_t*)(mpdu->skb->data+p_off);
}

int ieee80215_ack_confirm(void *obj, struct sk_buff *ack, int code)
{
	ieee80215_mac_t *mac = obj;
	struct sk_buff *received;

	dbg_print(mac, DATA, DBG_INFO, "code = %d\n", code);

	if (IEEE80215_PHY_SUCCESS != code) {
		dbg_print(mac, 0, DBG_INFO, "failed to send ACK, retry\n");
		mac->phy->pd_data_request(mac->phy, ack);
		return 0;
	}
	dbg_print(mac, 0, DBG_INFO, "ACK was sent out\n");

	received = skb_peek(&mac->from_network);
	if (!received) {
		dbg_print(mac, 0, DBG_ERR, "ACK for nothing\n");
		BUG();
	}
	skb_to_mpdu(received)->ack_send = true;

	/* well, let's process special case here.
	data request received, ACK is sent, no data pending. */
	if ((IEEE80215_TYPE_MAC_CMD == skb_to_mpdu(received)->mhr->fc.type)
		&& (IEEE80215_DATA_REQ == skb_to_mpdu(received)->p.g->cmd_id)
		&& (IEEE80215_TYPE_ACK == skb_to_mpdu(ack)->mhr->fc.type)
		&& (!skb_to_mpdu(ack)->mhr->fc.pend)) {
		dbg_print(mac, 0, DBG_ALL, "data request received, no data pending, discard request\n");
		skb_unlink(received, &mac->from_network);
		kfree_mpdu(skb_to_mpdu(received));
	}

	mac->from_network_running = 1;
	process_from_network_queue(mac);
	return 0;
}

static void ieee80215_ack_perform(ieee80215_mac_t *mac)
{
	struct sk_buff *skb;

	skb = skb_peek(&mac->to_network);
	if (!skb || IEEE80215_TYPE_ACK != skb_to_mpdu(skb)->mhr->fc.type) {
		dbg_print(mac, 0, DBG_ERR, "queue access error\n");
		BUG();
	}

	dbg_print(mac, 0, DBG_INFO, "sending out an ack\n");
	mac->phy->pd_data_request(mac->phy, skb);
}

void ieee80215_adjust_pointers(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	u8 addr_off = 0, intra_pan = 0;
	ieee80215_fc_t *fc;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	mpdu->mhr = (ieee80215_mhr_t*)mpdu->skb->data;
	fc = &mpdu->mhr->fc;

	dbg_print(mac, CMD, DBG_ALL,
		"type: %d, sec: %d, pend: %d, ack_req: %d, intra_pan: %d, dst addr mode: %d, src addr mode: %d\n",
		fc->type, fc->security, fc->pend, fc->ack_req, fc->intra_pan, fc->dst_amode, fc->src_amode);

	intra_pan = fc->intra_pan;

	switch (fc->dst_amode) {
	case IEEE80215_AMODE_16BIT:
		addr_off += sizeof(u16);
		break;
	case IEEE80215_AMODE_64BIT:
		addr_off += sizeof(u64);
		break;
	default:
		mpdu->da = NULL;
		mpdu->d_panid = NULL;
		addr_off = 0;
		break;
	}

	if (addr_off) {
		mpdu->d_panid = (u16*)(mpdu->skb->data + sizeof(*mpdu->mhr));
		mpdu->da = (ieee80215_addr_t*)((u8*)mpdu->d_panid + sizeof(*mpdu->d_panid));
		if (intra_pan) {
			mpdu->s_panid = mpdu->d_panid;
			mpdu->sa = (ieee80215_addr_t*)(((u8*)mpdu->da) + addr_off);
		} else {
			mpdu->s_panid = (u16*)(((u8*)mpdu->da) + addr_off);
			mpdu->sa = (ieee80215_addr_t*)(((u8*)mpdu->s_panid) + addr_off);
		}
	} else {
		mpdu->s_panid = (u16*)(mpdu->skb->data + sizeof(*mpdu->mhr));
		mpdu->sa = (ieee80215_addr_t*)((u8*)mpdu->s_panid + sizeof(*mpdu->s_panid));
	}

	switch (mpdu->mhr->fc.src_amode) {
	case IEEE80215_AMODE_16BIT:
		addr_off += sizeof(u16);
		break;
	case IEEE80215_AMODE_64BIT:
		addr_off += sizeof(u64);
		break;
	default:
		mpdu->sa = NULL;
		if (!intra_pan)
			mpdu->s_panid = NULL;
		break;
	}

	if (intra_pan) {
		addr_off += sizeof(u16);
	} else {
		addr_off += mpdu->d_panid?sizeof(u16):0;
		addr_off += mpdu->s_panid?sizeof(u16):0;
	}

	dbg_print(mac, 0, DBG_ALL,
		"addr_off = %u, s_panid = 0x%p, mhr = 0x%p, da = 0x%p, sa = 0x%p\n",
		sizeof(*mpdu->mhr)+addr_off, mpdu->s_panid, mpdu->mhr, mpdu->da, mpdu->sa);

	ieee80215_adjust_payload(mpdu, sizeof(*mpdu->mhr)+addr_off);
	mpdu->mfr = (ieee80215_mfr_t*)(skb->data + skb->len - 2);
	dump_mpdu(mac, mpdu);
	return;
}

int ieee80215_filter_af(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	u16 local_panid, panid, local16, dst16;
	u64 local64, dst64;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	dbg_print(mac, 0, DBG_INFO, "mpdu = 0x%p\n", mpdu);

	ieee80215_get_pib(mac, IEEE80215_PANID, &local_panid);

	if (mpdu->da) {
		panid = le16_to_cpu(*mpdu->d_panid);
	} else if (mpdu->sa) {
		panid = le16_to_cpu(*mpdu->s_panid);
	} else {
		dbg_print(mac, 0, DBG_ERR,
			"frame w/o addressing: dst = 0x%p, src = 0x%p\n",
			mpdu->da, mpdu->sa);
		return 1;
	}

	dbg_print(mac, 0, DBG_INFO,
		"panid = 0x%x, local panid = 0x%x\n",
		panid, local_panid);

	if (panid != 0xffff && local_panid != 0xffff && panid != local_panid) {
		dbg_print(mac, 0, DBG_INFO,
			"remote panid does not match local, discard frame\n");
		return 1;
	}

	dbg_print(mac, 0, DBG_ALL, "dst address mode = %d\n",
		mpdu->mhr->fc.dst_amode);

	switch (mpdu->mhr->fc.dst_amode) {
	case IEEE80215_AMODE_16BIT:
		ieee80215_get_pib(mac, IEEE80215_SHORT_ADDRESS, &local16);
		dst16 = le16_to_cpu(mpdu->da->_16bit);

		dbg_print(mac, 0, DBG_ALL, "dst16 = 0x%x, our = 0x%x\n",
			dst16, local16);

		if (dst16 == 0xffff || local16 == 0xffff || dst16 == local16) {
			/* match, frame is for us */
			mpdu->filtered = true;
		}
		break;
	case IEEE80215_AMODE_64BIT:
		local64 = mac->pib.dev_addr._64bit;
		dst64 = le64_to_cpu(mpdu->da->_64bit);

		dbg_print(mac, 0, DBG_ALL, "dst64 = 0x%llx, local64 = 0x%llx\n",
			dst64, local64);

		if (dst64 == local64) {
			/* match, frame is for us */
			mpdu->filtered = true;
		}
		break;
	default:
		dbg_print(mac, 0, DBG_ALL, "no dst addr\n");
		if (mpdu->sa && (0xffff == panid || 0xffff == local_panid || panid == local_panid)) {
			mpdu->filtered = true;
		}
		break;
	}

	dbg_print(mac, 0, DBG_ALL, "mpdu->filtered = %u\n", mpdu->filtered);
	return 0;
}

/**
 * \brief PD-SAP.data_indication
 *
 * Called by PHY to inform about data availability.
 *
 * \param mac	pointer to current mac
 * \param mpdu	actual mpdu
 */
int ieee80215_pd_data_indicate(struct ieee80215_mac *mac, struct sk_buff *skb)
{
	bool promiscuous_mode;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	dbg_dump8(mac, 0, DBG_INFO, skb->data, skb->len);

	ieee80215_adjust_pointers(mac, skb);

	ieee80215_get_pib(mac, IEEE80215_PROMISCOUS_MODE, (u8*)&promiscuous_mode);
	if (promiscuous_mode) {
#if 0
		ieee80215_mpdu_t *cloned_mpdu;
		cloned_mpdu = mpdu_clone(mpdu);
		if (!cloned_mpdu) {
			dbg_print(mac, DATA, DBG_ERR, "Unable to clone mpdu\n");
		} else {
			ieee80215_adjust_pointers(mac, cloned_mpdu);
			dbg_print(mac, DATA, DBG_INFO, "In promiscuous_mode\n");
			_nhle(mac)->mcps_data_indication(_nhle(mac), cloned_mpdu);
		}
#endif
		dbg_print(mac, 0, DBG_INFO, "In promiscuous_mode\n");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mcps_data_indication(_nhle(mac), skb);
#endif
	}

	if (ieee80215_ignore_mpdu(mac, skb)) {
		dbg_print(mac, 0, DBG_INFO, "Ignoring frame\n");
		kfree_mpdu(mpdu);
		return 0;
	}

	if (IEEE80215_TYPE_ACK == mpdu->mhr->fc.type) {
		dbg_print(mac, 0, DBG_INFO,
			"ACK received, seq: %d\n", mpdu->mhr->seq);
		mpdu->filtered = true;
		goto filtered;
	}

	if (ieee80215_filter_af(mac, skb) || !mpdu->filtered) {
		dbg_print(mac, 0, DBG_INFO,
			"Drop frame, it does not match filter rules\n");
		kfree_mpdu(mpdu);
		return 0;
	}

filtered:
	dbg_print(mac, 0, DBG_INFO, "queue frame for local processing\n");
	skb_queue_tail(&mac->from_network, skb);
	queue_work(mac->worker, &mac->data_indication);
	return 0;
}

static void process_incoming_frame(ieee80215_mac_t *mac)
{
	struct sk_buff *mpdu;

	mpdu = skb_peek(&mac->from_network);
	BUG_ON(!mpdu);

	dbg_print(mac, 0, DBG_INFO, "frame type = %d\n", skb_to_mpdu(mpdu)->mhr->fc.type);

	switch (skb_to_mpdu(mpdu)->mhr->fc.type) {
	case IEEE80215_TYPE_DATA:
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mcps_data_indication(_nhle(mac), mpdu);
#endif
		break;
	case IEEE80215_TYPE_ACK:
		recv_ack(mac, mpdu);
		break;
	case IEEE80215_TYPE_MAC_CMD:
		ieee80215_parse_cmd(mac, mpdu);
		break;
	case IEEE80215_TYPE_BEACON:
		ieee80215_parse_beacon(mac, mpdu);
		break;
	default:
		dbg_print(mac, 0, DBG_INFO, "unexpected frame type\n");
		break;
	}
	skb_unlink(mpdu, &mac->from_network);
	kfree_mpdu(skb_to_mpdu(mpdu));
	process_to_network_queue(mac);
	process_from_network_queue(mac);
}

static void bg_data_indication(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of(work, ieee80215_mac_t, data_indication);
	struct sk_buff *skb;
	ieee80215_mpdu_t *mpdu;
	int state;

	if (!mac->from_network_running) {
		dbg_print(mac, 0, DBG_ALL, "from network queue is stopped\n");
		return;
	}

	skb = skb_peek(&mac->from_network);
	if (!skb) {
		dbg_print(mac, 0, DBG_ALL, "from network queue is empty\n");
		return;
	}
	mpdu = skb_to_mpdu(skb);
	dbg_print(mac, 0, DBG_ALL, "mpdu = 0x%p\n", mpdu);
	if (mpdu->mhr->fc.ack_req && !mpdu->ack_send) {
		ieee80215_mpdu_t *ack;
		dbg_print(mac, 0, DBG_ALL, "ACK required\n");
		if (!ieee80215_can_process_ack(mac, skb)) {
			dbg_print(mac, 0, DBG_ALL, "no time slice left, drop frame\n");
			skb_unlink(skb, &mac->from_network);
			kfree_mpdu(mpdu);
			return;
		}
		ack = ieee80215_create_ack(mac, skb);
		if (ack) {
			ack->on_confirm = ieee80215_ack_confirm;
			mac->from_network_running = 0;
			skb_queue_head(&mac->to_network, mpdu_to_skb(ack));
			set_trx_state(mac, IEEE80215_TX_ON, ieee80215_ack_perform);
		}
		return;
	}

	dbg_print(mac, 0, DBG_INFO, "frame type = %d\n", mpdu->mhr->fc.type);

	if (mac->assoc_pending && IEEE80215_TYPE_MAC_CMD == mpdu->mhr->fc.type
		&& IEEE80215_ASSOCIATION_PERM == mpdu->p.g->cmd_id) {
		mac->assoc_pending = false;
		cancel_delayed_work(&mac->associate_timeout);
	}

	if (mac->poll_pending && IEEE80215_TYPE_DATA == mpdu->mhr->fc.type) {
		mac->poll_pending = false;
		cancel_delayed_work(&mac->poll_request);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_poll_confirm(_nhle(mac), IEEE80215_SUCCESS);
#endif
	}

	if (ieee80215_in_scanning(mac) || ieee80215_should_rxon(mac)) {
		state = IEEE80215_RX_ON;
	} else {
		state = IEEE80215_TRX_OFF;
	}
	set_trx_state(mac, state, process_incoming_frame);
}

static ieee80215_mac_t *ieee80215_mac_alloc(const char *name)
{
	ieee80215_mac_t *mac = NULL;
	size_t nlen;

	mac = kzalloc(sizeof(*mac), GFP_KERNEL);
	if (!mac) {
		printk(KERN_ERR "unable to allocate memory\n");
		return NULL;
	}

	nlen = strlen(name)+5;
	mac->name = kzalloc(nlen, GFP_KERNEL);
	if (!mac->name) {
		printk(KERN_ERR "mac->name allocation failed\n");
		kfree(mac);
		return NULL;
	}
	snprintf(mac->name, nlen, "%s:%s", name, "mac");

	return mac;
}

static void ieee80215_free(ieee80215_mac_t *mac)
{
	if (mac) {
		kfree(mac->scan.ed_detect_list);
		kfree(mac->name);
		kfree(mac);
	}
}

static void ieee80215_set_acl_defaults(ieee80215_acl_pib_head_t *acl, ieee80215_pib_t *pib)
{
	acl->pib.addr._16bit = IEEE80215_COORD_SHORT_ADDRESS_DEF;
	acl->pib.addr._64bit = pib->dev_addr._64bit;
	acl->pib.addr.panid = IEEE80215_PANID_DEF;
	acl->pib.sec_mlen = IEEE80215_DEFAULT_SECURITY_MLEN_DEF;
	acl->pib.sec_material = IEEE80215_DEFAULT_SECURITY_MATERIAL_DEF;
	acl->pib.sec_suite = IEEE80215_DEFAULT_SECURITY_SUITE_DEF;
}

static int ieee80215_init_acl(ieee80215_acl_pib_head_t *acl, ieee80215_mac_t *mac)
{
	if(!acl)
		return -EINVAL;

	spin_lock_init(&acl->lock);
	INIT_LIST_HEAD(&acl->pib.list);
	acl->count = 0;
	return 0;
}

void ieee80215_set_pib_defaults(ieee80215_pib_t *pib)
{
	pib->ack_wait_duration = IEEE80215_ACK_WAIT_DURATION_DEF;
	pib->auto_request = IEEE80215_AUTO_REQUEST_DEF;
	pib->bat_life_ext = IEEE80215_BAT_LIFE_EXT_DEF;
	pib->bat_life_ext_period = IEEE80215_BAT_LIFE_EXT_PERIOD_DEF;
	pib->coord._16bit = IEEE80215_COORD_SHORT_ADDRESS_DEF;
	pib->coord._64bit = IEEE80215_COORD_EXT_ADDRESS_DEF;
	pib->dsn = IEEE80215_DSN_DEF;
	pib->max_csma_backoff = IEEE80215_MAX_CSMA_BACKOFF_DEF;
	pib->min_be = IEEE80215_MIN_BE_DEF;
	pib->dev_addr.panid = IEEE80215_PANID_DEF;
	pib->rxon = IEEE80215_RXON_WHEN_IDLE_DEF;
	pib->dev_addr._16bit = IEEE80215_SHORT_ADDRESS_DEF;
	pib->def_sec = IEEE80215_DEFAULT_SECURITY_DEF;
	pib->def_sec_material = IEEE80215_DEFAULT_SECURITY_MATERIAL_DEF;
	pib->def_sec_mlen = IEEE80215_DEFAULT_SECURITY_MLEN_DEF;
	pib->def_sec_suite = IEEE80215_DEFAULT_SECURITY_SUITE_DEF;
	pib->sec_mode = IEEE80215_SECURITY_MODE_DEF;
#ifndef CONFIG_IEEE80215_RFD_NOOPT
	pib->association_permit = IEEE80215_ASSOCIATION_PERMIT_DEF;
	pib->beacon_payload = IEEE80215_BEACON_PAYLOAD_DEF;
	pib->beacon_payload_len = IEEE80215_BEACON_PAYLOAD_LEN_DEF;
	pib->beacon_order = IEEE80215_BEACON_ORDER_DEF;
	pib->beacon_tx_time = IEEE80215_BEACON_TX_TIME_DEF;
	pib->bsn = IEEE80215_BSN_DEF;
	pib->gts_permit = IEEE80215_GTS_PERMIT_DEF;
	pib->promiscuous_mode = IEEE80215_PROMISCOUS_MODE_DEF;
	pib->superframe_order = IEEE80215_SUPERFRAME_ORDER_DEF;
	pib->tr_pers_time = IEEE80215_TRANSACTION_PERSISTENSE_TIME_DEF;
#endif
	pib->rx_gts_id = 0;
	pib->tx_gts_id = 0;

	ieee80215_set_acl_defaults(&pib->acl_entries, pib);
}

int ieee80215_init_pib(ieee80215_pib_t *pib, ieee80215_mac_t *mac)
{
	if (!pib)
		return -EINVAL;

	ieee80215_set_pib_defaults(pib);

	if (ieee80215_init_acl(&pib->acl_entries, mac)) {
		dbg_print(mac, CORE, DBG_ERR_CRIT, "Cannot init acl entries\n");
		return -EINVAL;
	}
	return 0;
}

static void ieee80215_gts_close(ieee80215_mac_t *mac)
{
	ieee80215_gts_info_t *g;
	struct list_head *it;

	while (!list_empty(&mac->gts.db.list)) {
		it = mac->gts.db.list.next;
		g = container_of(it, ieee80215_gts_info_t, list);
		if (!g) {
			dbg_print(mac, 0, DBG_ERR, "No GTS entry found\n");
		}
		list_del(it);
		cancel_delayed_work(&g->gts_work);
		skb_queue_purge(g->gts_q);
		kfree(g->gts_q);
		kfree(g);
	}
}

static int ieee80215_init_gts(ieee80215_mac_t *mac)
{
	int i;
	ieee80215_gts_info_t *g;

	if (!mac->f.pan_coord) {
		mac->gts.max_gts = 1;
	} else
		mac->gts.max_gts = 8;

	mac->gts.active_count = 0;

	INIT_LIST_HEAD(&mac->gts.db.list);
	mac->i.final_cap_slot = IEEE80215_NUM_SFS;
	spin_lock_init(&mac->gts.lock);

	memset(&mac->gts.rc, 0, sizeof(mac->gts.rc));

	for( i=0; i<mac->gts.max_gts; i++) {
		g = (ieee80215_gts_info_t *)kmalloc(sizeof(*g), GFP_KERNEL);
		g->id = 0;
		g->starting_slot = 0;
		g->use_count = 0;
		g->active = false;
		g->gts_q = kmalloc(sizeof(*g->gts_q), GFP_KERNEL);
		g->mac = mac;
		INIT_DELAYED_WORK(&g->gts_work, ieee80215_gts_process_slice);
		skb_queue_head_init(g->gts_q);
		list_add_tail(&g->list, &mac->gts.db.list);
	}

	mac->gts.id = 0;
	return 0;
}

void ieee80215_clear_scan(ieee80215_mac_t *mac)
{
	ieee80215_pan_desc_t *pdesc;
	struct list_head *itr, *tmp;

	cancel_delayed_work(&mac->scan.work);
	pr_debug("locking\n");
	spin_lock(&mac->scan.desc.lock);
	list_for_each_safe(itr, tmp, &mac->scan.desc.list) {
		pdesc = container_of(itr, ieee80215_pan_desc_t, list);
		list_del(itr);
		mac->scan.desc.count--;
		kfree(pdesc);
	}
	if (mac->scan.desc.count) {
		pr_debug("mac->scan.desc is inconsistent: mac->scan.desc.count = %u, must be 0\n",
			mac->scan.desc.count);
		mac->scan.desc.count = 0;
	}
	spin_unlock(&mac->scan.desc.lock);
	pr_debug("unlocking\n");
	mac->scan.status = 0;
	mac->scan.type = 0;
	mac->scan.duration = 0;
	mac->scan.current_channel = 0;
	mac->scan.ch_list = 0;
	mac->scan.unscan_ch = 0;
	mac->scan.result_size = 0;
	mac->scan.scan_time = 0;
	mac->scan.delta_scan = 0;
	mac->scan.tmp_panid = 0;
	mac->scan.start_scan = 0;
	mac->scan.channels_below_threshold = 0;
	mac->scan.ed_detect_list = NULL;
}

void ieee80215_set_mac_defaults(ieee80215_mac_t *mac)
{
	ieee80215_clear_scan(mac);
	mac->scan.tmp_panid = 0xffff;
	mac->i.csma_val.nb = 0;
	mac->i.current_channel = 0;
#ifndef CONFIG_IEEE80215_RFD_NOOPT
	mac->f.ffd_device = true;
#else
	mac->f.ffd_device = false;
#endif
	mac->f.find_a_beacon = false;
	if (mac->pib.gts_permit)
		mac->i.cap_len = 16;
	mac->f.too_late = false;
	mac->f.phy_in_tx = false;
	mac->f.broadcast = false;
	mac->f.beacon_enabled_pan = false;
	mac->no_addr._16bit = 0;
	mac->symbol_duration = IEEE80215_2450MHZ_1SYM_TIME;
	mac->i.num_comm_failures = 0;
	mac->i.num_gts = 0;
	mac->scan.unscan_ch = 0;
	mac->i.res_size = 0;
	mac->state = WAIT;
}

int ieee80215_init(ieee80215_mac_t *mac)
{
	int ret;

	spin_lock_init(&mac->lock);
	rwlock_init(&mac->pib.lock);
	spin_lock_init(&mac->scan.desc.lock);
	INIT_LIST_HEAD(&mac->scan.desc.list);

	mac->from_network_running = 1;
	skb_queue_head_init(&mac->from_network);

	mac->to_network_running = 1;
	skb_queue_head_init(&mac->to_network);

	skb_queue_head_init(&mac->tr16);
	skb_queue_head_init(&mac->tr64);

	INIT_DELAYED_WORK(&mac->scan.work, NULL);
	ieee80215_set_mac_defaults(mac);

	if (ieee80215_init_gts(mac)) {
		dbg_print(mac, CORE, DBG_ERR_CRIT, "Could not init GTS DB\n");
		return -EFAULT;
	}

	mac->worker = create_workqueue(mac->name);
	if(!mac->worker) {
		dbg_print(mac, CORE, DBG_ERR_CRIT, "Could not create worker\n");
		ret = -EFAULT;
		goto err_exit_gts_free;
	}

	/* defer initialization until actual use */
	INIT_WORK(&mac->get_request, NULL);
	INIT_WORK(&mac->set_request, NULL);
	INIT_WORK(&mac->data_indication, bg_data_indication);
	INIT_WORK(&mac->purge_request, NULL);
	INIT_DELAYED_WORK(&mac->bwork, NULL);
	INIT_DELAYED_WORK(&mac->data_request, NULL);
	INIT_DELAYED_WORK(&mac->gts_request, NULL);
	INIT_DELAYED_WORK(&mac->associate_request, NULL);
	INIT_DELAYED_WORK(&mac->associate_timeout, NULL);
	INIT_DELAYED_WORK(&mac->disassociate_request, NULL);
	INIT_DELAYED_WORK(&mac->rx_enable_request, NULL);
	INIT_DELAYED_WORK(&mac->sync_request, NULL);
	INIT_DELAYED_WORK(&mac->poll_request, NULL);
	INIT_DELAYED_WORK(&mac->ack_wait, NULL);
	INIT_DELAYED_WORK(&mac->csma_dwork, NULL);

	mac->pd_data_confirm = ieee80215_pd_data_confirm;
	mac->pd_data_indicate = ieee80215_pd_data_indicate;

	mac->mcps_data_req = ieee80215_mcps_data_request;
	mac->mlme_assoc_req = ieee80215_mlme_assoc_req;
	mac->mlme_assoc_reply = ieee80215_mlme_assoc_reply;
	mac->mlme_get_req = ieee80215_mlme_get_req;
	mac->mlme_set_req = ieee80215_mlme_set_req;
	mac->mlme_reset_req = ieee80215_mlme_reset_req;
	mac->mlme_rxen_req = ieee80215_mlme_rxen_req;
	mac->mlme_scan_req = ieee80215_mlme_scan_req;
	mac->mlme_orphan_resp = ieee80215_mlme_orphan_resp;
	mac->mlme_disassoc_req = ieee80215_mlme_disassoc_req;
	mac->mlme_sync_req = ieee80215_mlme_sync_req;
	mac->mlme_poll_req = ieee80215_mlme_poll_req;
#ifndef CONFIG_IEEE80215_RFD_NOOPT
	mac->mcps_purge_req = ieee80215_mcps_purge_request;
	mac->mlme_gts_req = ieee80215_mlme_gts_req;
	mac->mlme_start_req = ieee80215_mlme_start_req;
#endif
	return 0;
err_exit_gts_free:
	ieee80215_gts_close(mac);
	return ret;
}

void ieee80215_mac_stop(ieee80215_mac_t *mac)
{
	ieee80215_gts_close(mac);

	dbg_print(mac, 0, DBG_INFO, "going to purge tr16\n");
	skb_queue_purge(&mac->tr16);

	dbg_print(mac, 0, DBG_INFO, "going to purge tr64\n");
	skb_queue_purge(&mac->tr64);

	dbg_print(mac, 0, DBG_INFO, "going to purge to_network\n");
	skb_queue_purge(&mac->to_network);

	dbg_print(mac, 0, DBG_INFO, "going to purge from_network\n");
	skb_queue_purge(&mac->from_network);

	dbg_print(mac, 0, DBG_INFO, "going to clear scan\n");
	ieee80215_clear_scan(mac);

	cancel_delayed_work(&mac->bwork);
	cancel_delayed_work(&mac->data_request);
	cancel_delayed_work(&mac->gts_request);
	cancel_delayed_work(&mac->associate_request);
	cancel_delayed_work(&mac->associate_timeout);
	cancel_delayed_work(&mac->disassociate_request);
	cancel_delayed_work(&mac->rx_enable_request);
	cancel_delayed_work(&mac->sync_request);
	cancel_delayed_work(&mac->poll_request);
	cancel_delayed_work(&mac->ack_wait);
	cancel_delayed_work(&mac->csma_dwork);

	work_clear_pending(&mac->data_indication);
	work_clear_pending(&mac->purge_request);
	work_clear_pending(&mac->start_request);
	work_clear_pending(&mac->get_request);
	work_clear_pending(&mac->set_request);

	flush_workqueue(mac->worker);
}

void ieee80215_mac_close(ieee80215_mac_t *mac)
{
	dbg_print(mac, CORE, DBG_ALL, "mac = 0x%p\n", mac);
	ieee80215_mac_stop(mac);
	destroy_workqueue(mac->worker);
	dbg_print(mac, CORE, DBG_ALL, "done\n");
}

int ieee80215_register_phy(ieee80215_phy_t *phy)
{
	ieee80215_mac_t *mac;
	int ret;

	if (!phy) {
		printk(KERN_WARNING "Unable to register NULL phy\n");
		return -EINVAL;
	}

	if (!phy->name) {
		printk(KERN_WARNING  "Unable to register phy with null name\n");
		return -EINVAL;
	}

	if (!phy->dev_op) {
		printk(KERN_WARNING  "Unable to register phy with null device\n");
		return -EINVAL;
	}

	if (phy->priv) {
		printk(KERN_WARNING  "Looks like phy is already registered with a mac\n");
		return -EINVAL;
	}

	mac = ieee80215_mac_alloc(phy->dev_op->name);
	if (!mac) {
		printk(KERN_WARNING  "Unable to allocate MAC\n");
		return -ENOMEM;
	}

	phy->priv = mac;
	mac->phy = phy;

	mac->pib.dev_addr._64bit = phy->dev_op->_64bit;
	pr_debug("mac = 0x%p, dev_addr_64bit = 0x%llx\n",
		mac, mac->pib.dev_addr._64bit);

	if (ieee80215_init_pib(&mac->pib, mac)) {
		dbg_print(mac, CORE, DBG_ERR_CRIT, "Cannot init pib\n");
		ret = -EINVAL;
		goto err_exit_memfree;
	}

	if (ieee80215_init(mac)) {
		pr_debug("Unable to init MAC\n");
		ret = -EINVAL;
		goto err_exit_memfree;
	}

#warning mac registration with nwk needs rewriting
#if 0
	if (zb_register_mac(mac)) {
		dbg_print(mac, CORE, DBG_ERR_CRIT, "Unable to register MAC\n");
		ret = -EINVAL;
		goto err_exit_memfree;
	}
#endif

	return 0;
err_exit_memfree:
	phy->priv = NULL;
	ieee80215_free(mac);
	return ret;
}

int ieee80215_unregister_phy(ieee80215_phy_t *phy)
{
	ieee80215_mac_t *mac;

	if (!phy) {
		printk(KERN_WARNING "Unable to unregister NULL phy\n");
		return -EINVAL;
	}
	mac = _mac(phy);
	if (!mac) {
		printk(KERN_WARNING "Unable to unregister NULL mac\n");
		return -EINVAL;
	}

	ieee80215_mac_close(mac);
#warning mac registration with nwk needs rewriting
#if 0
	zb_unregister_mac(mac);
#endif
	ieee80215_free(mac);
	return 0;
}


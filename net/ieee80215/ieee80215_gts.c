/*
 * ieee80215_gts.c
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
 */

#include <linux/timer.h>
#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/const.h>
#include <net/ieee80215/beacon.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>

int ieee80215_gts_start_slice(ieee80215_mac_t *mac, int code);
int ieee80215_gts_data_confirm(void *obj, struct sk_buff *skb, int code);
int ieee80215_gts_data_ack_recv(ieee80215_mac_t *mac, struct sk_buff *skb);

static inline u32 ieee80215_gts_expire_time(ieee80215_mac_t *mac)
{
	u8 n, bo;
	long unsigned int to;
	ieee80215_get_pib(mac, IEEE80215_BEACON_ORDER, &bo);
	if (bo <= 8) {
		n = 2*(1<<(8-bo)); /* 2*n^(8-bo) */
	} else {
		n = 2; /* 2*n, where n==1 */
	}

	to = n*mac->sf_time;
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, GTS, DBG_INFO, "GTS expiration time: %lu, n: %d, sflen: %lu\n",
		  to, n, mac->sf_time);
	return jiffies + to;
}

static inline u32 ieee80215_wind_gts_watch(ieee80215_mac_t *mac)
{
	long unsigned int ret;
	u8 so;

	ieee80215_get_pib(mac, IEEE80215_SUPERFRAME_ORDER, &so);
	ret = usecs_to_jiffies(IEEE80215_GTS_DESC_PERS_TIME*
			(IEEE80215_BASE_SFD *(1<<so))*mac->symbol_duration);

	dbg_print(mac, GTS, DBG_INFO, "GTS presense time: %lu\n", ret);
	return ret + jiffies;
}

long unsigned int ieee80215_gts_time_available(ieee80215_mac_t *mac)
{
	u32 gts_slice_end;
	gts_slice_end = mac->curr_gts->start +
			usecs_to_jiffies((mac->curr_gts->c.len*mac->i.symbols_per_slot -
			IEEE80215_TURNAROUND_TIME)*mac->symbol_duration);
	if (jiffies < gts_slice_end) {
		return gts_slice_end - jiffies;
	}
	return 0;
}

u32 ieee80215_calc_next_gts_time(ieee80215_mac_t *mac, ieee80215_gts_info_t *gts)
{
	long unsigned int gts_offset, next_sf_time = 0, btx, ret;
	u8 bo;

	ieee80215_get_pib(mac, IEEE80215_BEACON_TX_TIME, (u8*)&btx);
	ieee80215_get_pib(mac, IEEE80215_BEACON_ORDER, &bo);

	gts_offset = usecs_to_jiffies(gts->starting_slot *
			mac->i.symbols_per_slot *
			mac->symbol_duration);

	/* should we defer till next cfp ? */
	if (jiffies > (btx + gts_offset)) {
		/* we are miss our cfp, schedule to next sf */
		next_sf_time = btx + mac->totaltime - jiffies;
		ret = next_sf_time + gts_offset;
		dbg_print(mac, GTS, DBG_ERR, "GTS defer till next sf\n");

	} else {
		ret = btx + gts_offset - jiffies;
		dbg_print(mac, GTS, DBG_ERR, "GTS yet in this sf\n");
	}

	if (!ret) {
		dbg_print(mac, GTS, DBG_ERR,
			"btx: %lu, bi: %lu, j: %lu, off: %lu, nsf: %lu\n",
			btx, mac->totaltime, jiffies, gts_offset, next_sf_time);
		dbg_print(mac, GTS, DBG_ERR,
			"btx+off: %lu, j: %lu\n",
			btx + gts_offset, jiffies);
		BUG();
	}
	return ret;
}

int ieee80215_gts_data_action_start(ieee80215_mac_t *mac)
{
	mac->plme_set_trx_state_confirm = ieee80215_gts_start_slice;
	ieee80215_net_cmd(mac->phy, IEEE80215_MSG_SET_STATE,
				mac->i.action, 0);	
	return 0;
}

int ieee80215_gts_send_frame(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	unsigned long tmp;

	dbg_print(mac, GTS, DBG_INFO, "msg len = %d\n", skb->len);

	tmp = usecs_to_jiffies(skb->len * mac->symbol_duration);
	if (tmp > ieee80215_gts_time_available(mac)) {
		dbg_print(mac, GTS, DBG_INFO,
			"data len does not fit into remaining gts, defer\n");
	} else {
		skb_to_mpdu(skb)->on_confirm = ieee80215_gts_data_confirm;
		mac->phy->pd_data_request(mac->phy, skb);
	}
	return 0;
}

int ieee80215_gts_process_tx(ieee80215_mac_t *mac)
{
	struct sk_buff *msg;

	dbg_print(mac, GTS, DBG_INFO, "GTS txq len: %d\n",
		  skb_queue_len(mac->curr_gts->gts_q));

	msg = skb_peek(mac->curr_gts->gts_q);
	if (msg) {
		ieee80215_gts_send_frame(mac, msg);
	} else {
		dbg_print(mac, GTS, DBG_INFO,
			  "Transmit gts, but no data to transfer\n");
	}
	return 0;
}

void ieee80215_gts_end_slice(struct work_struct *work)
{
	ieee80215_gts_info_t *gts = container_of(work, ieee80215_gts_info_t,
			gts_work.work);
	ieee80215_mac_t *mac = gts->mac;

	dbg_print(mac, GTS, DBG_INFO, "GTS slice end, rescheduling\n");
	/* Recalc next gts slice time */
	cancel_delayed_work(&mac->gts_data_ack);

	ieee80215_schedule_gts_slice(mac, gts);
	mac->curr_gts = NULL;
}

int ieee80215_gts_data_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;
	u32 time_avail;

	if (code == IEEE80215_PHY_SUCCESS) {
		code = IEEE80215_SUCCESS;
	}
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mcps_data_confirm(_nhle(mac), skb, code);
#endif

	time_avail = ieee80215_gts_time_available(mac);
	if (time_avail &&
		time_avail > usecs_to_jiffies(IEEE80215_TURNAROUND_TIME*mac->symbol_duration)) {
		ieee80215_gts_process_tx(mac);
	}
	return 0;
}

int ieee80215_gts_start_slice(ieee80215_mac_t *mac, int code)
{
	ieee80215_gts_info_t *gts = mac->curr_gts;
	int ret = 0;
	if (!gts)
		BUG();

	dbg_print(mac, GTS, DBG_INFO, "GTS slice processing, len: %d, sym/slot: %d\n",
		  gts->c.len, mac->i.symbols_per_slot);

	if (code == mac->i.action || code == IEEE80215_PHY_SUCCESS) {
		long unsigned int gts_len;
		PREPARE_DELAYED_WORK(&gts->gts_work, ieee80215_gts_end_slice);
		gts_len = usecs_to_jiffies((gts->c.len*mac->i.symbols_per_slot)*
				mac->symbol_duration);

		dbg_print(mac, GTS, DBG_INFO, "GTS duration: %lu, %lu*10^-3 sec\n",
			  gts_len, (gts_len*1000)/HZ);

		schedule_delayed_work(&gts->gts_work, gts_len);
		gts->start = jiffies;

		if (mac->i.action == IEEE80215_TX_ON) {
			ieee80215_gts_process_tx(mac);
		}
	} else {
		dbg_print(mac, GTS, DBG_ERR, "Unable to switch to action: %d, %d\n",
			 mac->i.action, code);
		ret = 0;
	}
	return ret;
}

void ieee80215_gts_process_slice(struct work_struct *work)
{
	ieee80215_gts_info_t *gts = container_of(work, ieee80215_gts_info_t,
					    gts_work.work);
	ieee80215_mac_t *mac = gts->mac;

	int action;
	/* if gts char's dir == 1, the gts is about to be receive-only GTS.
	if gts char's dir == 0, the gts is about to be transmit-only GTS.
	If we are a Pan coordinator, we enable transmitter and send any
	data availbe if dir == 1, enable receiver otherwise.
	If we are device, we enable receiver, if dir == 1, and transmitter
	otherwise */
	if (gts->c.dir) {
		if (mac->i.i_pan_coord)
			action = IEEE80215_TX_ON;
		else
			action = IEEE80215_RX_ON;
	} else {
		if (mac->i.i_pan_coord)
			action = IEEE80215_RX_ON;
		else
			action = IEEE80215_TX_ON;
	}

	mac->i.action = action;
	mac->curr_gts = gts;
	ieee80215_gts_data_action_start(mac);
}

ieee80215_gts_info_t *
ieee80215_find_gts(ieee80215_mac_t *mac, u16 _16bit, ieee80215_gts_char_t *gc)
{
	struct list_head *it;
	ieee80215_gts_info_t *g = NULL;

	spin_lock(&mac->gts.lock);
	if (!mac->gts.id)
		goto exit_find;
	list_for_each(it, &mac->gts.db.list) {
		g = container_of(it, ieee80215_gts_info_t, list);
		if (_16bit == g->addr._16bit) {
			if (g->c.dir == gc->dir) {
				break;
			}
		}
	}
exit_find:
	spin_unlock(&mac->gts.lock);
	return g;
}

void ieee80215_defragment_gts(ieee80215_mac_t *mac, ieee80215_gts_info_t *gts)
{

	struct list_head *it;
	ieee80215_gts_info_t *g;

	for (it = gts->list.next; prefetch(it->prev), it != &mac->gts.db.list;
		    it = it->next) {
			    g = container_of(it, ieee80215_gts_info_t, list);
			    if (g->starting_slot) {
				    g->starting_slot += gts->c.len;
				    g->id--;
			    }
		    }
}

void ieee80215_pupulate_gts_db(ieee80215_mac_t *mac)
{
	struct list_head *it;
	ieee80215_gts_info_t *g;
	u8 sec_mode = 0x8;

	spin_lock(&mac->gts.lock);
	dbg_print(mac, GTS, DBG_ALL, "GTS active count: %d\n", mac->gts.active_count);
	if (!mac->gts.active_count)
		goto exit_ptr;

	list_for_each(it, &mac->gts.db.list) {
		g = container_of(it, ieee80215_gts_info_t, list);
		dbg_print(mac, GTS, DBG_ALL,
			  "GTS id: %d, ac: %d, exp: %lu, pers: %lu, j: %lu\n",
			 g->id, g->active, g->expires, g->pers_time, jiffies);
		dbg_print(mac, GTS, DBG_ALL,
			  "GTS ss: %d, len: %d\n", g->starting_slot, g->c.len);
		if (!g->active)
			continue;
		if (g->expires < jiffies) {
			dbg_print(mac, CMD, DBG_INFO,
				  "Removing GTS for %d, len: %d\n",
				  g->addr._16bit, g->c.len);
			if (mac->i.i_pan_coord && g->starting_slot) {
				dbg_print(mac, GTS, DBG_INFO,
					  "Schedule 0 ss gts, %d addr for removal\n",
					 g->addr._16bit);
				cancel_delayed_work(&g->gts_work);
				g->id = 0;
				g->starting_slot = 0;
				g->c.type = 0;
				g->expires = ieee80215_wind_gts_watch(mac);
				g->pers_time = g->expires;
				if (g->secure) {
					if (!g->acl)
						sec_mode = 0x8;
					else
						sec_mode = g->acl->sec_suite;
				}
#warning FIXME indication/confurm
#if 0
				_nhle(mac)->mlme_gts_indication(_nhle(mac),
					&g->addr, &g->c, g->acl?true:false, sec_mode);
#endif
				mac->gts.id--;
				mac->i.final_cap_slot += g->c.len;
				ieee80215_defragment_gts(mac, g);
			} else {
				/* just delete */
				dbg_print(mac, GTS, DBG_INFO,
					  "Remove gts from db\n");
				goto del_gts;
			}
		}
		if (mac->i.i_pan_coord &&
				  (g->pers_time < jiffies)) {
			dbg_print(mac, CMD, DBG_INFO, "GTS %d expires, removing\n",
				  g->addr._16bit);
			cancel_delayed_work(&g->gts_work);
			/* just delete */
			mac->gts.id--;
			mac->i.final_cap_slot += g->c.len;
			g->starting_slot = 0;
			ieee80215_defragment_gts(mac, g);
			goto del_gts;
		}
	}
exit_ptr:
	spin_unlock(&mac->gts.lock);
	dbg_print(mac, GTS, DBG_ALL, "GTS DB populated\n");
	return;
del_gts:
	skb_queue_purge(g->gts_q);
	g->c.len = 0;
	g->active = false;
	mac->gts.active_count--;
	goto exit_ptr;
}

ieee80215_gts_info_t *
ieee80215_get_free_gts(ieee80215_mac_t *mac)
{
	struct list_head *it;
	ieee80215_gts_info_t *g;

	list_for_each(it, &mac->gts.db.list) {
		g = container_of(it, ieee80215_gts_info_t, list);
		if (!g->active)
			return g;
	}
	return NULL;
}

void ieee80215_set_gts_timeout(ieee80215_mac_t *mac, ieee80215_gts_info_t *g)
{
	/* Remove gts request if it expire aGTSDescPresenseTime
	times of superframe duration */
	g->expires = ieee80215_gts_expire_time(mac);
	g->pers_time = ieee80215_wind_gts_watch(mac);
}

ieee80215_gts_info_t
*ieee80215_add_gts(ieee80215_mac_t *mac, u16 _16bit, ieee80215_gts_char_t *c,
		   u8 starting_slot, bool sec, ieee80215_acl_pib_t *acl_entry)
{
	ieee80215_gts_info_t *g;
	g = ieee80215_get_free_gts(mac);
	if(!g) {
		dbg_print(mac, CMD, DBG_ERR_CRIT, "GTS DB at capacity\n");
		return NULL;
	}

	g->active = true;
	g->use_count = 0;
	g->c.dir = c->dir;
	g->c.len = c->len;
	g->c.type = 1;
	g->starting_slot = starting_slot;
	g->addr._16bit = _16bit;
	g->id = ++mac->gts.id;
	if (sec) {
		g->secure = true;
		g->acl = acl_entry;
	} else {
		g->secure = false;
		g->acl = NULL;
	}
	return g;
}

void ieee80215_schedule_gts_slice(ieee80215_mac_t *mac, ieee80215_gts_info_t *gi)
{
	long unsigned int start_gts_time;
	if (!gi->active) {
		dbg_print(mac, GTS, DBG_INFO, "GTS slice is not mark as active\n");
		return;
	}
	start_gts_time = ieee80215_calc_next_gts_time(mac, gi);

	dbg_print(mac, GTS, DBG_INFO, "start_gts_time: %lu\n", start_gts_time);

	PREPARE_DELAYED_WORK(&gi->gts_work, ieee80215_gts_process_slice);
	schedule_delayed_work(&gi->gts_work, start_gts_time);
}

ieee80215_gts_info_t*
ieee80215_allocate_gts(ieee80215_mac_t *mac, struct sk_buff *skb, bool zero)
{
	ieee80215_gts_info_t *g = NULL;
	ieee80215_acl_pib_t *acl_entry;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	if (mpdu->mhr->fc.security) {
		acl_entry = ieee80215_find_acl(mac, mpdu->sa);
	} else {
		acl_entry = NULL;
	}

	g = ieee80215_add_gts(mac, mpdu->sa->_16bit, &mpdu->p.gts->c,
			      mac->gts.s_ss, mpdu->mhr->fc.security, acl_entry);
	if (!g) {
		goto err_exit_gts;
	}

	ieee80215_set_gts_timeout(mac, g);

	if (zero) {
		dbg_print(mac, CMD, DBG_INFO, "Allocating zero size gts descriptor");
		g->c.len = mac->gts.max_gts;
		g->id = 0;
		g->starting_slot = 0;
	}
err_exit_gts:
	return g;
}

/**
 * @brief Handle received GTS confirm
 *
 * Called from beacon parser, when gts information found in beacon.
 * Relevant only for gts_request callers.
 */
int ieee80215_gts_receive(ieee80215_mac_t *mac, ieee80215_gts_list_t *g,
			  ieee80215_gts_char_t *gc)
{
	bool should_confirm = false;
	ieee80215_gts_info_t *gi;

	gi = ieee80215_find_gts(mac, mac->pib.dev_addr._16bit, gc);

	if (!gi) {
		dbg_print(mac, GTS, DBG_INFO,
			  "Found GTS in beacon, but no req were sended, ignoring\n");
		return 0;
	}

	if (g->starting_slot == 0) {
		dbg_print(mac, GTS, DBG_INFO, "GTS with 0 starting slot received\n");
		if ((!gi->c.type && gi->starting_slot) ||
				    (gi->c.type && gi->starting_slot)) {

			if (!gi->c.type && gi->starting_slot)
				dbg_print(mac, GTS, DBG_INFO,
					  "Receive GTS deallocation confirm\n");
			if (gi->c.type && gi->starting_slot)
				dbg_print(mac, GTS, DBG_INFO,
					  "Receive GTS deallocation notification\n");

			mac->gts.active_count--;
			should_confirm = true;
			mac->i.startA = IEEE80215_SUCCESS;
			gi->starting_slot = 0;
			gi->id = 0;
			gi->active = false;
			gi->acl = NULL;
			gi->secure = false;
			gi->addr._16bit = 0xfffe;
			skb_queue_purge(gi->gts_q);
			cancel_delayed_work(&gi->gts_work);
			mac->i.startA = IEEE80215_SUCCESS;
		} else if (!gi->starting_slot) {
			dbg_print(mac, GTS, DBG_INFO,
				  "Dealloc confirm on already deallocated slice\n");
		} else {
			dbg_print(mac, BEACON, DBG_INFO, "GTS alloc denied\n");
			mac->i.startA = IEEE80215_DENINED;
			should_confirm = true;
		}
		gc->type = 0;
	} else {
		gc->type = 1;	/* allocate gts */
		gc->rsv = 0;

		dbg_print(mac, GTS, DBG_INFO,
			  "Found GTS info: len: %d, dir: %d, s_slot: %d\n",
					gc->len, gc->dir, g->starting_slot);
		mac->i.startA = IEEE80215_SUCCESS;
		if (gi->starting_slot != g->starting_slot ||
		   gi->c.len != g->len) {
			dbg_print(mac, GTS, DBG_INFO, "Adjusting GTS info\n");
			if (!gi->active)
				mac->gts.active_count++;
			should_confirm = true;
			gi->starting_slot = g->starting_slot;
			gi->pers_time = ieee80215_wind_gts_watch(mac);
			gi->expires = ieee80215_gts_expire_time(mac);
			gi->active = true;
			ieee80215_schedule_gts_slice(mac, gi);
		}
	}
	if (should_confirm) {
		cancel_delayed_work(&mac->gts_request);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_gts_confirm(_nhle(mac), gc, mac->i.startA);
#endif
	}

	return 0;
}

void ieee80215_gts_wait_confirm(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of(work, ieee80215_mac_t,
					    gts_request.work);
	ieee80215_gts_info_t *gts;
	u16 _16bit;

	dbg_print(mac, GTS, DBG_INFO, "No gts confirm received\n");
	ieee80215_get_pib(mac, IEEE80215_SHORT_ADDRESS, (u8*)&_16bit);

	gts = ieee80215_find_gts(mac, mac->pib.dev_addr._16bit, &mac->gts.rc);
	if (!gts) {
		dbg_print(mac, GTS, DBG_INFO, "No GTS for deallocate found\n");
		BUG();
	}

#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_gts_confirm(_nhle(mac), &mac->gts.rc, IEEE80215_NO_DATA);
#endif

	gts->active = false;
	gts->starting_slot = 0;
	memset(&gts->c, 0, sizeof(gts->c));
	gts->acl = NULL;
	skb_queue_purge(gts->gts_q);
	gts->addr._16bit = 0xfffe;
	memset(&mac->gts.rc, 0, sizeof(mac->gts.rc));
}

int ieee80215_gts_req_confirm(void *obj, struct sk_buff *skb, int code)
{
	struct ieee80215_mac *mac = obj;
	ieee80215_gts_info_t *gts;
	ieee80215_acl_pib_t *acl_entry;
	u16 _16bit;
	u8 so;
	ieee80215_mpdu_t *msg = skb_to_mpdu(skb);

	if (code != IEEE80215_PHY_SUCCESS) {
		dbg_print(mac, GTS, DBG_INFO, "code = 0x%x\n", code);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_gts_confirm(_nhle(mac), &mac->gts.rc, code);
#endif
		return 0;
	}

	dbg_print(mac, GTS, DBG_INFO, "Ack received, waiting confirm\n");

	if (msg->mhr->fc.security) {
		acl_entry = ieee80215_find_acl(mac, msg->sa);
	} else {
		acl_entry = NULL;
	}

	ieee80215_get_pib(mac, IEEE80215_SHORT_ADDRESS, (u8*)&_16bit);
	ieee80215_get_pib(mac, IEEE80215_SUPERFRAME_ORDER, &so);

	PREPARE_DELAYED_WORK(&mac->gts_request, ieee80215_gts_wait_confirm);

	if (mac->gts.rc.type) {
		unsigned long tmp;

		gts = ieee80215_add_gts(mac, _16bit, &mac->gts.rc, 0, acl_entry?true:false, acl_entry);
		if (gts) {
			dbg_print(mac, GTS, DBG_INFO,
				  "Save GTS req params, wait for beacon/timeout\n");
			gts->active = false;
		} else {
			dbg_print(mac, GTS, DBG_INFO, "Unable to store gts\n");
		}

		ieee80215_set_gts_timeout(mac, gts);
		tmp = IEEE80215_GTS_DESC_PERS_TIME * IEEE80215_BASE_SFD * (1<<so) * mac->symbol_duration;
		schedule_delayed_work(&mac->gts_request, usecs_to_jiffies(tmp));
	} else {
		gts = ieee80215_find_gts(mac, mac->pib.dev_addr._16bit, &mac->gts.rc);
		if (!gts) {
			dbg_print(mac, GTS, DBG_INFO,
				  "No GTS for deallocate found\n");
			BUG();
		}
		dbg_print(mac, GTS, DBG_INFO, "Deallocating GTS\n");
		cancel_delayed_work(&gts->gts_work);
		gts->active = false;
		gts->starting_slot = 0;
		memset(&gts->c, 0, sizeof(gts->c));
		skb_queue_purge(gts->gts_q);
		gts->acl = NULL;
		gts->addr._16bit = 0xfffe;
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_gts_confirm(_nhle(mac), &mac->gts.rc, IEEE80215_SUCCESS);
#endif
	}

	return 0;
}

int ieee80215_mlme_gts_req(ieee80215_mac_t *mac, ieee80215_gts_char_t *c,
			   bool sec_enable)
{
	ieee80215_gts_info_t *gi;
	ieee80215_mpdu_t *msg;

	dbg_print(mac, GTS, DBG_ALL, "Request gts type: %d, len: %d slots, dir: %d\n",
		 c->type, c->len, c->dir);

	if (mac->gts.max_gts == mac->gts.id && c->type) {
		dbg_print(mac, GTS, DBG_ALL,
			  "GTS alloc requested, while DB at capacity, max: %d, curr: %d\n",
			  mac->gts.max_gts, mac->gts.id);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_gts_confirm(_nhle(mac), c, IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	gi = ieee80215_find_gts(mac, mac->pib.dev_addr._16bit, c);
	if (gi && c->type) {
		dbg_print(mac, GTS, DBG_ERR,
			  "Such GTS is already allocated: %s\n", gi->active?"active":"not active");
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_gts_confirm(_nhle(mac), c, IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}

	msg = ieee80215_create_gts_request_cmd(mac, 0, c->len, c->dir, c->type, sec_enable);
	if (!msg) {
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_gts_confirm(_nhle(mac), c, IEEE80215_INVALID_PARAM);
#endif
		return 0;
	}
	msg->on_confirm = ieee80215_gts_req_confirm;
	skb_queue_head(&mac->to_network, mpdu_to_skb(msg));

	memcpy(&mac->gts.rc, c, sizeof(*c));
	ieee80215_csma_ca_start(mac);
	return 0;
}


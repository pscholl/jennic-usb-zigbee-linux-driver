/*
 * ieee80215_mac_cmd.c
 *
 * Description: MAC CMD helper functions.
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
#include <net/ieee80215/const.h>
#include <net/ieee80215/beacon.h>

extern int ieee80215_assoc_perm_cmd(ieee80215_mac_t *mac, struct sk_buff *skb);

/**
 * @brief Parse a MAC cmd frame
 *
 * @param mac pointer to current mac
 * @param mpdu pointer to received mpdu
 * @param len len in bytes of received mpdu
 * @param ppduLQ value of link quality while receiving the frame.
 * @return ieee80215_pan_desc_t pointer to a new descriptor if Ok, NULL if fail.
 */
int ieee80215_assoc_req_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_acl_pib_t *acl_entry = NULL;
	u8 sec_mode = 0x8;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	if (mac->pib.association_permit) {
		if (mpdu->mhr->fc.security) {
			acl_entry = ieee80215_find_acl(mac, mpdu->sa);
			if (acl_entry)
				sec_mode = acl_entry->sec_suite;
			else
				sec_mode = 0x8;
		}
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_associate_indication(_nhle(mac), mpdu->sa,
			&mpdu->p.areq->cap, mpdu->mhr->fc.security, sec_mode);
#endif
	} else {
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
		dbg_print(mac, CMD, DBG_INFO, "association is not permitted, ignore\n");
	}
	return 0;
}

int ieee80215_disassoc_notify_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_acl_pib_t *acl_entry = NULL;
	u8 sec_mode = 0x8;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	if (mpdu->mhr->fc.security) {
		acl_entry = ieee80215_find_acl(mac, mpdu->sa);
		if (acl_entry)
			sec_mode = acl_entry->sec_suite;
		else
			sec_mode = 0x8;
	}

	dbg_print(mac, CMD, DBG_INFO,
		"Disassociation notification received from %llu, panid: %d, reason: %d\n",
		mpdu->sa->_64bit, *mpdu->s_panid, mpdu->p.dn->reason);

#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_disassoc_indication(_nhle(mac), mpdu->sa,
		mpdu->p.dn->reason, mpdu->mhr->fc.security, sec_mode);
#endif
	return 0;
}

/* addr is little-endian, since we compare it with frames ready for the network */
u16 ieee80215_pending16_count(ieee80215_mac_t *mac, u16 addr)
{
	u16 count;
	u32 queue_len, idx;
	ieee80215_mpdu_t *mpdu;
	struct sk_buff *it;

	spin_lock(&mac->tr16.lock);
	queue_len = skb_queue_len(&mac->tr16);
	dbg_print(mac, DATA, DBG_INFO, "tr16 queue len = %u\n", queue_len);

	if (0 == queue_len) {
		spin_unlock(&mac->tr16.lock);
		return 0;
	}

	dbg_print(mac, DATA, DBG_INFO, "addr = 0x%x\n", addr);

	idx = 0;
	count = 0;
	for (it = mac->tr16.next; it != (struct sk_buff *)&mac->tr16; it = it->next) {
		mpdu = skb_to_mpdu(it);
		if (mpdu->da) {
			dbg_print(mac, DATA, DBG_INFO, "da->_16bit = 0x%x\n", mpdu->da->_16bit);
			if (mpdu->da->_16bit == addr) {
				++count;
			}
		} else if (mpdu->sa) {
			dbg_print(mac, DATA, DBG_INFO, "sa->_16bit = 0x%x\n", mpdu->sa->_16bit);
			if (mpdu->sa->_16bit == addr) {
				++count;
			}
		}
		++idx;
	}
	spin_unlock(&mac->tr16.lock);
	BUG_ON(idx != queue_len);
	dbg_print(mac, DATA, DBG_INFO, "count = %u\n", count);
	return count;
}

/* addr is little-endian, since we compare it with frames ready for the network */
u16 ieee80215_pending64_count(ieee80215_mac_t *mac, u64 addr)
{
	u16 count;
	u32 queue_len, idx;
	ieee80215_mpdu_t *mpdu;
	struct sk_buff *it;

	spin_lock(&mac->tr64.lock);
	queue_len = skb_queue_len(&mac->tr64);
	dbg_print(mac, DATA, DBG_INFO, "tr64 queue len = %u\n", queue_len);

	if (0 == queue_len) {
		spin_unlock(&mac->tr64.lock);
		return 0;
	}

	dbg_print(mac, DATA, DBG_INFO, "addr = 0x%llx\n", addr);

	idx = 0;
	count = 0;
	for (it = mac->tr64.next; it != (struct sk_buff *)&mac->tr64; it = it->next) {
		mpdu = skb_to_mpdu(it);
		if (mpdu->da) {
			dbg_print(mac, DATA, DBG_INFO, "da->_64bit = 0x%llx\n", mpdu->da->_64bit);
			if (mpdu->da->_64bit == addr) {
				++count;
			}
		} else if (mpdu->sa) {
			dbg_print(mac, DATA, DBG_INFO, "sa->_64bit = 0x%llx\n", mpdu->sa->_64bit);
			if (mpdu->sa->_64bit == addr) {
				++count;
			}
		}
		++idx;
	}
	spin_unlock(&mac->tr64.lock);
	BUG_ON(idx != queue_len);
	dbg_print(mac, DATA, DBG_INFO, "count = %u\n", count);
	return count;
}

/* addr is little-endian, since we compare it with frames ready for the network */
static ieee80215_mpdu_t* _dequeue_pending16(ieee80215_mac_t *mac, u16 addr)
{
	u32 queue_len;
	ieee80215_mpdu_t *ret;
	struct sk_buff *it;

	spin_lock(&mac->tr16.lock);
	queue_len = skb_queue_len(&mac->tr16);
	dbg_print(mac, DATA, DBG_INFO, "tr16 queue len = %u\n", queue_len);

	if (0 == queue_len) {
		spin_unlock(&mac->tr16.lock);
		return NULL;
	}

	dbg_print(mac, DATA, DBG_ALL, "addr = 0x%x\n", addr);
	ret = NULL;
	for (it = mac->tr16.next; it != (struct sk_buff *)&mac->tr16; it = it->next) {
		ret = skb_to_mpdu(it);
		if (ret->da) {
			dbg_print(mac, DATA, DBG_INFO, "da->_16bit = 0x%x\n", ret->da->_16bit);
			if (ret->da->_16bit == addr) {
				break;
			}
		} else if (ret->sa) {
			dbg_print(mac, DATA, DBG_INFO, "it->sa->_16bit = 0x%x\n", ret->sa->_16bit);
			if (ret->sa->_16bit == addr) {
				break;
			}
		}
		ret = NULL;
	}
	spin_unlock(&mac->tr16.lock);
	if (ret) {
		dbg_print(mac, DATA, DBG_INFO, "found 0x%p\n", ret);
		skb_unlink(it, &mac->tr16);
	} else {
		dbg_print(mac, DATA, DBG_INFO, "not found\n");
	}
	return ret;
}

/* addr is little-endian, since we compare it with frames ready for the network */
static ieee80215_mpdu_t* _dequeue_pending64(ieee80215_mac_t *mac, u64 addr)
{
	u32 queue_len;
	ieee80215_mpdu_t *ret;
	struct sk_buff *it;

	spin_lock(&mac->tr64.lock);
	queue_len = skb_queue_len(&mac->tr64);
	dbg_print(mac, DATA, DBG_INFO, "tr64 queue len = %u\n", queue_len);

	if (0 == queue_len) {
		spin_unlock(&mac->tr64.lock);
		return NULL;
	}

	dbg_print(mac, DATA, DBG_ALL, "addr = 0x%llx\n", addr);
	ret = NULL;
	for (it = mac->tr64.next; it != (struct sk_buff*)&mac->tr64;  it = it->next) {
		ret = skb_to_mpdu(it);
		if (ret->da) {
			dbg_print(mac, DATA, DBG_INFO, "da->_64bit = 0x%llx\n", ret->da->_64bit);
			if (ret->da->_64bit == addr) {
				break;
			}
		} else if (ret->sa) {
			dbg_print(mac, DATA, DBG_INFO, "it->sa->_64bit = 0x%llx\n", ret->sa->_64bit);
			if (ret->sa->_64bit == addr) {
				break;
			}
		}
		ret = NULL;
	}
	spin_unlock(&mac->tr64.lock);
	if (ret) {
		dbg_print(mac, DATA, DBG_INFO, "found 0x%p\n", ret);
		skb_unlink(it, &mac->tr64);
	} else {
		dbg_print(mac, DATA, DBG_INFO, "not found\n");
	}
	return ret;
}

int ieee80215_data_req_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_acl_pib_t *acl_entry = NULL;
	ieee80215_mpdu_t *pdata, *mpdu = skb_to_mpdu(skb);
	u8 sec_mode, amode;
	u16 count;

	dbg_print(mac, CMD, DBG_INFO, "data request received\n");

	if (!mac->i.i_pan_coord) {
		dbg_print(mac, CMD, DBG_INFO, "I'm not a coordinator, discard request\n");
		return 0;
	}
	if (mpdu->mhr->fc.security) {
		dbg_print(mac, CMD, DBG_INFO, "security processing\n");
		acl_entry = ieee80215_find_acl(mac, mpdu->sa);
		if (acl_entry)
			sec_mode = acl_entry->sec_suite;
		else
			sec_mode = 0x8;
	}

	amode = mpdu->mhr->fc.src_amode;
	if (IEEE80215_AMODE_16BIT == amode) {
		dbg_print(mac, CMD, DBG_INFO, "address mode 16bit\n");
		pdata = _dequeue_pending16(mac, mpdu->sa->_16bit);
		count = ieee80215_pending16_count(mac, mpdu->sa->_16bit);
	} else if (IEEE80215_AMODE_64BIT == amode) {
		dbg_print(mac, CMD, DBG_INFO, "address mode 64bit\n");
		pdata = _dequeue_pending64(mac, mpdu->sa->_64bit);
		count = ieee80215_pending64_count(mac, mpdu->sa->_64bit);
	} else {
		dbg_print(mac, CMD, DBG_ERR, "unexpected amode = %u\n", amode);
		BUG();
	}

	if (!pdata) {
		ieee80215_dev_addr_t src, dst;

		switch (amode) {
			case IEEE80215_AMODE_16BIT:
				src._16bit = le16_to_cpu(mpdu->sa->_16bit);
				break;
			case IEEE80215_AMODE_64BIT:
				src._64bit = le64_to_cpu(mpdu->sa->_64bit);
				break;
			default:
				break;
		}
		if (IEEE80215_AMODE_NOPAN != amode)
			src.panid = le16_to_cpu(*mpdu->s_panid);

		switch (mpdu->mhr->fc.dst_amode) {
			case IEEE80215_AMODE_16BIT:
				dst._16bit = le16_to_cpu(mpdu->da->_16bit);
				break;
			case IEEE80215_AMODE_64BIT:
				dst._64bit = le64_to_cpu(mpdu->da->_64bit);
				break;
			default:
				break;
		}
		if (IEEE80215_AMODE_NOPAN != mpdu->mhr->fc.dst_amode)
			dst.panid = le16_to_cpu(*mpdu->d_panid);

		dbg_print(mac, CMD, DBG_INFO, "No data pending, sending zero len payload\n");
		pdata = mac_alloc_mpdu(0);
		ieee80215_create_mcps_data_req(mac, &src, &dst, mpdu_to_skb(pdata), 0, mpdu->mhr->fc.security);
	}

	pdata->use_csma_ca = 0; /* do not wait backoffs before transmitting */

	if (count) {
		pdata->mhr->fc.pend = 1;
	}

	if (!pdata->on_confirm) {
		pdata->on_confirm = ieee80215_data_confirm;
	}

	skb_queue_head(&mac->to_network, mpdu_to_skb(pdata));
	return 0;
}

int ieee80215_pid_con_notify_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	dbg_print(mac, CMD, DBG_INFO, "PAN id conflict notification\n");
	if (mac->i.i_pan_coord) {
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_sync_loss_indication(_nhle(mac), IEEE80215_PANID_CONFLICT);
#endif
	} else {
		dbg_print(mac, CMD, DBG_INFO, "I'm not a coordinator, ignore\n");
	}
	return 0;
}

int ieee80215_orphan_notify_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_acl_pib_t *acl_entry = NULL;
	u8 sec_mode = 0x8;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	dbg_print(mac, CMD, DBG_INFO, "Orphan notification\n");
	if (mac->i.i_pan_coord) {
		if (mpdu->mhr->fc.security) {
			acl_entry = ieee80215_find_acl(mac, mpdu->sa);
			if (acl_entry)
				sec_mode = acl_entry->sec_suite;
			else
				sec_mode = 0x8;
		}
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_orphan_indication(_nhle(mac), mpdu->sa, mpdu->mhr->fc.security, sec_mode);
#endif
	} else {
		dbg_print(mac, CMD, DBG_INFO, "I'm not a pan coordinator, ignore\n");
	}
	return 0;
}

int ieee80215_beacon_req_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_mpdu_t *beacon;

	dbg_print(mac, CMD, DBG_INFO, "beacon requested\n");
	mac->f.beacon_req = true;

	beacon = ieee80215_create_beacon(mac);
	if (beacon) {
		beacon->on_confirm = ieee80215_data_confirm;
		skb_queue_head(&mac->to_network, mpdu_to_skb(beacon));
	} else {
		dbg_print(mac, CMD, DBG_ERR, "unable to create beacon\n");
	}
	return 0;
}

int ieee80215_realign_req_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	dbg_print(mac, CMD, DBG_INFO, "Coordinator realignment\n");
	ieee80215_parse_coordinator_realignment(mac, skb);

	mac->f.find_a_coord_realign = true;
#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mlme_sync_loss_indication(_nhle(mac), IEEE80215_REALIGMENT);
#endif
	return 0;
}

int ieee80215_gts_req_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_gts_info_t *g = NULL;
	u8 sec_mode = 0x8;
	bool gts_permit;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	ieee80215_get_pib(mac, IEEE80215_GTS_PERMIT, &gts_permit);

	dbg_print(mac, CMD, DBG_INFO, "GTS request: %s\n", gts_permit?"allowed":"denied");

	if (!gts_permit) {
		return 0;
	}

	g = ieee80215_find_gts(mac, mpdu->sa->_16bit, &mpdu->p.gts->c);
	if (mpdu->p.gts->c.type) {
		dbg_print(mac, CMD, DBG_INFO, "GTS allocation request, 0x%p\n", g);
		if (!g) {
			dbg_print(mac, GTS, DBG_ALL,
				  "No gts entry found, need to allocate new one\n");
			dbg_print(mac, GTS, DBG_ALL, "fcs: %d, len: %d, s_ss: %d\n",
				  mac->i.final_cap_slot, mpdu->p.gts->c.len, mac->gts.s_ss);
			mac->gts.s_ss = mac->i.final_cap_slot -	mpdu->p.gts->c.len;

			ieee80215_pupulate_gts_db(mac);
			if (mac->gts.id >= mac->gts.max_gts) {
				dbg_print(mac, CMD, DBG_INFO, "GTS DB at capacity\n");
				return 0;
			}
			if (mac->gts.s_ss < mac->i.num_cap_slots) {
				dbg_print(mac, CMD, DBG_INFO, "Req gts is out of CFP\n");
				/* Adding new descriptor with starting_slot 0 */
				g = ieee80215_allocate_gts(mac, skb, true);
			} else {
				g = ieee80215_allocate_gts(mac, skb, false);
				mac->i.final_cap_slot -= mpdu->p.gts->c.len;
				mac->gts.active_count++;
			}

			if (!g) {
				dbg_print(mac, GTS, DBG_ERR, "No gts entry added\n");
				return 0;
			}

			if (g->secure) {
				if (!g->acl)
					sec_mode = 0x8;
				else
					sec_mode = g->acl->sec_suite;
			}
			ieee80215_schedule_gts_slice(mac, g);
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mlme_gts_indication(_nhle(mac),
				&g->addr, &g->c, g->acl?true:false, sec_mode);
#endif
		}
	} else {
		dbg_print(mac, CMD, DBG_INFO, "GTS deallocation request\n");
		if (!g) {
			dbg_print(mac, CMD, DBG_INFO,
				  "Deallocation request on non-existing GTS\n");
			return 0;
		}
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
		skb_queue_purge(g->gts_q);
		g->c.len = 0;
		g->active = false;
		mac->gts.active_count--;
		cancel_delayed_work(&g->gts_work);
	}
	return 0;
}

int ieee80215_gts_alloc_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	dbg_print(mac, CMD, DBG_INFO, "not implemented\n");
	return 0;
}

int ieee80215_parse_cmd(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	dbg_print(mac, CMD, DBG_INFO, "cmd_id = 0x%x\n", skb_to_mpdu(skb)->p.g->cmd_id);
	switch (skb_to_mpdu(skb)->p.g->cmd_id) {
	case IEEE80215_ASSOCIATION_REQ:
		ieee80215_assoc_req_cmd(mac, skb);
		break;
	case IEEE80215_ASSOCIATION_PERM:
		ieee80215_assoc_perm_cmd(mac, skb);
		break;
	case IEEE80215_DISASSOCIATION_NOTIFY:
		ieee80215_disassoc_notify_cmd(mac, skb);
		break;
	case IEEE80215_DATA_REQ:
		ieee80215_data_req_cmd(mac, skb);
		break;
	case IEEE80215_PANID_CONFLICT_NOTIFY:
		ieee80215_pid_con_notify_cmd(mac, skb);
		break;
	case IEEE80215_ORPHAN_NOTIFY:
		ieee80215_orphan_notify_cmd(mac, skb);
		break;
	case IEEE80215_BEACON_REQ:
		ieee80215_beacon_req_cmd(mac, skb);
		break;
	case IEEE80215_COORD_REALIGN_NOTIFY:
		ieee80215_realign_req_cmd(mac, skb);
		break;
	case IEEE80215_GTS_REQ:
		ieee80215_gts_req_cmd(mac, skb);
		break;
	case IEEE80215_GTS_ALLOC:
		ieee80215_gts_alloc_cmd(mac, skb);
		break;
	default:
		dbg_print(mac, 0, DBG_INFO, "unknown cmd_id\n");
		break;
	}
	return 0;
}


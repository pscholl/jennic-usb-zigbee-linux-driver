/*
 * ieee80215_beacon.c
 *
 * Description: MAC beacon helper functions.
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

/**
 * @brief Check Pending addresses in beacon header
 *
 * Check pending address list of the beacon, and if found our own, signal the
 * caller. Pending address structure contain a pending address specification
 * field, which is mandatory for the beacon, and a set of addresses, coming one
 * after other. 16bit addresses coming first, 64bit - last. Pend spec field
 * specify how many both of addr types are in beacon. For example
 *
 * |16bit|rsv1|64bit|rsv2|addrs_list|
 * |    2|xxxx|    1|xxxx|000200030010002000300040|
 * contain 2 16bit addresses of 0x0002 and 0x0003, and 1 64bit of
 * 0x0010002000300040
 *
 * @param mac pointer to current mac
 * @param p_alist pointer to pending address structure in beacon
 * @return 1 if match found, 0 otherwise
 */
static int ieee80215_check_pending(ieee80215_mac_t *mac, ieee80215_paddr_t *p_alist)
{
	u8	idx = 0;
	u8	*t_addr = NULL;
	u8	*addr_list;
	u16	_16bit;
	u64	_64bit;

	addr_list = (u8*)p_alist+sizeof(*p_alist);
	if (p_alist->addr_spec._16bit_pend) {
		t_addr = addr_list;
		for (idx = 0; idx < p_alist->addr_spec._16bit_pend; idx++) {
			_16bit = (u16)*t_addr;
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
			dbg_print(mac, BEACON, DBG_INFO,
				"16bit_pend: %d, our: %d\n",
				le16_to_cpu(_16bit), mac->pib.dev_addr._16bit);
			if (le16_to_cpu(_16bit) == mac->pib.dev_addr._16bit)
				return 1;
			t_addr += sizeof(_16bit);
		}
	}
	if (p_alist->addr_spec._64bit_pend) {
		if (!t_addr)
			t_addr = addr_list;
		for (idx = 0; idx < p_alist->addr_spec._64bit_pend; idx++) {
			_64bit = (u64)(*t_addr);
			dbg_print(mac, BEACON, DBG_INFO,
				"64bit_pend: %llu, our: %llu\n",
				le64_to_cpu(_64bit), mac->pib.dev_addr._64bit);
			if (le64_to_cpu(_64bit) == mac->pib.dev_addr._64bit)
				return 1;
			t_addr += sizeof(_64bit);
		}
	}
	return 0;
}

/**
 * @brief Parse a beacon frame, returning a PAN descriptor structure
 *
 * If beacon has a non-zero payload, issue MLME-BEACON-NOTIFY.indication
 * primitive.
 * @param mac pointer to current mac
 * @param mpdu pointer to received mpdu
 * @param len len in bytes of received mpdu
 * @param ppduLQ value of link quality while receiving the frame.
 * @return none.
 */
void ieee80215_parse_beacon(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	bool has_payload;
	u8 r_bsn, bp_len = 0, *bp_off = NULL, idx, sec_mode = 0x8, *addr_list = NULL;
	ieee80215_pan_desc_t *desc, *match = NULL;
	ieee80215_gts_frame_t *gts;
	ieee80215_gts_list_t *g;
	ieee80215_gts_char_t gc;
	ieee80215_paddr_t *r_alist;
	ieee80215_acl_pib_t *acl_entry;
	u16 beacon_panid;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	dbg_print(mac, BEACON, DBG_INFO, "timestamp = %lu\n", mpdu->timestamp);

	if (mpdu->mhr->fc.src_amode != IEEE80215_AMODE_16BIT && mpdu->mhr->fc.src_amode != IEEE80215_AMODE_64BIT) {
		dbg_print(mac, BEACON, DBG_ERR, "invalid src_amode: %u\n", mpdu->mhr->fc.src_amode);
		return;
	}

	beacon_panid = le16_to_cpu(*mpdu->s_panid);
	dbg_print(mac, BEACON, DBG_INFO, "beacon panid = 0x%x\n", beacon_panid);

	mac->pib.beacon_tx_time = mpdu->timestamp;
	if (mpdu->p.b->sff.pan_coord) {
		if (mac->i.i_pan_coord) {
			if (ieee80215_in_scanning(mac)) {
				dbg_print(mac, BEACON, DBG_INFO,
					"coordinator received beacon in scanning mode\n");
				BUG();
			} else {
				ieee80215_mpdu_t *realign_cmd;
				realign_cmd = ieee80215_create_realign_cmd(mac, mpdu->sa, mac->i.current_channel);
				if (!realign_cmd) {
					BUG();
				}
				skb_queue_head(&mac->to_network, mpdu_to_skb(realign_cmd));
				goto exit_kfree;
			}
		} else {
			u16 my_panid;
			/* check for PAN id conflict here.
			 * device must be associated through PAN coordinator to be able to detect PAN id conflict.
			 * TODO:
			 * check if I am associated and if parent is PAN coordinator
			 */
			if (ieee80215_in_scanning(mac))
				my_panid = mac->scan.tmp_panid;
			else
				my_panid = mac->pib.dev_addr.panid;

			dbg_print(mac, BEACON, DBG_INFO, "my_panid = 0x%x\n", my_panid);

			if (my_panid == beacon_panid) {
				u8 alien = 1;
				dbg_print(mac, BEACON, DBG_INFO,
					"mpdu->mhr->fc.src_amode = %u\n",
					mpdu->mhr->fc.src_amode);

				if (IEEE80215_AMODE_16BIT == mpdu->mhr->fc.src_amode) {
					u16 tmp;
					tmp = le16_to_cpu(mpdu->sa->_16bit);
					dbg_print(mac, BEACON, DBG_INFO,
						"src16 = 0x%x, coord16 = 0x%x\n",
						tmp, mac->pib.coord._16bit);
					if (tmp == mac->pib.coord._16bit)
						alien = 0;
				} else if (IEEE80215_AMODE_64BIT == mpdu->mhr->fc.src_amode) {
					u64 tmp;
					tmp = le64_to_cpu(mpdu->sa->_64bit);
					dbg_print(mac, BEACON, DBG_INFO,
						"src64 = 0x%llx, coord64 = 0x%llx\n",
						tmp, mac->pib.coord._64bit);
					if (tmp == mac->pib.coord._64bit)
						alien = 0;
				} else {
					dbg_print(mac, BEACON, DBG_ERR, "unexpected src addr mode\n");
					BUG();
				}

				if (alien) {
					ieee80215_mpdu_t *cmd;
					dbg_print(mac, BEACON, DBG_INFO, "PAN id conflict detected\n");
					cmd = ieee80215_create_pid_con_cmd(mac);
					if (!cmd) {
						BUG();
					}
					skb_queue_head(&mac->to_network, mpdu_to_skb(cmd));
					goto exit_kfree;
				}
			}
		}
	}

	desc = kzalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		dbg_print(mac, BEACON, DBG_ERR, "Unable to allocate memory\n");
		goto exit_kfree;
	}
	mac->i.final_cap_slot = mpdu->p.b->sff.fcap_slot;
	desc->coord_addr.panid = le16_to_cpu(*mpdu->s_panid);
	desc->coord_mode = mpdu->mhr->fc.src_amode;
	if (IEEE80215_AMODE_16BIT == mpdu->mhr->fc.src_amode) {
		desc->coord_addr._16bit = le16_to_cpu(mpdu->sa->_16bit);
		dbg_print(mac, BEACON, DBG_ALL, "coord_addr[16bit]: %d\n",
			  desc->coord_addr._16bit);
	} else if (IEEE80215_AMODE_64BIT == mpdu->mhr->fc.src_amode) {
		desc->coord_addr._64bit = le64_to_cpu(mpdu->sa->_64bit);
		desc->coord_addr._16bit = 0xfffe;
		dbg_print(mac, BEACON, DBG_ALL, "coord_addr[64bit]: %lu\n",
			  desc->coord_addr._64bit);
	} else {
		dbg_print(mac, BEACON, DBG_ERR, "unexpected address mode = %u\n",
			mpdu->mhr->fc.src_amode);
		BUG();
	}
	desc->ch = mac->i.current_channel;
	(*(u16*)&desc->sfs) = (*(u16*)&mpdu->p.b->sff);
	desc->lq = mpdu->lq;
	desc->timestamp = jiffies;

	acl_entry = ieee80215_find_acl(mac, mpdu->sa);
	if (acl_entry)
		sec_mode = acl_entry->sec_suite;
	else
		sec_mode = 0x8;

	if (mpdu->mhr->fc.security) {
		desc->security = true;
		if (acl_entry) {
			desc->acl_entry = true;
			if (1/*(ieee80215_decode_security(mac, add)*/) {
				desc->sec_failure = false;
			} else {
				desc->sec_failure = true;
			}
		} else {
			desc->acl_entry = false;
		}
	} else {
		desc->security = false;
		if (acl_entry) {
			desc->acl_entry = true;
		} else {
			desc->acl_entry = false;
		}
		desc->sec_failure = false;
	}

	gts = (ieee80215_gts_frame_t *)(((u8*)&mpdu->p.b->sff) + sizeof(mpdu->p.b->sff));
	desc->gts_permit = gts->spec.permit;
	/* Looking for gts, if requested */
	if (gts->spec.desc_count) {
		dbg_print(mac, BEACON, DBG_INFO, "gts count: %d\n", gts->spec.desc_count);
		g = (ieee80215_gts_list_t*)((u8*)gts + sizeof(gts->dir) +
				sizeof(gts->spec));
		for (idx = 0; idx < gts->spec.desc_count; idx ++) {
			dbg_print(mac, BEACON, DBG_INFO, "gts addr: %d\n",
				 cpu_to_le16(g->_16bit));
			if (le16_to_cpu(g->_16bit) == mac->pib.dev_addr._16bit) {
				gc.len = g->len;
				gc.dir = test_bit(idx, (unsigned long*)&gts->dir);
				ieee80215_gts_receive(mac, g, &gc);
				break;
			}
			g++;
		}
		/* check pending addresses */
		r_alist = (ieee80215_paddr_t*)((u8*)gts + (sizeof(gts->dir) +
				sizeof(gts->spec) +
				gts->spec.desc_count*sizeof(*g)));
	} else {
		/* check pending addresses */
		r_alist = (ieee80215_paddr_t*)((u8*)gts + sizeof(gts->spec));
	}

	if (r_alist->addr_spec._64bit_pend | r_alist->addr_spec._16bit_pend) {
		addr_list = (u8*)r_alist + sizeof(*r_alist);
	}

	bp_off = ((u8*)r_alist + r_alist->addr_spec._16bit_pend*sizeof(u16) +
		r_alist->addr_spec._64bit_pend*sizeof(u64) + sizeof(*r_alist));
	if (skb->data + skb->len - sizeof(mpdu->mfr->fcs) > bp_off) {
		u8 *tmp;
		has_payload = true;
		bp_len = (u8*)mpdu->mfr - bp_off;
		dbg_print(mac, BEACON, DBG_INFO, "beacon payload length = %u\n", bp_len);
		/* save to PIB */
		tmp = kmalloc(bp_len, GFP_KERNEL);
		if (tmp) {
			memcpy(tmp, bp_off, bp_len);
			write_lock(&mac->pib.lock);
			if(mac->pib.beacon_payload && mac->pib.beacon_payload_len)
				kfree(mac->pib.beacon_payload);
			mac->pib.beacon_payload = tmp;
			mac->pib.beacon_payload_len = bp_len;
			write_unlock(&mac->pib.lock);
		} else {
			dbg_print(mac, BEACON, DBG_ERR, "unable to allocate memory for beacon payload\n");
		}
	} else {
		dbg_print(mac, BEACON, DBG_INFO, "beacon without payload\n");
	}

	r_bsn = mpdu->mhr->seq;

	match = ieee80215_find_pan_desc(mac, desc);
	if (match) {
		dbg_print(mac, BEACON, DBG_INFO, "update pan desc\n");
		match->security = desc->security;
		match->sec_failure = desc->sec_failure;
		match->lq = desc->lq;
		match->gts_permit = desc->gts_permit;
		match->coord_mode = desc->coord_mode;
		match->ch = desc->ch;
		memcpy(&match->sfs, &desc->sfs, sizeof(match->sfs));
		memcpy(&match->coord_addr, &desc->coord_addr, sizeof(match->coord_addr));
		match->timestamp = desc->timestamp;
	} else {
		dbg_print(mac, BEACON, DBG_INFO, "add new pan desc\n");
		ieee80215_add_pan_desc(mac, desc);
	}
	/* Look over sync request */
	ieee80215_sync_check_beacon(mac);

	if (beacon_panid == mac->pib.dev_addr.panid) {
		dbg_print(mac, BEACON, DBG_INFO,
			"beacon for us, bp_len = %u, auto_request = %d\n",
			bp_len, mac->pib.auto_request);
		if (!mac->pib.auto_request || bp_len) {
			dbg_print(mac, BEACON, DBG_INFO, "Notify beacon arrival\n");
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mlme_beacon_notify(_nhle(mac), r_bsn, desc,
			      r_alist, addr_list, bp_len, bp_off);
#endif
		}
		if (mac->pib.auto_request) {
			if (ieee80215_check_pending(mac, r_alist)) {
				ieee80215_dev_addr_t dst;
				ieee80215_mpdu_t *msg;

				if (mpdu->mhr->fc.src_amode == IEEE80215_AMODE_64BIT) {
					dst._16bit = 0xfffe;
					dst._64bit = le64_to_cpu(mpdu->sa->_64bit);
				} else
					dst._16bit = le16_to_cpu(mpdu->sa->_16bit);
				dst.panid = beacon_panid;
				dbg_print(mac, BEACON, DBG_INFO, "We got data on a peer device\n");

				msg = ieee80215_create_data_request_cmd(mac, &dst);
				if (msg) {
					msg->on_confirm = ieee80215_data_confirm;
					skb_queue_head(&mac->to_network, mpdu_to_skb(msg));
				} else {
					dbg_print(mac, BEACON, DBG_ERR, "Unable to allocate data_req\n");
				}
			}
		}
	} else if (0xffff == beacon_panid || 0xffff == mac->pib.dev_addr.panid) {
		dbg_print(mac, BEACON, DBG_INFO, "process beacon due to broadcast panid (in beacon or local)\n");
		if (!mac->pib.auto_request || bp_len) {
			dbg_print(mac, BEACON, DBG_INFO, "Notify beacon arrival\n");
#warning FIXME indication/confurm
#if 0
			_nhle(mac)->mlme_beacon_notify(_nhle(mac), r_bsn, desc,
				r_alist, addr_list, bp_len, bp_off);
#endif
		}
	} else {
		dbg_print(mac, BEACON, DBG_INFO, "alien beacon\n");
	}

	if (match)
		kfree(desc);
exit_kfree:
	mac->f.find_a_beacon = true;
	return;
}

ieee80215_mpdu_t* ieee80215_create_beacon(ieee80215_mac_t *mac)
{
	ieee80215_mpdu_t *mpdu = NULL;
	ieee80215_gts_info_t *gts;
	ieee80215_gts_frame_t *gframe;
	ieee80215_gts_list_t *g;
	ieee80215_paddr_t *pa;
	struct list_head *it;
	struct sk_buff *skb, *tr_skb;

	u8	src_amode;
	u8	idx;
	unsigned long flags;
	u8	*addr_list;
	bool	gts_permit;

	dbg_print(mac, BEACON, DBG_INFO, "Creating beacon\n");
	mpdu = ieee80215_dev_alloc_mpdu(IEEE80215_MAX_FRAME_SIZE, GFP_KERNEL);
	if (!mpdu) {
		dbg_print(mac, BEACON, DBG_ERR, "Cannot allocate memory\n");
		return NULL;
	}
	skb = mpdu_to_skb(mpdu);

	read_lock(&mac->pib.lock);
	switch (mac->pib.dev_addr._16bit) {
		case 0xfffe:
			src_amode = IEEE80215_AMODE_64BIT;
			break;
		case 0xffff:
			dbg_print(mac, BEACON, DBG_ERR, "macShortAddr must not be 0xffff\n");
			BUG();
			break;
		default:
			src_amode = IEEE80215_AMODE_16BIT;
			break;
	}

	mpdu->mhr = (ieee80215_mhr_t*)skb_put(skb, sizeof(ieee80215_mhr_t));
	ieee80215_pack_fc_and_seq(mac, skb, ieee80215_get_bsn(mac), IEEE80215_TYPE_BEACON,
		mac->f.sec_enable ? 1 : 0, 0, 0, 0, IEEE80215_AMODE_NOPAN, src_amode);

	mpdu->s_panid = (u16*)skb_put(skb, sizeof(u16));
	*mpdu->s_panid = cpu_to_le16(mac->pib.dev_addr.panid);
	switch (src_amode) {
		case IEEE80215_AMODE_16BIT:
			dbg_print(mac, BEACON, DBG_INFO, "src16 = 0x%x\n", mac->pib.dev_addr._16bit);
			mpdu->sa = (ieee80215_addr_t*)skb_put(skb, sizeof(u16));
			mpdu->sa->_16bit = cpu_to_le16(mac->pib.dev_addr._16bit);
			break;
		case IEEE80215_AMODE_64BIT:
			dbg_print(mac, BEACON, DBG_INFO, "src64 = 0x%llx\n", mac->pib.dev_addr._64bit);
			mpdu->sa = (ieee80215_addr_t*)skb_put(skb, sizeof(u64));
			mpdu->sa->_64bit = cpu_to_le64(mac->pib.dev_addr._64bit);
			break;
		default:
			dbg_print(mac, BEACON, DBG_ERR, "unexpected src_amode = %u\n", src_amode);
			BUG();
			break;
	}

	mpdu->p.b = (ieee80215_beacon_payload_t*)skb_put(skb, sizeof(mpdu->p.b->sff));
	mpdu->p.b->sff.b_order = mac->pib.beacon_order;
	mpdu->p.b->sff.s_order = mac->pib.superframe_order;
	mpdu->p.b->sff.pan_coord = mac->i.i_pan_coord;
	mpdu->p.b->sff.a_permit = mac->pib.association_permit?1:0;
	mpdu->p.b->sff.fcap_slot = mac->i.final_cap_slot;
	mpdu->p.b->sff.bat_life_ext = mac->pib.bat_life_ext?1:0;
	dbg_print(mac, BEACON, DBG_INFO,
		"bo: %d, so: %d, pan_coord: %d, assoc_permit: %d, fcs: %d, ble: %d\n",
		mpdu->p.b->sff.b_order, mpdu->p.b->sff.s_order,
		mpdu->p.b->sff.pan_coord, mpdu->p.b->sff.a_permit,
		mpdu->p.b->sff.fcap_slot, mpdu->p.b->sff.bat_life_ext);

	/* Adding GTS info into beacon */
	spin_lock_irqsave(&mac->gts.lock, flags);

	gframe = (ieee80215_gts_frame_t*)skb_put(skb, sizeof(ieee80215_gts_spec_t));

	ieee80215_get_pib(mac, IEEE80215_GTS_PERMIT, &gts_permit);
	gframe->spec.permit = gts_permit?1:0;
	gframe->spec.desc_count = 0;

	dbg_print(mac, BEACON, DBG_INFO, "Gts perm: %d, count: %d\n",
		  gframe->spec.permit, mac->gts.active_count);

	if (mac->gts.active_count) {
		u8 gcount = 0;
		dbg_print(mac, BEACON, DBG_ALL, "Has GTS\n");

		/* Add direction field to gts info in beacon */
		skb_put(skb, sizeof(ieee80215_gts_dir_t));

		g = (ieee80215_gts_list_t*)skb->tail;

		dbg_print(mac, BEACON, DBG_INFO, "Gts permit\n");
		list_for_each(it, &mac->gts.db.list) {
			gts = container_of(it, ieee80215_gts_info_t, list);
			BUG_ON(gts == NULL);
			dbg_print(mac, BEACON, DBG_INFO, "Gts 0x%p, active: %d\n",
				  gts, gts->active);
			if (gts->active) {
				dbg_print(mac, BEACON, DBG_INFO, "Gts1 0x%p\n", g);
				skb_put(skb, sizeof(*g));
				dbg_print(mac, BEACON, DBG_INFO, "mpdu_len %d\n", mpdu->skb->len);
				g->starting_slot = gts->starting_slot;
				dbg_print(mac, BEACON, DBG_INFO, "Gts1 0x%p, ss: %d\n",
					  g, g->starting_slot);
				g->_16bit = cpu_to_le16(gts->addr._16bit);
				dbg_print(mac, BEACON, DBG_INFO, "Gts1 0x%p, addr: %d\n",
					  g, g->_16bit);
				g->len = gts->c.len;
				dbg_print(mac, BEACON, DBG_INFO, "Gts1 0x%p, len: %d\n",
					  g, g->len);
				dbg_print(mac, BEACON, DBG_INFO, "mpdu->p.b 0x%p\n", mpdu->p.b);
				dbg_print(mac, BEACON, DBG_INFO, "mpdu->p.b->gts 0x%p\n",
					  gframe);
				dbg_print(mac, BEACON, DBG_INFO, "mpdu->p.b->gts->dir 0x%p\n",
					  &gframe->dir);
				dbg_print(mac, BEACON, DBG_INFO, "gcount %d\n", gcount);
				if (gts->c.dir)
					__set_bit(gcount,(unsigned long*)&gframe->dir);
				else
					__clear_bit(gcount,(unsigned long*)&gframe->dir);
				dbg_print(mac, BEACON, DBG_ALL,
					  "add gts: type: %d, ss: %d, adr: %d, len: %d, dir: %d\n",
					gts->c.type, g->starting_slot, g->_16bit, g->len, gts->c.dir);
				gcount++;
				g++;
			}
		}
		gframe->spec.desc_count = gcount;
	}

	spin_unlock_irqrestore(&mac->gts.lock, flags);

	/* Add pending addresses list into beacon */
	pa = (ieee80215_paddr_t*)skb_put(skb, sizeof(ieee80215_paddr_spec_t));

	pa->addr_spec._16bit_pend = 0;
	pa->addr_spec._64bit_pend = 0;
	addr_list = (u8*)pa + sizeof(pa->addr_spec);

	dbg_print(mac, BEACON, DBG_ALL, "pa: 0x%p, pa_list: 0x%p\n", pa, addr_list);
	spin_lock_irqsave(&mac->tr16.lock, flags);
	dbg_print(mac, BEACON, DBG_INFO, "tr16 queue len = %u\n", skb_queue_len(&mac->tr16));
	if (skb_queue_len(&mac->tr16)) {
		u16 _16bit;
		idx = 0;
		for (tr_skb = mac->tr16.next; tr_skb != (struct sk_buff *)&mac->tr16;
				tr_skb = tr_skb->next) {
			skb_put(skb, sizeof(u16));
			_16bit = cpu_to_le16(skb_to_mpdu(tr_skb)->da->_16bit);
			memcpy(addr_list, &_16bit, sizeof(_16bit));
			dbg_print(mac, BEACON, DBG_INFO,
				"Add pend 16bit: %d\n", _16bit);
			addr_list += sizeof(u16);
			++idx;
		}
		pa->addr_spec._16bit_pend = idx;
		BUG_ON(idx != skb_queue_len(&mac->tr16));
	}
	spin_unlock_irqrestore(&mac->tr16.lock, flags);
	spin_lock_irqsave(&mac->tr64.lock, flags);
	dbg_print(mac, BEACON, DBG_INFO, "tr64 queue len = %u\n", skb_queue_len(&mac->tr64));
	if (skb_queue_len(&mac->tr64)) {
		u64 _64bit;
		idx = 0;
		for (tr_skb = mac->tr64.next; tr_skb != (struct sk_buff *)&mac->tr64;
				   tr_skb = tr_skb->next) {
			skb_put(skb, sizeof(u64));
			_64bit = cpu_to_le64(skb_to_mpdu(tr_skb)->da->_64bit);
			memcpy(addr_list, &_64bit, sizeof(_64bit));
			dbg_print(mac, BEACON, DBG_INFO,
				"Add pend 64bit: %llu\n", _64bit);
			addr_list += sizeof(u64);
			++idx;
		}
		pa->addr_spec._64bit_pend = idx;
		BUG_ON(idx != skb_queue_len(&mac->tr64));
	}
	spin_unlock_irqrestore(&mac->tr64.lock, flags);

	dbg_print(mac, BEACON, DBG_INFO, "beacon payload length = %u\n", mac->pib.beacon_payload_len);
	if (mac->pib.beacon_payload_len) {
		u8 depth, tmp, *buf, *c;

		buf = kzalloc(mac->pib.beacon_payload_len * 5 + 1, GFP_KERNEL);
		BUG_ON(!buf);
		c = buf;
		for (tmp = 0; tmp < mac->pib.beacon_payload_len; ++tmp) {
			c += sprintf(c, " 0x%02x", *(mac->pib.beacon_payload + tmp));
		}
		dbg_print(mac, BEACON, DBG_INFO, "payload:%s\n", buf);
		kfree(buf);
		depth = mac->pib.beacon_payload[2] & 0x78;
		dbg_print(mac, BEACON, DBG_INFO, "my depth = %u\n", depth);

		skb_put(skb, mac->pib.beacon_payload_len);
		memcpy(addr_list, mac->pib.beacon_payload, mac->pib.beacon_payload_len);
	} else {
		dbg_print(mac, BEACON, DBG_INFO, "no nwk beacon payload\n");
	}
	read_unlock(&mac->pib.lock);

	mpdu->mfr = (ieee80215_mfr_t*)skb_put(skb, 2);
	mpdu->mfr->fcs = ieee80215_crc_itu(skb->data, skb->len);

	dbg_dump8(mac, 0, DBG_INFO, skb->data, skb->len);

	return mpdu;
}

int ieee80215_parse_coordinator_realignment(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	ieee80215_pan_desc_t *desc, *match;
	ieee80215_mpdu_t *mpdu = skb_to_mpdu(skb);

	desc = kzalloc(sizeof(*desc), GFP_KERNEL);

	desc->coord_addr.panid = mpdu->p.r->pan_id;
	desc->coord_addr._16bit = mpdu->p.r->c_16bit;
	desc->coord_mode = ((mpdu->p.r->c_16bit == 0xfffe)?IEEE80215_AMODE_64BIT:
			   IEEE80215_AMODE_16BIT);
	desc->ch = mpdu->p.r->lch;
	desc->lq = mpdu->lq;

	if (mpdu->p.r->_16bit != 0xfffe) {
		ieee80215_set_pib(mac, IEEE80215_SHORT_ADDRESS, (u8*)&mpdu->p.r->_16bit);
		ieee80215_set_pib(mac, IEEE80215_COORD_SHORT_ADDRESS,
				  (u8*)&desc->coord_addr._16bit);
	} else {
		u16 _16bit = IEEE80215_COORD_SHORT_ADDRESS_64BIT;
		ieee80215_set_pib(mac, IEEE80215_COORD_SHORT_ADDRESS, (u8*)&_16bit);
	}

	ieee80215_set_pib(mac, IEEE80215_PANID, (u8*)&desc->coord_addr.panid);

	dbg_print(mac, BEACON, DBG_INFO, "Coordinator realign: panid: %d \
			camod: %d, ca: %d, ch: %d, lq: %d, da: %d\n",
		 desc->coord_addr.panid, desc->coord_mode,
		 desc->coord_addr._16bit, desc->ch, desc->lq, mpdu->p.r->_16bit);

	match = ieee80215_find_pan_desc(mac, desc);
	if (!match)
		ieee80215_add_pan_desc(mac, desc);
	else {
		match->security = desc->security;
		match->sec_failure = desc->sec_failure;
		match->lq = desc->lq;
		match->gts_permit = desc->gts_permit;
		match->coord_mode = desc->coord_mode;
		match->ch = desc->ch;
		memcpy(&match->sfs, &desc->sfs, sizeof(match->sfs));
		memcpy(&match->coord_addr, &desc->coord_addr,
			sizeof(match->coord_addr));
		match->timestamp = desc->timestamp;
	}

	if (match)
		kfree(desc);

	kfree_mpdu(mpdu);

	return 0;
}

static int beacon_xmit_confirm(void *obj, struct sk_buff *skb, int code)
{
	ieee80215_mac_t *mac = obj;

	dbg_print(mac, BEACON, DBG_INFO, "code = 0x%x\n");

	if (IEEE80215_PHY_SUCCESS == code) {
		ieee80215_bsn_inc(mac);
	}
	return 0;
}

static void ieee80215_wait_next_beacon_time(ieee80215_mac_t *mac)
{
	dbg_print(mac, BEACON, DBG_INFO, "wait next superframe start %lu jiffies\n",
		mac->totaltime - mac->sf_time);
	PREPARE_DELAYED_WORK(&mac->bwork, ieee80215_send_beacon);
	schedule_delayed_work(&mac->bwork, mac->totaltime - (jiffies-mac->pib.beacon_tx_time));
}

void ieee80215_superframe_end(struct work_struct *work)
{
	ieee80215_mac_t *mac;
	mac = container_of(work, ieee80215_mac_t, bwork.work);

	dbg_print(mac, BEACON, DBG_INFO, "superframe end, now: %lu\n", jiffies);
	set_trx_state(mac, IEEE80215_TRX_OFF, ieee80215_wait_next_beacon_time);
}

static void ieee80215_transmit_beacon(ieee80215_mac_t *mac)
{
	struct sk_buff *beacon;

	beacon = skb_peek(&mac->to_network);
	if (!beacon) {
		dbg_print(mac, BEACON, DBG_ERR, "no pending frame\n");
		BUG();
	}
	if (IEEE80215_TYPE_BEACON != skb_to_mpdu(beacon)->mhr->fc.type) {
		dbg_print(mac, BEACON, DBG_ERR, "pending frame is not a beacon\n");
		BUG();
	}

	PREPARE_DELAYED_WORK(&mac->bwork, ieee80215_superframe_end);
	skb_to_mpdu(beacon)->timestamp = jiffies;
	ieee80215_set_pib(mac, IEEE80215_BEACON_TX_TIME, (void*)&jiffies);
	ieee80215_set_beacon_interval(mac);
	schedule_delayed_work(&mac->bwork, mac->sf_time);
	mac->phy->pd_data_request(mac->phy, beacon);
}

void ieee80215_send_beacon(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of(work, ieee80215_mac_t, bwork.work);
	ieee80215_mpdu_t *beacon;

	dbg_print(mac, BEACON, DBG_INFO, "superfame start\n");

	ieee80215_pupulate_gts_db(mac);
	beacon = ieee80215_create_beacon(mac);
	if (!beacon) {
		dbg_print(mac, BEACON, DBG_ERR, "unable to create beacon\n");
		return;
	}
	beacon->on_confirm = beacon_xmit_confirm;
	skb_queue_head(&mac->to_network, mpdu_to_skb(beacon));
	set_trx_state(mac, IEEE80215_TX_ON, ieee80215_transmit_beacon);
}


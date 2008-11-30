/*
 * ieee80215_mac_lib.h
 * IEEE 802.15.4 MAC. Functions for internal use.
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
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 */

#ifndef IEEE80215_MAC_LIB_H
#define IEEE80215_MAC_LIB_H

#include <net/ieee80215/mac.h>

/* ieee80215_mac_lib.c */
void ieee80215_adjust_symbol_duration(ieee80215_mac_t *mac);
int ieee80215_in_scanning(ieee80215_mac_t *mac);
int ieee80215_ignore_mpdu(ieee80215_mac_t *mac, struct sk_buff *skb);
int ieee80215_cmp_addr(ieee80215_dev_addr_t *addr1, ieee80215_dev_addr_t *addr2);
void ieee80215_pack_fc_and_seq(ieee80215_mac_t *mac, struct sk_buff *skb, u8 sn,
	int type, int sec, int pend, int ack, int intra_pan, int damode, int samode);
ieee80215_mpdu_t* ieee80215_create_orphan_cmd(ieee80215_mac_t *mac);
ieee80215_mpdu_t* ieee80215_create_beacon_request_cmd(ieee80215_mac_t *mac);
ieee80215_mpdu_t* ieee80215_create_data_request_cmd(ieee80215_mac_t *mac,
	struct ieee80215_dev_address *dst_addr);
ieee80215_mpdu_t* ieee80215_dev_alloc_mpdu(unsigned int size, gfp_t gfp_mask);
ieee80215_mpdu_t* ieee80215_create_pid_con_cmd(ieee80215_mac_t *mac);
ieee80215_mpdu_t* ieee80215_create_realign_cmd(ieee80215_mac_t *mac,
	ieee80215_addr_t *dev_addr, u8 lch);
ieee80215_mpdu_t* ieee80215_create_ack(ieee80215_mac_t *mac, struct sk_buff *skb);
ieee80215_mpdu_t* ieee80215_create_assoc_cmd(ieee80215_mac_t *mac,
	ieee80215_dev_addr_t *dst, u8 cap_info);
ieee80215_mpdu_t* ieee80215_create_assocresp_cmd(ieee80215_mac_t *mac,
	ieee80215_dev_addr_t *da, u8 status);
int ieee80215_create_mcps_data_req(ieee80215_mac_t *mac, ieee80215_dev_addr_t *src,
	ieee80215_dev_addr_t *dst, struct sk_buff *skb, u8 with_ack, bool sec_enable);
ieee80215_mpdu_t* ieee80215_create_disassoc_cmd(ieee80215_mac_t *mac,
	u8 reason, u64 _64bit);
ieee80215_mpdu_t* ieee80215_create_gts_request_cmd(ieee80215_mac_t *mac,
	u8 gts_id, u8 gts_len, u8 gts_dir, u8 gts_type, bool sec_enable);
int ieee80215_csma_ca_start(ieee80215_mac_t *mac);
u32 ieee80215_calc_backoffs(ieee80215_mac_t *mac, u32 rnd_backoff);
int ieee80215_can_process_ack(ieee80215_mac_t *mac, struct sk_buff *skb);
void ieee80215_set_beacon_scan_interval(ieee80215_mac_t *mac);
void ieee80215_set_beacon_interval(ieee80215_mac_t *mac);
void ieee80215_set_superframe_params(ieee80215_mac_t *mac);
int ieee80215_mlme_reset_req(ieee80215_mac_t *mac, bool def_reset);
int ieee80215_mlme_rxen_req(ieee80215_mac_t *mac, bool def_permit,
	u32 time, u32 duration);
int ieee80215_data_confirm(void *obj, struct sk_buff *skb, int code);

/* ieee80215_mac.c */
void set_trx_state(ieee80215_mac_t *mac, int state, set_trx_state_func_t func);
u16 ieee80215_pending16_count(ieee80215_mac_t *mac, u16 addr);
u16 ieee80215_pending64_count(ieee80215_mac_t *mac, u64 addr);
void ieee80215_mac_stop(ieee80215_mac_t *mac);
void ieee80215_set_pib_defaults(ieee80215_pib_t *pib);
void ieee80215_set_mac_defaults(ieee80215_mac_t *mac);
void ieee80215_clear_scan(ieee80215_mac_t *mac);
int ieee80215_should_rxon(ieee80215_mac_t *mac);

/* ieee80215_mac_set.c */
int ieee80215_get_pib(ieee80215_mac_t *mac, int attr, void *ret);
int ieee80215_set_pib(ieee80215_mac_t *mac, int attr, void *data);
int ieee80215_mlme_get_req(ieee80215_mac_t *mac, u8 pib_attr);
int ieee80215_mlme_set_req(ieee80215_mac_t *mac, ieee80215_mlme_pib_t a);

/* ieee80215_mac_cmd.c */
int ieee80215_parse_cmd(ieee80215_mac_t *mac, struct sk_buff *skb);

/* ieee80215_gts.c */
void ieee80215_gts_process_slice(struct work_struct *work);
int ieee80215_mlme_gts_req(ieee80215_mac_t *mac, ieee80215_gts_char_t *c,
	bool sec_enable);
int ieee80215_gts_receive(ieee80215_mac_t *mac, ieee80215_gts_list_t *g,
	ieee80215_gts_char_t *gc);
void ieee80215_pupulate_gts_db(ieee80215_mac_t *mac);
ieee80215_gts_info_t* ieee80215_find_gts(ieee80215_mac_t *mac, u16 _16bit,
	ieee80215_gts_char_t *gc);
ieee80215_gts_info_t* ieee80215_allocate_gts(ieee80215_mac_t *mac,
	struct sk_buff *skb, bool zero);
void ieee80215_schedule_gts_slice(ieee80215_mac_t *mac, ieee80215_gts_info_t *gi);
void ieee80215_defragment_gts(ieee80215_mac_t *mac, ieee80215_gts_info_t *gts);

/* ieee80215_purge.c */
int ieee80215_mcps_purge_request(ieee80215_mac_t *mac, struct sk_buff *skb);

/* ieee80215_mac_data.c */
int ieee80215_mcps_data_request(ieee80215_mac_t *mac, ieee80215_dev_addr_t *src,
	ieee80215_dev_addr_t *dst, struct sk_buff *skb, u8 tx_opt);

/* ieee80215_assoc.c */
int ieee80215_mlme_assoc_req(ieee80215_mac_t *mac, u8 lch, u16 c_panid,
	ieee80215_dev_addr_t *crd, u8 cap_info, bool sec_enable);
int ieee80215_mlme_assoc_reply(ieee80215_mac_t *mac,
	ieee80215_dev_addr_t *adev, u8 status, bool sec_enable);
int ieee80215_mlme_orphan_resp(ieee80215_mac_t *mac, ieee80215_dev_addr_t *addr,
	bool assoc_member, bool sec_enable);

/* ieee80215_mac_scan.c */
int ieee80215_mlme_scan_req(ieee80215_mac_t *mac, u8 type, u32 channels,
	u8 duration);

/* ieee80215_rxenable.c */
int ieee80215_mlme_rxen_req(ieee80215_mac_t *mac, bool def_permit, u32 time,
	u32 duration);

/* ieee80215_disassoc.c */
int ieee80215_mlme_disassoc_req(ieee80215_mac_t *mac,
	ieee80215_dev_addr_t *addr, u8 reason, bool sec_enable);

/* ieee80215_sync.c */
int ieee80215_mlme_sync_req(ieee80215_mac_t *mac, u8 lch, bool tr_beacon);
void ieee80215_sync_check_beacon(ieee80215_mac_t *mac);

/* ieee80215_poll.c */
int ieee80215_mlme_poll_req(ieee80215_mac_t *mac, ieee80215_dev_addr_t *crd,
	bool sec_enable);

/* ieee80215_mac_start.c */
int ieee80215_mlme_start_req(ieee80215_mac_t *mac, u16 pan_id, u8 lch, u8 b_order,
	u8 s_order, bool pan_coord, bool bat_life_ext, bool realign, bool sec_enable);

/* ieee80215_secure.c */
ieee80215_acl_pib_t* ieee80215_find_acl(ieee80215_mac_t *mac,
	ieee80215_addr_t *addr);

#endif /* IEEE80215_MAC_LIB_H */

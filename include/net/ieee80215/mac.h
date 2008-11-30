/*
 * ieee80215_mac.h
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

#ifndef IEEE80215_MAC_H
#define IEEE80215_MAC_H

#include <linux/workqueue.h>
#include <net/ieee80215/lib.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/info.h>

/******************************************************************************/
/* Some MAC's strucutre definitions */
/******************************************************************************/

/**
 * \brief MAC ACL Pib entity
 *
 * Structure describe MAC ACL Pib entity
 */
struct ieee80215_acl_pib {
	struct list_head list;		/**< MAC ACL pib list entry */
	ieee80215_dev_addr_t addr;	/**< Specific ACL device addresses */
	u8 sec_mlen;			/**< The number of octets contained in
					 * ACLSecurityMaterial.*/
	u8 *sec_material;
	/**< The specific keying material to be used to protect frames between
	 * the MAC sublayer and the device indicated by the associated
	 * ACLExtendedAddress (see 7.6.1.8).*/
	u8 sec_suite;
	/**< The unique identifier of the security suite to be used to protect
	 * communications between the MAC sublayer and the device indicated by
	 * the associated ACLExtendedAddress as specified in Table 75.*/
};
typedef struct ieee80215_acl_pib ieee80215_acl_pib_t;

/**
 * \brief MAC ACL Pib
 *
 * Structure describe MAC ACL Pib head.
 */
struct ieee80215_acl_pib_head {
	ieee80215_acl_pib_t	pib;	/**< MAC ACL Pib entrys */
	size_t			count;	/**< ACL's count */
	spinlock_t		lock;	/**< Race prevention lock */
};
typedef struct ieee80215_acl_pib_head ieee80215_acl_pib_head_t;

/******************************************************************************/
/* MAC's PAN Information Base (PIB) */
/******************************************************************************/
/**
 * \brief MAC Pib
 *
 * Structure describe MAC Pib
 */
struct ieee80215_pib {
	rwlock_t lock;
	u16	ack_wait_duration;	/**< Maximum symbols to wait for acknowledgment */
	bool	association_permit;	/**< Device is a coordinator and permit association */
	bool	auto_request;		/**< Send data requests automatically */
	bool	bat_life_ext;		/**< Battery life extension on */
	u8	bat_life_ext_period;	/**< Number of backoff periods */
	u8*	beacon_payload;		/**< Content of beacon payload */
	u8	beacon_payload_len;	/**< Beacon payload len in octets */
	u8	beacon_order;		/**< How often coordinator transmit beacons */
	u32	beacon_tx_time;		/**< Time of transmission of last beacon frame in symbols periods */
	u8	bsn;			/**< Beacon sequence number */
	ieee80215_dev_addr_t coord;	/**< Associated coordinator address */
	u8	dsn;			/**< MAC's data or cmd frame seq number */
	u8	max_csma_backoff;	/**< The maximum number of backoffs the
					* CSMA-CA algorithm will attempt before
					* declaring a channel access failure.*/
	u8	min_be;			/**< The minimum value of the backoff exponent in the CSMA-CA.*/
	bool	promiscuous_mode;	/**< Promiscuous mode flag */
	bool	gts_permit;		/**< GTS requests accept flag */
	u8	rx_gts_id;
	bool	rxon;			/**< Enable rx while idle flag */
	ieee80215_dev_addr_t dev_addr;	/**< Device address */
	u8	superframe_order;	/**< Length of the active portion of the superframe, including the beacon frame. */
	u16	tr_pers_time;		/**< The maximum time (in superframe periods) that a transaction
					 * is stored by a coordinator and indicated in its beacon. */
	u8	tx_gts_id;

	/* MAC PIB security attributes */
	ieee80215_acl_pib_head_t acl_entries;	/**< MAC's ACL */
	bool	def_sec;		/**< Indicate whether device can rx/tx of secure frames */
	u8	def_sec_mlen;		/**< Default security material len */
	u8	*def_sec_material;	/**< Default security material contents */
	u8	def_sec_suite;		/**< Default security suite */
	u8	sec_mode;		/**< Default security mode */
};
typedef struct ieee80215_pib ieee80215_pib_t;

union ieee80215_attr_val {
	u16	ack_wait_duration;	/**< Maximum symbols to wait for acknowledgment */
	bool	auto_request;		/**< Send data requests automatically */
	bool	bat_life_ext;		/**< Battery life extension on */
	u8	bat_life_ext_period;	/**< Number of backoff periods */
#ifndef CONFIG_IEEE80215_RFD_NOOPT
	bool	association_permit;	/**< Device is a coordinator and permit association */
	u8*	beacon_payload;		/**< Content of beacon payload */
	u8	beacon_payload_len;	/**< Beacon payload len in octets */
	u8	beacon_order;		/**< How often coordinator transmit beacons */
	unsigned long beacon_tx_time;	/**< Time of transmission of last beacon frame in symbols periods */
	u8	bsn;			/**< Beacon sequence number */
	bool	gts_permit;		/**< GTS requests accept flag */
	bool	promiscuous_mode;	/**< Promiscuous mode flag */
	u8	superframe_order;	/**< Length of the active portion of the superframe, including the beacon frame. */
	u16	tr_pers_time;		/**< The maximum time (in superframe periods)
					* that a transaction is stored by a coordinator
					* and indicated in its beacon. */
#endif
	ieee80215_dev_addr_t coord;	/**< Associated coordinator address */
	u8	dsn;			/**< MAC's data or cmd frame seq number */
	u8	max_csma_backoff;	/**< The maximum number of backoffs the
					 * CSMA-CA algorithm will attempt before
					 * declaring a channel access failure.*/
	u8	min_be;			/**< The minimum value of the backoff exponent in the CSMA-CA.*/
	u16	pan_id;			/**< Associated PAN ID */
	bool	rxon;			/**< Enable rx while idle flag */
	u16	_16bit;			/**< Device short address */

	/* MAC PIB security attributes */
	ieee80215_acl_pib_head_t *acl_entries;	/**< MAC's ACL */
	bool	def_sec;		/**< Indicate whether device can rx/tx of secure frames */
	u8	def_sec_mlen;		/**< Default security material len */
	u8	*def_sec_material;	/**< Default security material contents */
	u8	def_sec_suite;		/**< Default security suite */
	u8	sec_mode;		/**< Default security mode */
};
typedef union ieee80215_attr_val ieee80215_attr_val_t;

/**
 * \brief MLME PIB entry
 */
struct ieee80215_mlme_pib {
	int attr_type;
	ieee80215_attr_val_t attr;
};
typedef struct ieee80215_mlme_pib ieee80215_mlme_pib_t;

struct ieee80215_mac;
typedef void (*set_trx_state_func_t)(struct ieee80215_mac *mac);

/**
 * @brief GTS Info entity
 *
 * Used in GTS DB, in MAC, to store gts related information, received from
 * the peers.
 */
struct ieee80215_gts_info {
	struct list_head	list;
	u8	id;
	u8	starting_slot;	/**< Slot to start for this gts */
	ieee80215_gts_char_t c; /**< GTS characteristics */
	long unsigned int	expires;	/**< Expiration value, jiffies + timeout */
	long unsigned int	pers_time;	/**< GTS persistence time */
	long unsigned int	start;
	bool	active;		/**< marked true, when GTS is active */
	u8	use_count;	/**< Increase, when gts is becoming active, and
				descrease it when we receive/xmit data within this GTS */
	bool	secure;
	ieee80215_dev_addr_t	addr; /**< Peer address */
	ieee80215_acl_pib_t	*acl;
	struct sk_buff_head	*gts_q;	/**< Queue for data packets for this GTS */
	struct delayed_work	gts_work;
	struct ieee80215_mac	*mac;
};
typedef struct ieee80215_gts_info ieee80215_gts_info_t;

/**
 * @brief GTS DB
 *
 * Used in MAC.
 */
struct ieee80215_gts {
	struct list_head list;
	spinlock_t lock;
	u8 id;				/* last gts id */
	u8 active_count;
	u8 s_ss;
	u8 s_ln;
	u8 max_gts;			/**< Maximum GTS allowed in this configuration */
	ieee80215_gts_char_t rc;	/**< GTS req params for !coordinator */
	struct delayed_work gts_perform;
	ieee80215_gts_info_t db;	/**< DB entrys */
};
typedef struct ieee80215_gts ieee80215_gts_t;

/******************************************************************************/
/* MAC's Scan types */
/******************************************************************************/
#define IEEE80215_SCAN_ED	0x0
#define IEEE80215_SCAN_ACTIVE	0x1
#define IEEE80215_SCAN_PASSIVE	0x2
#define IEEE80215_SCAN_ORPHAN	0x3

/******************************************************************************/
/* MAC's PAN descriptor Structure */
/******************************************************************************/
/**
 * @brief MAC's PAN descriptor structure
 */
struct ieee80215_pan_desc {
	struct list_head	list;
	u8			coord_mode;	/**< Coordinator addressing mode */
	ieee80215_dev_addr_t	coord_addr;	/**< Coordinator address */
	u8			ch;		/**< Current logical channel */
	ieee80215_sff_t		sfs;		/**< Super frame specification */
	bool			gts_permit;	/**< Coordinator accept GTS's */
	u8			lq;		/**< Link quality */
	u32			timestamp;	/**< Beacon arrival timestamp */
	bool			security;	/**< Beacon secure? */
	u8			acl_entry;	/**< macSecurityMode parameter */
	bool			sec_failure;	/**< Error in security processing ? */
};
typedef struct ieee80215_pan_desc ieee80215_pan_desc_t;

/**
 * @brief MAC's PAN descriptors list
 */
struct ieee80215_pdesc_head {
	spinlock_t lock;
	struct list_head list;
	u8 count;
};
typedef struct ieee80215_pdesc_head ieee80215_pdesc_head_t;

/******************************************************************************/
/* MAC's Structure */
/******************************************************************************/
enum ieee80215_mac_states {
	WAIT = 0,
	PEND_AS,
	PEND_AS1,
	PEND_OS,
	PEND_OS1,
	PEND_PS,
	YA,
	ZA,
	ZP,
	ACTIVE,
	B,
	C,
	D,
	E,
	F,
	G,
	H,
	PEND_RESET,
	PEND_ED,
	ED
};
typedef enum ieee80215_mac_states ieee80215_mac_states_t;

extern char *s_states[];

/**
 * @brief MAC's scan information
 */
struct ieee80215_scan {
	u8	status;
	u8	type;
	u8	duration;
	u8	current_channel;
	u32	ch_list;
	u32	unscan_ch;
	u8	result_size;
	u8	*ed_detect_list;
	u32	scan_time;
	u32	delta_scan;
	u16	tmp_panid;
	u32	start_scan;
	ieee80215_pdesc_head_t desc;
	struct delayed_work work;
	u32	channels_below_threshold; /* to report ED scan results */
};
typedef struct ieee80215_scan ieee80215_scan_t;

struct ieee80215_b {
	bool	ack_recv;
	bool	assoc_member;
	bool	beacon_enabled_pan;
	bool	beacon_req;
	bool	ble;
	bool	broadcast;
	bool	co_re;
	bool	decode_success;
	bool	find_a_beacon;
	bool	find_a_coord_realign;
	bool	ffd_device;
	bool	gts_cap;
	bool	in_acl;
	bool	key_found;
	bool	msdu_found;
	bool	not_correct;
	bool	pan_coord;
	bool	passed;
	bool	phy_in_tx;
	bool	r_acle;
	bool	r_sec;
	bool	sec_proc;
	bool	sec_enable;
	bool	set_default_pib;
	bool	track_beacon;
	bool	sync_on;
	bool	await_pend_data;
	bool	too_late;
	bool	too_long;
	bool	will_fit;
};
typedef struct ieee80215_b ieee80215_b_t;

struct csma_ca_values {
	u8	nb;	/**< Number of Backoff's */
	u8	cw;	/**< Contention window length, only for slotted CSMA-CA */
	u8	be;	/**< Backoff exponent */
};
typedef struct csma_ca_values csma_ca_t;

struct ieee80215_i {
	u16	assoc_dev_addr;
	csma_ca_t	csma_val;
	u8	action;
	u8	bo;
	u8	cam;
	u8	clc;
	u16	cpid;
	u16	co_pid;
	u16	co_shortaddr;
	u32	cap_len;		/**< A current CAP len, in symbols */
	u8	num_cap_slots;		/**< A count of slots in CAP */
	u8	slot_duration;		/**< A slot duration in symbols */
	u8	final_cap_slot;		/**< Last number of slot in the CAP */
	u32	symbols_per_slot;	/**< Count of symbols in slot */
	u8	current_channel;
	u8	dam;
	u32	rxon_time;
	u8	disassociate_reason;
	u16	dpid;
	u8	etbd;
	u8	i_pan_coord;
	u16	len;
	u16	missed_beacons;
	u8	ml;
	u8	mlq;
	u8	num_gts;
	long unsigned int num_of_backoffs;
	u8	num_comm_failures;
	u8	num_pend;
	u8	original_channel;
	u16	panid;
	u8	res_size;
	u8	r_sn;
	u8	r_dam;
	u16	r_dpid;
	u8	r_sam;
	u16	r_spid;
	u32	rxon_duration;
	u8	sam;
	u16	spid;
	u8	startA;
	u8	strength;
	u8	sfo;
	u8	gts;
	u8	max_trq;
};
typedef struct ieee80215_i ieee80215_i_t;

/**
 * \brief MAC structure
 */
struct ieee80215_mac {
	char			*name;	/**< Current MAC name */
	void			*priv;	/**< Private MAC data */
	ieee80215_phy_t		*phy;	/**< PHY to use */

	ieee80215_pib_t		pib;
	ieee80215_mlme_pib_t	pib_attr;

	/*spinlock_t		to_network_lock;*/
	bool			to_network_running;
	struct sk_buff_head	to_network;

	/*spinlock_t		from_network_lock;*/
	bool			from_network_running;
	struct sk_buff_head	from_network;

	struct sk_buff_head	tr16;	/**< indirect transaction info */
	struct sk_buff_head	tr64;	/**< indirect transaction info */

	struct sk_buff		cmd;	/**< Static command to MAC */
	spinlock_t		lock;	/**< State change lock */
	struct timer_list	timer;
	void			*bg_data;

	ieee80215_mac_states_t	state;
	ieee80215_mac_states_t	original_state;

	csma_ca_t		csma_val;
	ieee80215_b_t		f;	/* Boolean Flags */
	ieee80215_i_t		i;	/* Flags */
	bool			poll_pending;
	bool			assoc_pending;

	/* GTS */
	ieee80215_gts_t		gts;
	ieee80215_gts_info_t	*curr_gts;
	struct delayed_work	gts_data_ack;

	/* Time values */
	u32			symbol_duration;
	long unsigned int	totaltime;
	long unsigned int	sf_time;

	/* Timers, preliminary definitions */
	struct timer_list	t_ack_wait;
	struct timer_list	t_backoff;
	struct timer_list	t_beacon;
	struct timer_list	t_btp;
	struct timer_list	t_defertime;
	struct timer_list	t_max_frame_resp_time;
	struct timer_list	t_resp_wait_time;
	struct timer_list	t_rxon_time;
	struct timer_list	t_scan_duration;
	struct timer_list	t_superframe;

	ieee80215_dev_addr_t	caddr;
	ieee80215_dev_addr_t	association_addr;
	ieee80215_dev_addr_t	coord_addr;
	ieee80215_dev_addr_t	dev_addr;
	ieee80215_dev_addr_t	dst;
	ieee80215_dev_addr_t	no_addr;
	ieee80215_dev_addr_t	r_addr;
	ieee80215_dev_addr_t	r_da;
	ieee80215_dev_addr_t	r_sa;
	ieee80215_dev_addr_t	src;

	u16			assoc_dev_addr[4];
	u16			test_addr[4];
	u32			r_direction;
	u8			msdu_handle;
	u8			p_msdu_handle;
	u8			max_store_trans;	/**< Maximum allowed transaction to store */
	ieee80215_scan_t	scan;
	u8			assoc_status;		/**< association attempt status */
	int			pending_trx_state;
	set_trx_state_func_t	pending_trx_state_func;

	struct workqueue_struct	*worker;		/**< Batch worker */

	struct work_struct	data_indication;	/**< PD-Data.indication batch process */
	struct work_struct	get_request;		/**< MLME-Get.request */
	struct work_struct	set_request;		/**< MLME-Set.request */
#ifndef CONFIG_IEEE80215_RFD_NOOPT
	struct work_struct	start_request;		/**< MLME-Start.request */
	struct work_struct	purge_request;		/**< MCPS-Purge.request */

	struct delayed_work	gts_request;		/**< MLME-Gts.request */
#endif
	struct delayed_work	bwork;			/**< Batch delayed work */
	struct delayed_work	data_request;		/**< MCPS-Data.request */
	struct delayed_work	associate_request;	/**< MLME-Associate.request */
	struct delayed_work	associate_timeout;
	struct delayed_work	disassociate_request;	/**< MLME-Disassociate.request */
	struct delayed_work	rx_enable_request;	/**< MLME-RxEnabel.request */
	struct delayed_work	sync_request;		/**< MLME-Sync.request */
	struct delayed_work	poll_request;		/**< MLME-Poll.request */
	struct delayed_work	ack_wait;
	struct delayed_work	csma_dwork;

	int (*pd_data_confirm)(struct ieee80215_mac *mac, int code);
	int (*pd_data_indicate)(struct ieee80215_mac *mac, struct sk_buff *skb);

	/* NLME callbacks, ie. PHY-ME confirm calls */
	int (*plme_cca_confirm)(struct ieee80215_mac *mac, int code);
	int (*plme_ed_confirm)(struct ieee80215_mac *mac, int code, int ret);
	int (*plme_get_confirm)(struct ieee80215_mac *mac, int code,
		ieee80215_plme_pib_t *attr);
	int (*plme_set_trx_state_confirm)(struct ieee80215_mac *mac, int code);
	int (*plme_set_confirm)(struct ieee80215_mac *mac, int code,
		ieee80215_plme_pib_t *attr);

	/* MCPS entry */
	int (*mcps_data_req)(struct ieee80215_mac *mac, ieee80215_dev_addr_t *src,
		ieee80215_dev_addr_t *dst, struct sk_buff *skb, u8 tx_opt);
	int (*mlme_assoc_req)(struct ieee80215_mac *mac, u8 lch, u16 c_panid,
		ieee80215_dev_addr_t *crd, u8 cap_info, bool sec_enable);
	int (*mlme_assoc_reply)(struct ieee80215_mac *mac,
		ieee80215_dev_addr_t *adev, u8 status, bool sec_enable);
	int (*mlme_disassoc_req)(struct ieee80215_mac *mac, ieee80215_dev_addr_t *addr,
		u8 reason, bool sec_enable);
	int (*mlme_get_req)(struct ieee80215_mac *mac, u8 pib_attr);
	int (*mlme_reset_req)(struct ieee80215_mac *mac, bool def_reset);
	int (*mlme_rxen_req)(struct ieee80215_mac *mac, bool def_permit, u32 time,
		u32 duration);
	int (*mlme_scan_req)(struct ieee80215_mac *mac, u8 type, u32 channels,
		u8 duration);
	int (*mlme_set_req)(struct ieee80215_mac *mac, ieee80215_mlme_pib_t a);
	int (*mlme_sync_req)(struct ieee80215_mac *mac, u8 lch, bool tr_beacon);
	int (*mlme_poll_req)(struct ieee80215_mac *mac, ieee80215_dev_addr_t *crd,
		bool sec_enable);
	int (*mlme_orphan_resp)(struct ieee80215_mac *mac, ieee80215_dev_addr_t *addr,
		bool assoc_member, bool sec_enable);
#ifndef CONFIG_IEEE80215_RFD_NOOPT
	int (*mcps_purge_req)(struct ieee80215_mac *mac, struct sk_buff *skb);
	int (*mlme_gts_req)(struct ieee80215_mac *mac, ieee80215_gts_char_t *c, bool sec_enable);
	int (*mlme_start_req)(struct ieee80215_mac *mac, u16 pan_id, u8 lch, u8 b_order,
		u8 s_order, bool pan_coord, bool bat_life_ext, bool realign, bool sec_enable);
#endif
};
typedef struct ieee80215_mac ieee80215_mac_t;

#define _mac(phy) ((ieee80215_mac_t*)phy->priv)

static __inline__ void ieee80215_set_state(ieee80215_mac_t *mac, ieee80215_mac_states_t new_state)
{
#warning FIXME debug
#if 0
	dbg_print(mac, CORE, DBG_INFO, "change state: [%s] -> [%s]\n",
		s_states[mac->state], s_states[new_state]);
#endif
	mac->original_state = mac->state;
	mac->state = new_state;
}

static __inline__ void ieee80215_restore_state(ieee80215_mac_t *mac)
{
#warning FIXME debug
#if 0
	dbg_print(mac, CORE, DBG_INFO, "Restoring state: [%s] -> [%s]\n",
		s_states[mac->state], s_states[mac->original_state]);
#endif
	mac->state = mac->original_state;
}

#define IEEE80215_BACKOFF(mac)  ieee80215_random_range(1, ((1<<mac->csma_val.be) - 1))

static __inline__ u8 ieee80215_get_dsn(struct ieee80215_mac *mac)
{
	u8 ret;
	read_lock(&mac->pib.lock);
	ret = mac->pib.dsn;
	read_unlock(&mac->pib.lock);
	return ret;
}

static __inline__ void ieee80215_dsn_inc(struct ieee80215_mac *mac)
{
	write_lock(&mac->pib.lock);
	if (mac->pib.dsn == IEEE80215_DSN_MAX)
		mac->pib.dsn = IEEE80215_DSN_MIN;
	else
		mac->pib.dsn++;
	write_unlock(&mac->pib.lock);
}

#ifndef CONFIG_IEEE80215_RFD_NOOPT
static __inline__ u8 ieee80215_get_bsn(struct ieee80215_mac *mac)
{
	u8 ret;
	read_lock(&mac->pib.lock);
	ret = mac->pib.bsn;
	read_unlock(&mac->pib.lock);
	return ret;
}

static __inline__ void ieee80215_bsn_inc(struct ieee80215_mac *mac)
{
	u8 ret = ieee80215_get_bsn(mac);
	write_lock(&mac->pib.lock);
	if (ret == IEEE80215_BSN_MAX)
		mac->pib.bsn = IEEE80215_BSN_MIN;
	else
		mac->pib.bsn++;
	write_unlock(&mac->pib.lock);
}
#endif

static inline int ieee80215_slotted(ieee80215_mac_t *mac) {
	int ret;

	read_lock(&mac->pib.lock);
	ret = (IEEE80215_BEACON_ORDER_MAX == mac->pib.beacon_order) ? 0 : 1;
	read_unlock(&mac->pib.lock);
	return ret;
}

static inline void dump_mpdu(struct ieee80215_mac *obj, ieee80215_mpdu_t *mpdu)
{
	ieee80215_fc_t *fc;

	fc = &mpdu->mhr->fc;

	__print_mpdu(mpdu);
#warning FIXME debug
#if 0
	dbg_print(obj, CORE, DBG_ALL,
		"type: %d, sec: %d, pend: %d, ack_req: %d, intra_pan: %d, dst addr mode: %d, src addr mode: %d\n",
		fc->type, fc->security, fc->pend, fc->ack_req, fc->intra_pan, fc->dst_amode, fc->src_amode);

	dbg_print(obj, CORE, DBG_ALL,
		"s_panid = 0x%p, mhr = 0x%p, da = 0x%p, sa = 0x%p\n",
		mpdu->s_panid, mpdu->mhr, mpdu->da, mpdu->sa);
	
	if (mpdu->sa && !fc->intra_pan) {
		dbg_print(obj, CORE, DBG_INFO, "src_panid: %d\n", *mpdu->s_panid);
	}
	switch(fc->src_amode) {
	case IEEE80215_AMODE_16BIT:
		dbg_print(obj, CORE, DBG_INFO, "src[16bit]: %d\n", mpdu->sa->_16bit);
		break;
	case IEEE80215_AMODE_64BIT:
		dbg_print(obj, CORE, DBG_INFO, "src[64bit]: %lu\n", mpdu->sa->_64bit);
		break;
	default:
		dbg_print(obj, CORE, DBG_INFO, "src: noaddr\n");
		break;
	}
	if (mpdu->da) {
		dbg_print(obj, CORE, DBG_INFO, "dst_panid: %d\n", *mpdu->d_panid);
	}
	if (fc->intra_pan)
		dbg_print(obj, CORE, DBG_INFO, "intra pan transmission\n");

	switch(fc->dst_amode) {
	case IEEE80215_AMODE_16BIT:
		dbg_print(obj, CORE, DBG_INFO, "dst[16bit]: %d\n", mpdu->da->_16bit);
		break;
	case IEEE80215_AMODE_64BIT:
		dbg_print(obj, CORE, DBG_INFO, "dst[64bit]: %lu\n", mpdu->da->_64bit);
		break;
	default:
		dbg_print(obj, CORE, DBG_INFO, "dst: noaddr\n");
		break;
	}
	dbg_print(obj, CORE, DBG_INFO, "mpdu payload: 0x%p\n", mpdu->p.msdu);

	switch(fc->type) {
	case IEEE80215_TYPE_BEACON:
		dbg_print(obj, CORE, DBG_INFO, "Frame is beacon, bid: %d\n", mpdu->mhr->seq);
		dbg_print(obj, 0, DBG_INFO,
			"bo: %d, so: %d, pan_coord: %d, assoc_permit: %d, fcs: %d, ble: %d\n",
			mpdu->p.b->sff.b_order, mpdu->p.b->sff.s_order,
			mpdu->p.b->sff.pan_coord, mpdu->p.b->sff.a_permit,
			mpdu->p.b->sff.fcap_slot, mpdu->p.b->sff.bat_life_ext);
		break;
	case IEEE80215_TYPE_ACK:
		dbg_print(obj, CORE, DBG_INFO, "Frame is ack, seq: %d\n", mpdu->mhr->seq);
		break;
	case IEEE80215_TYPE_DATA:
		dbg_print(obj, CORE, DBG_INFO, "Frame is data\n");
		break;
	case IEEE80215_TYPE_MAC_CMD:
		dbg_print(obj, CORE, DBG_INFO, "Frame is mac cmd, id: %d\n", mpdu->p.g->cmd_id);
		switch(mpdu->p.g->cmd_id) {
		case IEEE80215_ASSOCIATION_REQ:
			dbg_print(obj, CORE, DBG_INFO, "Association request, from %lu\n", mpdu->sa->_64bit);
			break;
		case IEEE80215_ASSOCIATION_PERM:
			dbg_print(obj, CORE, DBG_INFO, "Association reply, from %lu, status: %d, 16bit: %d\n",
				mpdu->da->_16bit, mpdu->p.aresp->status, mpdu->p.aresp->_16bit);
			break;
		case IEEE80215_DISASSOCIATION_NOTIFY:
			break;
		case IEEE80215_DATA_REQ:
			break;
		case IEEE80215_PANID_CONFLICT_NOTIFY:
			break;
		case IEEE80215_ORPHAN_NOTIFY:
			break;
		case IEEE80215_BEACON_REQ:
			break;
		case IEEE80215_COORD_REALIGN_NOTIFY:
			break;
		case IEEE80215_GTS_REQ:
			break;
		case IEEE80215_GTS_ALLOC:
			break;
		default:
			break;
		}
		break;
	default:
		dbg_print(obj, CORE, DBG_INFO, "Unknown frame type\n");
		break;
	}
	dbg_dump8(obj, CORE, DBG_INFO, mpdu->skb->data, mpdu->skb->len);
#endif
}

int ieee80215_register_phy(ieee80215_phy_t *phy);
int ieee80215_unregister_phy(ieee80215_phy_t *phy);

#endif /* IEEE80215_MAC_H */

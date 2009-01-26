#ifndef IEEE80215_MAC_STRUCT_H
#define IEEE80215_MAC_STRUCT_H

/* csma_ca values */
struct csma_ca_values {
	u8	nb;	/**< Number of Backoff's */
	u8	cw;	/**< Contention window length, only for slotted CSMA-CA */
	u8	be;	/**< Backoff exponent */
};

struct ieee80215_i {
	u16	assoc_dev_addr;
	struct  csma_ca_values	csma_val;
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

/**
 * \brief MAC ACL Pib entity
 *
 * Structure describe MAC ACL Pib entity
 */
struct ieee80215_acl_pib {
	struct list_head list;		/**< MAC ACL pib list entry */
	struct sockaddr_ieee80215 addr;	/**< Specific ACL device addresses */
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

/**
 * \brief MAC ACL Pib
 *
 * Structure describe MAC ACL Pib head.
 */
struct ieee80215_acl_pib_head {
	struct ieee80215_acl_pib pib;	/**< MAC ACL Pib entrys */
	size_t			count;	/**< ACL's count */
	spinlock_t		lock;	/**< Race prevention lock */
};
/******************************************************************************/
/* MAC's PAN Information Base (PIB) */
/******************************************************************************/
/**
 * \brief MAC Pib
 *
 * Structure describe MAC Pib
 */
struct ieee80215_pib_data {
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
	struct sockaddr_ieee80215 coord;	/**< Associated coordinator address */
	u8	dsn;			/**< MAC's data or cmd frame seq number */
	u8	max_csma_backoff;	/**< The maximum number of backoffs the
					* CSMA-CA algorithm will attempt before
					* declaring a channel access failure.*/
	u8	min_be;			/**< The minimum value of the backoff exponent in the CSMA-CA.*/
	bool	promiscuous_mode;	/**< Promiscuous mode flag */
	bool	gts_permit;		/**< GTS requests accept flag */
	u8	rx_gts_id;
	bool	rxon;			/**< Enable rx while idle flag */
	struct sockaddr_ieee80215 dev_addr;	/**< Device address */
	u8	superframe_order;	/**< Length of the active portion of the superframe, including the beacon frame. */
	u16	tr_pers_time;		/**< The maximum time (in superframe periods) that a transaction
					 * is stored by a coordinator and indicated in its beacon. */
	u8	tx_gts_id;

	/* MAC PIB security attributes */
	struct ieee80215_acl_pib_head acl_entries;	/**< MAC's ACL */
	bool	def_sec;		/**< Indicate whether device can rx/tx of secure frames */
	u8	def_sec_mlen;		/**< Default security material len */
	u8	*def_sec_material;	/**< Default security material contents */
	u8	def_sec_suite;		/**< Default security suite */
	u8	sec_mode;		/**< Default security mode */
};
/**
 * @brief MAC's PAN descriptors list
 */
struct ieee80215_pdesc_head {
	spinlock_t lock;
	struct list_head list;
	u8 count;
};
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
	struct ieee80215_pdesc_head desc;
	struct delayed_work work;
	u32	channels_below_threshold; /* to report ED scan results */
};

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
	struct sockaddr_ieee80215 coord;	/**< Associated coordinator address */
	u8	dsn;			/**< MAC's data or cmd frame seq number */
	u8	max_csma_backoff;	/**< The maximum number of backoffs the
					 * CSMA-CA algorithm will attempt before
					 * declaring a channel access failure.*/
	u8	min_be;			/**< The minimum value of the backoff exponent in the CSMA-CA.*/
	u16	pan_id;			/**< Associated PAN ID */
	bool	rxon;			/**< Enable rx while idle flag */
	u16	_16bit;			/**< Device short address */

	/* MAC PIB security attributes */
	struct ieee80215_acl_pib_head *acl_entries;	/**< MAC's ACL */
	bool	def_sec;		/**< Indicate whether device can rx/tx of secure frames */
	u8	def_sec_mlen;		/**< Default security material len */
	u8	*def_sec_material;	/**< Default security material contents */
	u8	def_sec_suite;		/**< Default security suite */
	u8	sec_mode;		/**< Default security mode */
};
/**
 * \brief MLME PIB entry
 */
struct ieee80215_mlme_pib {
	int attr_type;
	union ieee80215_attr_val attr;
};

/**
 * \brief MAC structure
 */
struct ieee80215_mac {
	struct ieee80215_pib_data	pib;
	struct ieee80215_mlme_pib	pib_attr;


	struct sk_buff_head	tr16;	/**< indirect transaction info */
	struct sk_buff_head	tr64;	/**< indirect transaction info */

	spinlock_t		lock;	/**< State change lock */
	struct timer_list	timer;
	int			state;

#if 0
	ieee80215_mac_states_t	state;
	ieee80215_mac_states_t	original_state;
#endif

	struct csma_ca_values	csma_val;
	struct ieee80215_b	f;	/* Boolean Flags */
	struct ieee80215_i	i;	/* Flags */
	bool			poll_pending;
	bool			assoc_pending;

#if 0
	/* Time values */
	u32			symbol_duration;
	long unsigned int	totaltime;
	long unsigned int	sf_time;
#endif

#if 0
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
#endif

	struct sockaddr_ieee80215 coord_addr;

	u8			max_store_trans;	/**< Maximum allowed transaction to store */
	struct ieee80215_scan	scan;
	u8			assoc_status;		/**< association attempt status */
	int			pending_trx_state;

};

#endif


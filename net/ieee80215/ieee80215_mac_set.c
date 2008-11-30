/*
 * ieee80215_mac_set
 *
 * Description: MAC MLME-SET/GET helper functions.
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

#include <net/ieee80215/ieee80215.h>
#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/const.h>

/**
 * \brief MLME-GET.request MAC layer handler
 *
 * Called from workqueue to process GET-request from NHLE
 *
 * \param work current work struct pointer
 * \return 0 if Ok, errno if fail
 */
static void ieee80215_bg_mlme_get_req ( struct work_struct *work )
{
	ieee80215_mac_t *mac = container_of ( work, ieee80215_mac_t, get_request );
	int pib_attr = mac->pib_attr.attr_type, ret = IEEE80215_SUCCESS;

	mac->pib_attr.attr_type = pib_attr;
	ret = ieee80215_get_pib ( mac, pib_attr, ( u8* ) &mac->pib_attr.attr );
#warning FIXME indication/confurm
#if 0
	_nhle ( mac )->mlme_get_confirm ( _nhle ( mac ), ret, &mac->pib_attr );
#endif
	return;
}

/**
 * \brief MLME-GET.request to MAC from NHLE
 *
 * Called from NHLE in order to get attribute value from MAC's pib
 *
 * \param mac current mac pointer
 * \param pib_attr attribute to get
 * \return 0 if Ok, errno if fail
 */
int ieee80215_mlme_get_req(ieee80215_mac_t *mac, u8 pib_attr)
{
	mac->pib_attr.attr_type = pib_attr;
	PREPARE_WORK(&mac->get_request, ieee80215_bg_mlme_get_req);
	queue_work(mac->worker, &mac->get_request);
	return 0;
}

int ieee80215_get_pib ( ieee80215_mac_t *mac, int attr, void *ret )
{
	int r = IEEE80215_SUCCESS;
	ieee80215_attr_val_t *a;
	read_lock ( &mac->pib.lock );

	a = ( ieee80215_attr_val_t* ) ret;
	switch ( attr )
	{
		case IEEE80215_ACK_WAIT_DURATION:
			a->ack_wait_duration = mac->pib.ack_wait_duration;
			break;
		case IEEE80215_AUTO_REQUEST:
			a->auto_request = mac->pib.auto_request;
			break;
		case IEEE80215_BAT_LIFE_EXT:
			a->bat_life_ext = mac->pib.bat_life_ext;
			break;
		case IEEE80215_BAT_LIFE_EXT_PERIOD:
			a->bat_life_ext_period = mac->pib.bat_life_ext_period;
			break;
		case IEEE80215_COORD_EXTENDED_ADDRESS:
			a->coord._64bit = mac->pib.coord._64bit;
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
			dbg_print(mac, SET_GET, DBG_ALL, "coord[64bit]: %llu, %llu\n",
				  mac->pib.coord._64bit, a->coord._64bit);
			break;
		case IEEE80215_COORD_SHORT_ADDRESS:
			a->coord._16bit = mac->pib.coord._16bit;
			dbg_print(mac, SET_GET, DBG_ALL, "coord[16bit]: %d, %d\n",
				  mac->pib.coord._16bit, a->coord._16bit);
			break;
		case IEEE80215_MAX_CSMA_BACKOFF:
			a->max_csma_backoff = mac->pib.max_csma_backoff;
			break;
		case IEEE80215_MIN_BE:
			a->min_be = mac->pib.min_be;
			break;
		case IEEE80215_PANID:
			a->pan_id = mac->pib.dev_addr.panid;
			break;
		case IEEE80215_RXON_WHEN_IDLE:
			a->rxon = mac->pib.rxon;
			break;
		case IEEE80215_SHORT_ADDRESS:
			a->_16bit = mac->pib.dev_addr._16bit;
			break;
		case IEEE80215_ACL_ENTRY_DESCRIPTOR_SET:
		case IEEE80215_ACL_ENTRY_DESCRIPTOR_SET_SIZE:
			a->acl_entries = &mac->pib.acl_entries;
			break;
		case IEEE80215_DEFAULT_SECURITY:
			a->def_sec = mac->pib.def_sec;
			break;
		case IEEE80215_DEFAULT_SECURITY_MLEN:
			a->def_sec_mlen = mac->pib.def_sec_mlen;
			break;
		case IEEE80215_DEFAULT_SECURITY_MATERIAL:
			a->def_sec_material = mac->pib.def_sec_material;
			break;
		case IEEE80215_DEFAULT_SECURITY_SUITE:
			a->def_sec_suite = mac->pib.def_sec_suite;
			break;
		case IEEE80215_SECURITY_MODE:
			a->sec_mode = mac->pib.sec_mode;
			break;
#ifndef CONFIG_IEEE80215_RFD_NOOPT
		case IEEE80215_ASSOCIATION_PERMIT:
			a->association_permit = mac->pib.association_permit;
			break;
		case IEEE80215_BEACON_PAYLOAD:
			a->beacon_payload = mac->pib.beacon_payload;
			break;
		case IEEE80215_BEACON_PAYLOAD_LEN:
			a->beacon_payload_len = mac->pib.beacon_payload_len;
			break;
		case IEEE80215_BEACON_ORDER:
			a->beacon_order = mac->pib.beacon_order;
			break;
		case IEEE80215_BEACON_TX_TIME:
			a->beacon_tx_time = mac->pib.beacon_tx_time;
			break;
		case IEEE80215_BSN:
			a->bsn = mac->pib.bsn;
			break;
		case IEEE80215_GTS_PERMIT:
			a->gts_permit = mac->pib.gts_permit;
			break;
		case IEEE80215_PROMISCOUS_MODE:
			a->promiscuous_mode = mac->pib.promiscuous_mode;
			break;
		case IEEE80215_SUPERFRAME_ORDER:
			a->superframe_order = mac->pib.superframe_order;
			break;
		case IEEE80215_TRANSACTION_PERSISTENSE_TIME:
			a->tr_pers_time = mac->pib.tr_pers_time;
			break;
#endif
		default:
			r = IEEE80215_UNSUPPORTED_ATTR;
			break;
	}
	read_unlock ( &mac->pib.lock );
	return r;
}

/**
 * \brief MLME-SET.request MAC layer handler
 *
 * Called from workqueue to process SET-request from NHLE
 *
 * \param work pointer to current work struct
 * \return 0 if Ok, errno if fail
 */
static void ieee80215_bg_mlme_set_req(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of ( work, ieee80215_mac_t, set_request );
	int ret = IEEE80215_SUCCESS;

	BUG_ON ( mac==NULL );

	dbg_print ( mac, SET_GET, DBG_ALL, "mac: 0x%p\n", mac );

	ret = ieee80215_set_pib(mac, mac->pib_attr.attr_type, (u8*)&mac->pib_attr.attr);
	dbg_print(mac, SET_GET, DBG_ALL, "Set is done, informing upper layer\n" );
#warning FIXME indication/confurm
#if 0
	_nhle ( mac )->mlme_set_confirm ( _nhle ( mac ), ret, mac->pib_attr.attr_type );
#endif
	return;
}

/**
 * \brief MLME-SET.request to MAC from NHLE
 *
 * Called by NHLE to modify MAC's pib
 *
 * \param mac current mac pointer
 * \param a attribute information
 * \return 0 if Ok, errno if fail
 */
int ieee80215_mlme_set_req(ieee80215_mac_t *mac, ieee80215_mlme_pib_t a)
{
	dbg_print(mac, SET_GET, DBG_ALL, "Set req on mac: 0x%p, attr: %d\n",
		mac, a.attr_type );
	memcpy ( &mac->pib_attr, &a, sizeof ( a ) );
	PREPARE_WORK(&mac->set_request, ieee80215_bg_mlme_set_req);
	queue_work(mac->worker, &mac->set_request);
	return 0;
}

int ieee80215_set_pib ( ieee80215_mac_t *mac, int attr, void *data )
{
	int ret = IEEE80215_SUCCESS;
	ieee80215_attr_val_t *a;
	write_lock ( &mac->pib.lock );

	a = ( ieee80215_attr_val_t* ) data;
	switch ( attr )
	{
		case IEEE80215_ACK_WAIT_DURATION:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: ack_wait_duration: %d\n",
						a->ack_wait_duration );
			if ( a->ack_wait_duration < IEEE80215_ACK_WAIT_DURATION_MIN ||
					a->ack_wait_duration > IEEE80215_ACK_WAIT_DURATION_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR,
							"ack_wait_duration is out of range: %d\n",
							a->ack_wait_duration );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.ack_wait_duration = a->ack_wait_duration;
			break;
		case IEEE80215_AUTO_REQUEST:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: auto_request: %s\n",
						a->auto_request?"true":"false" );
			mac->pib.auto_request = a->auto_request;
			break;
		case IEEE80215_BAT_LIFE_EXT:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: bat_life_ext: %s\n",
						a->bat_life_ext?"true":"false" );
			mac->pib.bat_life_ext = a->bat_life_ext;
			break;
		case IEEE80215_BAT_LIFE_EXT_PERIOD:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: bat_life_ext_period: %d\n",
						a->bat_life_ext_period );
			if ( a->bat_life_ext_period < IEEE80215_BAT_LIFE_EXT_PERIOD_MIN ||
					a->bat_life_ext_period > IEEE80215_BAT_LIFE_EXT_PERIOD_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR,
							"bat_life_ext_period is out of the range: %d\n",
							a->bat_life_ext_period );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.bat_life_ext_period = a->bat_life_ext_period;
			break;
		case IEEE80215_COORD_EXTENDED_ADDRESS:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: 64bit_coord: %llu\n",
						a->coord._64bit );
			mac->pib.coord._64bit = a->coord._64bit;
			break;
		case IEEE80215_COORD_SHORT_ADDRESS:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: 16bit_coord: %d\n",
						a->coord._16bit );
			mac->pib.coord._16bit = a->coord._16bit;
			break;
		case IEEE80215_MAX_CSMA_BACKOFF:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: csma_backoff: %d\n",
						a->max_csma_backoff );
			if ( a->max_csma_backoff > IEEE80215_MAX_CSMA_BACKOFF_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "max_csma_backoff "
							"is out of the range: %d\n",
							a->max_csma_backoff );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.max_csma_backoff = a->max_csma_backoff;
			break;
		case IEEE80215_MIN_BE:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: min_be: %d\n", a->min_be );
			if ( a->min_be > IEEE80215_MIN_BE_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "min_be is out of "
							"the range: %d\n",
							a->min_be );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.min_be = a->min_be;
			break;
		case IEEE80215_PANID:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: pan_id: %d\n",
						a->pan_id );
			mac->pib.dev_addr.panid = a->pan_id;
			break;
		case IEEE80215_RXON_WHEN_IDLE:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: rxon_when_idle: %s\n",
						a->rxon?"true":"false" );
			mac->pib.rxon = a->rxon;
			break;
		case IEEE80215_SHORT_ADDRESS:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: device 16bit: %d\n",
						a->_16bit );
			mac->pib.dev_addr._16bit = a->_16bit;
			break;
		case IEEE80215_ACL_ENTRY_DESCRIPTOR_SET:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: acl_enty: TBD\n" );
#warning "TODO: acl_entries"
			/*a->acl_entrys = &mac->pib.acl_entries;*/
			break;
		case IEEE80215_ACL_ENTRY_DESCRIPTOR_SET_SIZE:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: acl_entry desc size: %d\n",
						a->acl_entries->count );
			mac->pib.acl_entries.count = a->acl_entries->count;
			break;
		case IEEE80215_DEFAULT_SECURITY:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: default_sec: %s\n",
						a->def_sec?"true":"false" );
			mac->pib.def_sec = a->def_sec;
			break;
		case IEEE80215_DEFAULT_SECURITY_MLEN:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: def_sec_mlen: %d\n",
						a->def_sec_mlen );
			if ( a->def_sec_mlen > IEEE80215_DEFAULT_SECURITY_MLEN_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "def_sec_mlen is out "
							"of the range: %d\n",
							a->def_sec_mlen );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.def_sec_mlen = a->def_sec_mlen;
			break;
		case IEEE80215_DEFAULT_SECURITY_MATERIAL:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: def_sec_material\n" );
			if (mac->pib.def_sec_material) {
				kfree(mac->pib.def_sec_material);
			}
			mac->pib.def_sec_material = a->def_sec_material;
			if (!mac->pib.def_sec_material) {
				mac->pib.def_sec_mlen = 0;
				mac->pib.def_sec = false;
			}
			break;
		case IEEE80215_DEFAULT_SECURITY_SUITE:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: def_sec_suite: %d\n",
						a->def_sec_suite );
			mac->pib.def_sec_suite = a->def_sec_suite;
			break;
		case IEEE80215_SECURITY_MODE:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: sec_mode: %d\n",
						a->sec_mode );
			if ( a->sec_mode > IEEE80215_SECURITY_MODE_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "sec_mode is out of "
							"the range: %d\n",
							a->sec_mode );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.sec_mode = a->sec_mode;
			break;
#ifndef CONFIG_IEEE80215_RFD_NOOPT
		case IEEE80215_ASSOCIATION_PERMIT:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: association_permit: %s\n",
						a->association_permit?"true":"false" );
			mac->pib.association_permit = a->association_permit;
			break;
		case IEEE80215_BEACON_PAYLOAD:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: beacon_payload\n" );
			if (mac->pib.beacon_payload) {
				kfree(mac->pib.beacon_payload);
				mac->pib.beacon_payload = NULL;
			}
			if (!a->beacon_payload) {
				dbg_print(mac, 0, DBG_ERR, "beacon_payload is NULL\n" );
				/*
				mac->pib.beacon_payload_len = 0;
				break;
				*/
			}
#if 0
			mac->pib.beacon_payload = kmalloc ( mac->pib.beacon_payload_len,
					GFP_KERNEL );
			if ( !mac->pib.beacon_payload )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "Unable to alloc mem" );
				ret = IEEE80215_INVALID_PARAM;
				break;
			}
			memcpy ( mac->pib.beacon_payload,
					 a->beacon_payload,
					 mac->pib.beacon_payload_len );
#endif
			mac->pib.beacon_payload = a->beacon_payload;
			break;
		case IEEE80215_BEACON_PAYLOAD_LEN:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: beacon_payload_len: %d\n",
						a->beacon_payload_len );
			if ( !a->beacon_payload_len )
			{
				if ( mac->pib.beacon_payload )
				{
					kfree ( mac->pib.beacon_payload );
					mac->pib.beacon_payload = NULL;
				}
			}
			if ( a->beacon_payload_len >
					IEEE80215_BEACON_PAYLOAD_LEN_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "beacon_payload_len "
							"is out of the range: %d\n",
							a->beacon_payload_len );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.beacon_payload_len =
					a->beacon_payload_len;
			break;
		case IEEE80215_BEACON_ORDER:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: beacon_order: %d\n",
						a->beacon_order );
			if ( a->beacon_order > IEEE80215_BEACON_ORDER_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "beacon_order is out "
							"of the range: %d\n",
							a->beacon_order );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
				mac->pib.beacon_order = a->beacon_order;
			break;
		case IEEE80215_BEACON_TX_TIME:
			dbg_print(mac, SET_GET, DBG_ALL,
				"Set: beacon_tx_time: %lu\n",
				a->beacon_tx_time );
			if ( a->beacon_tx_time > IEEE80215_BEACON_TX_TIME_MAX ) {
				dbg_print(mac, SET_GET, DBG_ERR,
					"beacon_tx_time is out of the range: %lu\n",
					a->beacon_tx_time);
				ret = IEEE80215_INVALID_PARAM;
			} else {
				mac->pib.beacon_tx_time = a->beacon_tx_time;
			}
			break;
		case IEEE80215_BSN:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: fixme BSN: %d\n",
						a->bsn );
			mac->pib.bsn = a->bsn;
			break;
		case IEEE80215_GTS_PERMIT:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: gts_permit: %s\n",
						a->gts_permit?"true":"false" );
			mac->pib.gts_permit = a->bsn;
			break;
		case IEEE80215_PROMISCOUS_MODE:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: promiscuous_mode: %s\n",
						a->promiscuous_mode?"true":"false" );
			mac->pib.promiscuous_mode = a->promiscuous_mode;
			break;
		case IEEE80215_SUPERFRAME_ORDER:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: superframe_order: %d\n",
						a->superframe_order );
			if ( a->superframe_order >
					IEEE80215_SUPERFRAME_ORDER_MAX )
			{
				dbg_print(mac, SET_GET, DBG_ERR, "superframe_order "
							"is out of the range: %d\n",
							a->superframe_order );
				ret = IEEE80215_INVALID_PARAM;
			}
			else
			{
				mac->pib.superframe_order =
					a->superframe_order;
				ieee80215_set_superframe_params ( mac );
				if ( !mac->i.cap_len )
				{
					dbg_print(mac, SET_GET, DBG_ALL,
								"superframe_order is invalid, cap_len is wrong: %d\n",
								mac->pib.superframe_order );
					ret = IEEE80215_INVALID_PARAM;
				}
				else
					dbg_print(mac, SET_GET, DBG_ALL,
								"Set: pib:superframe_order: %d\n",
								mac->pib.superframe_order );
			}
			break;
		case IEEE80215_TRANSACTION_PERSISTENSE_TIME:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: tr_pers_time: %d\n",
						a->tr_pers_time );
			mac->pib.tr_pers_time = a->tr_pers_time;
			break;
#endif
		default:
			dbg_print(mac, SET_GET, DBG_ALL, "Set: unsupported attribute\n" );
			ret = IEEE80215_UNSUPPORTED_ATTRIBUTE;
			break;
	}
	write_unlock ( &mac->pib.lock );

	return ret;
}


/*
 * ieee80215_rxenable
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

int ieee80215_rxenable_end(struct ieee80215_mac *mac, int code)
{
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	dbg_print(mac, RXEN, DBG_INFO, "Finishing RXEN with code: %d\n", code);
	return 0;
}

void ieee80215_rxenable_finish(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of(work, ieee80215_mac_t,
					    rx_enable_request.work);

	dbg_print(mac, RXEN, DBG_INFO, "Finishing RXEN\n");
	cancel_delayed_work(&mac->gts_request);
	mac->plme_set_trx_state_confirm = ieee80215_rxenable_end;
	mac->phy->plme_set_trx_state_request(mac->phy, IEEE80215_TRX_OFF);
}


int ieee80215_rxenable_confirm_off(struct ieee80215_mac *mac, int code)
{
	if (code == IEEE80215_PHY_SUCCESS || code == IEEE80215_TRX_OFF) {
		dbg_print(mac, RXEN, DBG_INFO, "Receiver is off\n");
		code = IEEE80215_SUCCESS;
	} else {
		dbg_print(mac, RXEN, DBG_INFO, "Unable to turn off receiver\n");
	}
#warning FIXME indication/confurm !!!!!!!!!!!!!
#if 0
	return _nhle(mac)->mlme_rxen_confirm(_nhle(mac), code);
#endif
	return 0;
}

int ieee80215_rxenable_start(struct ieee80215_mac *mac, int code)
{
	if (code == IEEE80215_PHY_SUCCESS || code == IEEE80215_RX_ON) {
		dbg_print(mac, RXEN, DBG_INFO, "RXEN!\n");
		schedule_delayed_work(&mac->rx_enable_request,
				       usecs_to_jiffies(mac->i.rxon_duration*mac->symbol_duration));
	} else {
		dbg_print(mac, RXEN, DBG_INFO, "Unable to RX_ON: %d\n", code);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_rxen_confirm(_nhle(mac), IEEE80215_TX_ACTIVE);
#endif
	}
	return 0;
}

void ieee80215_rxenable_defer(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of(work, ieee80215_mac_t,
					    rx_enable_request.work);

	dbg_print(mac, RXEN, DBG_INFO, "Enabling RX\n");
	mac->plme_set_trx_state_confirm = ieee80215_rxenable_start;
	mac->phy->plme_set_trx_state_request(mac->phy, IEEE80215_RX_ON);
}

/* we fit in cap if rxon_time - aTurnaroundTime less that cap_len */
static inline int ieee80215_start_time_in_cap(ieee80215_mac_t *mac)
{
	if ((mac->i.rxon_time - IEEE80215_TURNAROUND_TIME) > mac->i.cap_len)
		return 0;
	return 1;
}

/* we fit in superframe if rxon_time - aTurnaroundTime less that pib.superframe_order */
static inline int ieee80215_start_time_in_sf(ieee80215_mac_t *mac)
{
	if ((mac->i.rxon_time - IEEE80215_TURNAROUND_TIME) >
		    mac->pib.superframe_order)
		return 0;
	return 1;
}

/**
 * @brief check the duration
 *
 * return 0 if ok, ret code if not.
 */
static inline int ieee80215_duration_is_ok(ieee80215_mac_t *mac)
{
	u32 final_rxon = mac->i.rxon_time+mac->i.rxon_duration;

	/* does rxon duration overlap next beacon tx time ? */
	if (final_rxon > mac->pib.beacon_order)
		return IEEE80215_INVALID_PARAM;
	/* does rxon duration overlap with cfp ? */
	if (final_rxon > mac->i.final_cap_slot)
		return IEEE80215_OUT_OF_CAP;
	return 0;
}

int ieee80215_mlme_rxen_req(ieee80215_mac_t *mac, bool def_permit, u32 time,
			    u32 duration)
{
	u8 ret;
	mac->i.rxon_time = time;
	mac->i.rxon_duration = duration;

	if (!duration) {
		/* Just disable receiver */
		mac->plme_set_trx_state_confirm = ieee80215_rxenable_confirm_off;
		mac->phy->plme_set_trx_state_request(mac->phy, IEEE80215_TRX_OFF);
		return 0;
	}


	mac->plme_set_trx_state_confirm = ieee80215_rxenable_start;
	if (mac->f.beacon_enabled_pan) {
		long unsigned int btx;
		u8 bo;

		/* Do we fit into superframe ? */
		ret = ieee80215_duration_is_ok(mac);
		if (ret) {
			dbg_print(mac, RXEN, DBG_INFO, "Invalid requested params\n");
#warning FIXME indication/confurm
#if 0
			return _nhle(mac)->mlme_rxen_confirm(_nhle(mac),
				     ret);
#endif
			return 0;
		}

		ieee80215_get_pib(mac, IEEE80215_BEACON_TX_TIME, (u8*)&btx);
		ieee80215_get_pib(mac, IEEE80215_BEACON_ORDER, (u8*)&bo);

		/* Are we in current superframe ? */
		if ((jiffies - btx) >
			   usecs_to_jiffies((time - IEEE80215_TURNAROUND_TIME)*mac->symbol_duration)) {
			/* We are not fit into superframe, check if we can defer */
			if (def_permit) {
				PREPARE_DELAYED_WORK(&mac->rx_enable_request,
						 ieee80215_rxenable_defer);

				schedule_delayed_work(&mac->rx_enable_request,
						usecs_to_jiffies((IEEE80215_BASE_SFD*
							(1<<bo))*mac->symbol_duration));
			} else {
				/* Inform NHLE */
#warning FIXME indication/confurm
#if 0
				_nhle(mac)->mlme_rxen_confirm(_nhle(mac), IEEE80215_OUT_OF_CAP);
#endif
				return 0;
			}
		} else {
			if ( !ieee80215_start_time_in_cap(mac)) {
				/* Out of CAP */
#warning FIXME indication/confurm
#if 0
				_nhle(mac)->mlme_rxen_confirm(_nhle(mac), IEEE80215_OUT_OF_CAP);
#endif
				return 0;
			}
		}
	} else {
		PREPARE_DELAYED_WORK(&mac->rx_enable_request, ieee80215_rxenable_finish);
	}
	mac->phy->plme_set_trx_state_request(mac->phy, IEEE80215_RX_ON);
	return 0;
}


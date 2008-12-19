/*
 * ieee80215_sync.c
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

#include <linux/timer.h>
#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/const.h>
#include <net/ieee80215/beacon.h>
#include <net/ieee80215/netdev.h>

static void sync_perform(ieee80215_mac_t *mac);

/* called before beacon, to enable rx */
static void ieee80215_sync_rxon(struct work_struct *work)
{
	ieee80215_mac_t *mac;
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
	mac = container_of(work, ieee80215_mac_t, sync_request.work);

	dbg_print(mac, SYNC, DBG_INFO, "Start of the SF, Tracking the beacon\n");
	ieee80215_net_set_trx_state(mac, IEEE80215_RX_ON, sync_perform);
}

static void sync_period_off(struct work_struct *work)
{
	u8 ret = 0;
	ieee80215_mac_t *mac;

	mac = container_of(work, ieee80215_mac_t, sync_request.work);

	dbg_print(mac, SYNC, DBG_INFO, "End of SF, Sync period off, beacon found: %s\n",
		 mac->f.find_a_beacon?"yes":"no");
	if (mac->f.track_beacon && !mac->f.find_a_beacon) {
		if (++mac->i.missed_beacons >= IEEE80215_MAX_LOST_BEACONS) {
			dbg_print(mac, SYNC, DBG_INFO, "Beacon loss: %d\n",
				 mac->i.missed_beacons);
			ret = IEEE80215_BEACON_LOSS;
		}
	}
	if (!mac->f.track_beacon && !mac->f.find_a_beacon) {
		dbg_print(mac, SYNC, DBG_INFO, "Beacon loss after first attempt\n");
		ret = IEEE80215_BEACON_LOSS;
	}

	if (ret == IEEE80215_BEACON_LOSS) {
		mac->f.sync_on = false;
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_sync_loss_indication(_nhle(mac), ret);
#endif
	} else {
		unsigned long int rxon_delta;
		if (mac->f.track_beacon) {
			dbg_print(mac, SYNC, DBG_INFO,
				  "Starting next iteration of sync\n");
			mac->f.find_a_beacon = false;
			PREPARE_DELAYED_WORK(&mac->sync_request, ieee80215_sync_rxon);
			rxon_delta = usecs_to_jiffies(IEEE80215_TURNAROUND_TIME*mac->symbol_duration);
			/* It is necessary to reserve some time for turning on receiver */
			dbg_print(mac, SYNC, DBG_ALL, "delta: %lu, wait_time: %lu, exp_time: %lu\n",
				rxon_delta, mac->totaltime-mac->sf_time-rxon_delta, jiffies+(mac->totaltime-mac->sf_time-rxon_delta));
			schedule_delayed_work(&mac->sync_request, mac->totaltime-mac->sf_time-rxon_delta);
		}
	}
	return;
}

void ieee80215_sync_check_beacon(ieee80215_mac_t *mac)
{
	if (mac->f.sync_on) {
		dbg_print(mac, SYNC, DBG_INFO, "sync_on\n");
		if (delayed_work_pending(&mac->sync_request))
			cancel_delayed_work(&mac->sync_request);

		if (!mac->f.track_beacon) {
			dbg_print(mac, SYNC, DBG_INFO, "Sync once\n");
			mac->f.sync_on = false;
		} else {
			long unsigned int next_beacon_time =
					usecs_to_jiffies((IEEE80215_BASE_SFD*
					(1<<mac->pib.beacon_order)) *
					mac->symbol_duration);
			/*FIXME: TODO calcullate time for turn on/off receiver to calc rxon_delta more
			 percise */
			long unsigned int rxon_delta = usecs_to_jiffies(IEEE80215_TURNAROUND_TIME*2*
					mac->symbol_duration);
			dbg_print(mac, SYNC, DBG_INFO,
				  "Tracking the next beacon after: %lu jiffies, delta: %lu\n",
					next_beacon_time-rxon_delta, rxon_delta);
			/* Rewind rx for the next beacon time */
			PREPARE_DELAYED_WORK(&mac->sync_request, ieee80215_sync_rxon);
			schedule_delayed_work(&mac->sync_request, next_beacon_time-rxon_delta);
		}
	} else {
		dbg_print(mac, SYNC, DBG_ALL, "sync_off\n");
	}
}

static void sync_perform(ieee80215_mac_t *mac)
{
	dbg_print(mac, SYNC, DBG_INFO,
		  "Prepare beacon search, wait for beacon in CAP time\n");
	ieee80215_set_beacon_interval(mac);
	PREPARE_DELAYED_WORK(&mac->sync_request, sync_period_off);
	if (mac->f.find_a_beacon)
		schedule_delayed_work(&mac->sync_request, mac->sf_time);
	else
		schedule_delayed_work(&mac->sync_request, mac->totaltime);
}

static int ieee80215_sync_start(ieee80215_mac_t *mac, int code, ieee80215_plme_pib_t *attr)
{
	if (code == IEEE80215_PHY_SUCCESS) {
		dbg_print(mac, SYNC, DBG_INFO, "set channel: done\n");
		mac->i.current_channel = attr->attr.curr_channel;
		ieee80215_net_set_trx_state(mac, IEEE80215_RX_ON, sync_perform);
	} else {
		dbg_print(mac, SYNC, DBG_ERR, "Unable to set channel\n");
		BUG();
	}
	return 0;
}

/*
 * Set channel on PHY, enable RX and wait for a beacon for a beacon_interval time.
 * On next iteration, enable RX only before beacon.
 */
int ieee80215_mlme_sync_req(ieee80215_mac_t *mac, u8 lch, bool tr_beacon)
{
	ieee80215_plme_pib_t attr;

	dbg_print(mac, SYNC, DBG_INFO, "channel = 0x%x, tr_beacon = %u\n",
		lch, tr_beacon);

	if (!ieee80215_slotted(mac)) {
		dbg_print(mac, SYNC, DBG_ERR, "Sync allowed only on beacon enabled pan\n");
		return -1;
	}

	if (lch > IEEE80215_PHY_CURRENT_CHANNEL_MAX) {
		dbg_print(mac, SYNC, DBG_ERR, "Wrong channel value\n");
		return -1;
	}
	mac->f.track_beacon = tr_beacon;
	if (mac->f.sync_on) {/* MAC is already in sync process, treat as a new request */
		dbg_print(mac, SYNC, DBG_ERR, "MLME.SYNC-request on already executing sync mac\n");
		mac->f.find_a_beacon = false;
		if (delayed_work_pending(&mac->sync_request))
			cancel_delayed_work(&mac->sync_request);
	}
	mac->f.sync_on = true;

	attr.attr_type = IEEE80215_PHY_CURRENT_CHANNEL;
	attr.attr.curr_channel = lch;
	mac->plme_set_confirm = ieee80215_sync_start;
	mac->phy->plme_set_request(mac->phy, attr);
	return 0;
}


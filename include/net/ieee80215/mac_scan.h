/*
 * ieee80215_mac_scan.h
 *
 * Description: MAC scan helper functions header
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

#ifndef IEEE80215_MAC_SCAN_H
#define IEEE80215_MAC_SCAN_H

#include <linux/random.h>	/* for get_random_int() */
#include <net/ieee80215/phy.h>
#include <net/ieee80215/lib.h>
#include <net/ieee80215/mac.h>

/**
 * @brief Get first unscanned channel number
 *
 * Return the index of first set bit in unscanned channels bit map array.
 *
 * @param scan current scan parameters
 */
static __inline__ int get_curr_channel(ieee80215_scan_t *scan)
{
	unsigned int idx;

	idx = find_first_bit((const unsigned long *)&scan->unscan_ch, 32);
	if (idx > 25)
		return -1;
	if (!test_bit(idx, (const unsigned long *)&scan->ch_list))
		return idx;
	return -1;
}

/**
 * @brief Mark current scan channel as scanned
 *
 * Set approptiate bit, corresponding for the channel in bit map array for
 * scanned channel list, and clear same bit in unscanned channels but map array.
 *
 * @param scan current scan parameters
 */
static __inline__ void mark_channel_scanned(ieee80215_scan_t *scan)
{
	set_bit(scan->current_channel, (unsigned long *)&scan->ch_list);
	clear_bit(scan->current_channel, (unsigned long *)&scan->unscan_ch);
}

ieee80215_pan_desc_t *
ieee80215_find_pan_desc(ieee80215_mac_t *mac, ieee80215_pan_desc_t *pdesc);
int ieee80215_add_pan_desc(ieee80215_mac_t *mac, ieee80215_pan_desc_t *pdesc);
int ieee80215_scan_data(struct ieee80215_mac *mac, ieee80215_mpdu_t *mpdu);
int ieee80215_ed_scan(struct ieee80215_mac *mac);
int ieee80215_active_scan(struct ieee80215_mac *mac);
int ieee80215_passive_scan(struct ieee80215_mac *mac);
int ieee80215_orphan_scan(struct ieee80215_mac *mac);

#endif /* IEEE80215_MAC_SCAN_H */

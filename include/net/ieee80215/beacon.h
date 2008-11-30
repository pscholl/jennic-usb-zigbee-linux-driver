/*
 * ieee80215_beacon.h
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

#ifndef IEEE80215_BEACON_H
#define IEEE80215_BEACON_H

#include <net/ieee80215/mac.h>
#include <net/ieee80215/lib.h>

void ieee80215_parse_beacon(ieee80215_mac_t *mac, struct sk_buff *skb);
int ieee80215_parse_coordinator_realignment(ieee80215_mac_t *mac, struct sk_buff *skb);
ieee80215_mpdu_t* ieee80215_create_beacon(ieee80215_mac_t *mac);
void ieee80215_superframe_end(struct work_struct *work);
void ieee80215_send_beacon(struct work_struct *work);
#endif /* IEEE80215_BEACON_H */

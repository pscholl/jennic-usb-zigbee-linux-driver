/*
 * MAC beacon hash storage
 *
 * Copyright 2007, 2008 Siemens AG
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
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#ifndef IEEE802154_BEACON_HASH_H
#define IEEE802154_BEACON_HASH_H

#define IEEE802154_BEACON_HTABLE_SIZE 256

struct beacon_node {
	struct hlist_node list;
	struct ieee802154_addr coord_addr;
	u16 pan_addr;
};
struct beacon_node *ieee802154_beacon_find_pan(
		struct ieee802154_addr *coord_addr,
		u16 pan_addr);
void ieee802154_beacon_hash_add(struct ieee802154_addr *coord_addr);
void ieee802154_beacon_hash_del(struct ieee802154_addr *coord_addr);
void ieee802154_beacon_hash_dump(void);
#endif


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

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include <net/ieee802154/af_ieee802154.h>

#include "beacon_hash.h"

static struct hlist_head beacon_hash[IEEE802154_BEACON_HTABLE_SIZE];
static DEFINE_RWLOCK(beacon_hash_lock);

static int beacon_hashfn(struct ieee802154_addr *coord_addr, u16 pan_addr)
{
	return pan_addr % IEEE802154_BEACON_HTABLE_SIZE;
}

static void __beacon_add_node(struct ieee802154_addr *coord_addr, u16 pan_addr)
{
	struct beacon_node *node =
		kzalloc(sizeof(struct beacon_node), GFP_KERNEL);
	struct hlist_head *list =
		&beacon_hash[beacon_hashfn(coord_addr, pan_addr)];
	memcpy(&node->coord_addr, coord_addr, sizeof(struct ieee802154_addr));
	node->pan_addr = pan_addr;
	INIT_HLIST_NODE(&node->list);
	hlist_add_head(&node->list, list);
}

struct beacon_node *ieee802154_beacon_find_pan(
		struct ieee802154_addr *coord_addr, u16 pan_addr)
{
	struct hlist_head *list;
	struct hlist_node *tmp;
	list = &beacon_hash[beacon_hashfn(coord_addr, pan_addr)];
	if (hlist_empty(list))
		return NULL;
	hlist_for_each(tmp, list) {
		struct beacon_node *entry =
			hlist_entry(tmp, struct beacon_node, list);
		if (entry->pan_addr == pan_addr)
			return entry;
	}
	return NULL;
}

void ieee802154_beacon_hash_add(struct ieee802154_addr *coord_addr)
{
	if (!ieee802154_beacon_find_pan(coord_addr, coord_addr->pan_id)) {
		write_lock(&beacon_hash_lock);
		__beacon_add_node(coord_addr, coord_addr->pan_id);
		write_unlock(&beacon_hash_lock);
	}
}

void ieee802154_beacon_hash_del(struct ieee802154_addr *coord_addr)
{
	struct beacon_node *entry = ieee802154_beacon_find_pan(coord_addr,
							coord_addr->pan_id);
	if (!entry)
		return;
	write_lock(&beacon_hash_lock);
	hlist_del(&entry->list);
	write_unlock(&beacon_hash_lock);
	kfree(entry);
}

void ieee802154_beacon_hash_dump(void)
{
	int i;
	struct hlist_node *tmp;
	pr_debug("beacon hash dump begin\n");
	read_lock(&beacon_hash_lock);
	for (i = 0; i < IEEE802154_BEACON_HTABLE_SIZE; i++) {
		struct beacon_node *entry;
		hlist_for_each(tmp, &beacon_hash[i]) {
			entry = hlist_entry(tmp, struct beacon_node, list);
			pr_debug("PAN: %04x\n", entry->pan_addr);
		}
	}
	read_unlock(&beacon_hash_lock);
	pr_debug("beacon hash dump end\n");
}


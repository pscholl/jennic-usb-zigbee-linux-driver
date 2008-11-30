/*
 * ieee80215_mac_tx.c
 *
 * Description: MAC TX helper functions.
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

#include <linux/list.h>
#include <net/ieee80215/debug.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/mac.h>

int ieee80215_tx_init_pool(ieee80215_t *mac)
{
	INIT_LIST_HEAD(&mac->tx_pool.tx.list);
	spin_lock_init(&mac->tx_pool.lock);
	mac->tx_pool.count = 0;
}

int ieee80215_tx_work(struct work_struct *work)
{
	ieee80215_tx_t *tx = container_of(work, ieee80215_t, work);
	ieee80215_t *mac = tx?tx->mac:NULL;

	if (!mac) {
		dbg_print("mac", DBG_ERR_CRIT, "Could not find current mac\n");
		return -1;
	}

	tx->retry++;
	if(tx->retry > IEEE80215_MAX_FRAME_RETRIES) {
		spin_lock(&mac->tx_pool.lock);
		del_list(&ret->list);
		mac->tx_pool.count--;
		spin_unlock(&mac->tx_pool.lock);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->data_confirm(_nhle(mac), tx->msdu_handle,
					IEEE80215_TRANSACTION_EXPIRED);
#endif
		ieee80215_tx_free(tx);
	} else {
		ieee80215_tx_start(mac, tx->frame);
	}
	return 0;
}

ieee80215_tx_t *ieee80215_tx_alloc(ieee80215_t *mac, bool ack,
					   bool trans,
					   ieee80215_gframe_t *frame)
{
	ieee80215_tx_t *tx;

	tx = kmalloc(sizeof(*tx), GFP_KERNEL);

	INIT_DELAYED_WORK(&tx->work, ieee80215_tx_work);
	tx->ack = ack;
	tx->is_trans = trans;
	tx->frame = frame;
	tx->retry = 0;
	tx->mac = mac;

	return tx;
}

void ieee80215_tx_free(ieee80215_tx_t *tx)
{
	cancel_delayed_work(&tx->work);
	ieee80215_free_frame(tx->frame);
	kfree(tx);
}

int ieee80215_add_tx(ieee80215_t *mac, bool ack, bool trans,
			 		ieee80215_gframe_t *frame)
{
	ieee80215_tx_t *tx;
	int ret = 0;

	tx = ieee80215_tx_alloc(mac, ack, trans, frame);

	spin_lock(&mac->tx_pool.lock);
	if (mac->tx_pool.count > IEEE80215_MAX_TX) {
		dbg_print(mac->name, DBG_ERR, "Maximum tx transaction exceeded\n");
		ret = -ENOMEM;
		goto ext_ptr;
	}
	list_add(&tx->list, &mac->tx_pool);
	mac->tx_pool.count++;
ext_ptr:
	spin_unlock(&mac->tx_pool.lock);
	return ret;
}

ieee80215_tx_t *ieee80215_tx_find(ieee80215_t *mac,
					  ieee80215_gframe *frame)
{
	struct list_head *tmp;
	ieee80215_tx_t *ret;

	list_for_each(tmp, &mac->tx_pool.tx) {
		ret = container_of(tmp, ieee80215_tx_t, list);
		if (ret->frame->addr->seq == frame->addr->seq) {
			spin_lock(&mac->tx_pool.lock);
			del_list(&ret->list);
			mac->tx_pool.count--;
			spin_unlock(&mac->tx_pool.lock);
			return ret;
		}
	}
	return NULL;
}

int ieee80215_tx_ack(ieee80215_t *mac, ieee80215_gframe *ack)
{
	ieee80215_tx *tx;

	tx = ieee80215_tx_find(mac, ack);
	if (!tx) {
		dbg_print(mac->name, DBG_ERR, "Tx not found\n");
		return -1;
	}
	ieee80215_tx_free(tx);
}


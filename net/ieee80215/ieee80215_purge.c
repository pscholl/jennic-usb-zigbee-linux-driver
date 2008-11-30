/*
 * ieee80215_purge.c
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

static void ieee80215_bg_mcps_purge_request(struct work_struct *work)
{
	ieee80215_mac_t *mac = container_of(work, ieee80215_mac_t, purge_request);
	struct sk_buff *skb;
#if 0
	int count, idx, ret = IEEE80215_INVALID_HANDLE;
	spin_lock(&mac->tr16.lock);
	skb = mac->tr16.next;
	count = skb_queue_len(&mac->tr16);
	for(idx = 0; idx < count; idx++) {
		/* TODO: fix it. handle is not unique. MAC must not use handle since it is NWK domain */
		if (skb_to_mpdu(skb)->nwk_handle == mac->cmd.len) {
			skb_unlink(skb, &mac->tr16);
			kfree_mpdu(skb_to_mpdu(skb));
			ret = IEEE80215_SUCCESS;
			break;
		}
	}
	spin_unlock(&mac->tr16.lock);
	spin_lock(&mac->tr64.lock);
	skb = mac->tr64.next;
	count = skb_queue_len(&mac->tr64);
	for(idx = 0; idx < count; idx++) {
		/* TODO: fix it. handle is not unique. MAC must not use handle since it is NWK domain */
		if (skb_to_mpdu(skb)->nwk_handle == mac->cmd.len) {
			skb_unlink(skb, &mac->tr64);
			kfree_mpdu(skb_to_mpdu(skb));
			ret = IEEE80215_SUCCESS;
			break;
		}
	}
	spin_unlock(&mac->tr64.lock);
#endif
	skb = (struct sk_buff *)mac->bg_data;
	skb_unlink(skb, &mac->tr16);
	skb_unlink(skb, &mac->tr64);

#warning FIXME indication/confurm
#if 0
	_nhle(mac)->mcps_purge_confirm(_nhle(mac), skb, IEEE80215_SUCCESS);
#endif
}

int ieee80215_mcps_purge_request(ieee80215_mac_t *mac, struct sk_buff *skb)
{
	mac->bg_data = skb;
	PREPARE_WORK(&mac->purge_request, ieee80215_bg_mcps_purge_request);
	queue_work(mac->worker, &mac->purge_request);
	return 0;
}


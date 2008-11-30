/*
 * ieee80215_lib.c
 *
 * Description: MAC helper functions
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

#include <linux/hardirq.h>
#include <linux/module.h>
#include <net/ieee80215/lib.h>

static struct kmem_cache *mpdu_head_cache __read_mostly;

ieee80215_mpdu_t *__alloc_mpdu(unsigned int size, gfp_t gfp_mask, int node)
{
	ieee80215_mpdu_t *mpdu;

	/* Get the HEAD */
	mpdu = kmem_cache_alloc_node(mpdu_head_cache, gfp_mask & ~__GFP_DMA, node);
	if (!mpdu)
		goto out;
	memset(mpdu, 0, sizeof(*mpdu));
	mpdu->use_csma_ca = 1;
out:
	return mpdu;
}
EXPORT_SYMBOL_GPL(__alloc_mpdu);

ieee80215_mpdu_t *mpdu_clone(ieee80215_mpdu_t *mpdu)
{
	size_t buf_len;
	ieee80215_mpdu_t *ret;
	u16 offset;
	struct sk_buff *skb;
	gfp_t prio = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	skb = skb_clone(mpdu_to_skb(mpdu), prio);
	if (!skb) {
		printk(KERN_ERR "%s(): Unable to alloc memory\n", __FUNCTION__);
		return NULL;
	}
	buf_len = (size_t)((char*)mpdu->skb->end - (char*)mpdu->skb->head);

	ret = alloc_mpdu(buf_len, GFP_KERNEL);
	if (!ret)
		return NULL;

	kfree_skb(ret->skb);
	ret->skb = skb;
	memcpy(skb->head, mpdu->skb->head, buf_len);
	ret->skb->len = mpdu->skb->len;
	ret->timestamp = mpdu->timestamp;
	ret->lq = mpdu->lq;
	ret->type = mpdu->type;
	ret->retries = mpdu->retries;
	ret->filtered = mpdu->filtered;
	ret->ack_send = mpdu->ack_send;
	ret->use_csma_ca = mpdu->use_csma_ca;
	ret->nwk_handle = mpdu->nwk_handle;
	ret->aps_handle = mpdu->aps_handle;
	ret->on_confirm = mpdu->on_confirm;

	if (mpdu->mhr) {
		offset = (char*)mpdu->mhr - (char*)mpdu->skb->head;
		ret->mhr = (ieee80215_mhr_t*)((char*)ret->skb->head + offset);
	}

	if (mpdu->d_panid) {
		offset = (char*)mpdu->d_panid - (char*)mpdu->skb->head;
		ret->d_panid = (u16*)((char*)ret->skb->head + offset);
	}

	if (mpdu->da) {
		offset = (char*)mpdu->da - (char*)mpdu->skb->head;
		ret->da = (ieee80215_addr_t*)((char*)ret->skb->head + offset);
	}

	if (mpdu->s_panid) {
		offset = (char*)mpdu->s_panid - (char*)mpdu->skb->head;
		ret->s_panid = (u16*)((char*)ret->skb->head + offset);
	}

	if (mpdu->sa) {
		offset = (char*)mpdu->sa - (char*)mpdu->skb->head;
		ret->sa = (ieee80215_addr_t*)((char*)ret->skb->head + offset);
	}

	if (mpdu->p.h) {
		offset = (char*)mpdu->p.h - (char*)mpdu->skb->head;
		ret->p.h = (zb_npdu_head_t*)((char*)ret->skb->head + offset);
	}

	if (mpdu->mfr) {
		offset = (char*)mpdu->mfr - (char*)mpdu->skb->head;
		ret->mfr = (ieee80215_mfr_t*)((char*)ret->skb->head + offset);
	}

	if (mpdu->skb->data) {
		offset = (char*)mpdu->skb->data - (char*)mpdu->skb->head;
		ret->skb->data = (u8*)((char*)ret->skb->head + offset);
	}

	if (mpdu->skb->end) {
		offset = (char*)mpdu->skb->end - (char*)mpdu->skb->head;
		ret->skb->end = (u8*)((char*)ret->skb->head + offset);
	}

	if (mpdu->skb->tail) {
		offset = (char*)mpdu->skb->tail - (char*)mpdu->skb->head;
		ret->skb->tail = (u8*)((char*)ret->skb->head + offset);
	}

	printk(KERN_INFO "%s(): original:\n", __FUNCTION__);
	__print_mpdu(mpdu);

	printk(KERN_INFO "%s(): cloned:\n", __FUNCTION__);
	__print_mpdu(ret);

	return ret;
}
EXPORT_SYMBOL(mpdu_clone);

void __kfree_mpdu(ieee80215_mpdu_t *mpdu)
{
	kmem_cache_free(mpdu_head_cache, mpdu);
}
EXPORT_SYMBOL_GPL(__kfree_mpdu);

static int __init ieee80215_lib_init(void)
{
	printk(KERN_INFO "%s()\n", __FUNCTION__);
	mpdu_head_cache = kmem_cache_create("mpdu_head_cache",
		sizeof(ieee80215_mpdu_t), 0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
	if (mpdu_head_cache)
		return 0;
	else
		return -ENOMEM;
}

static void __exit ieee80215_lib_exit(void)
{
	printk(KERN_INFO "%s()\n", __FUNCTION__);
	kmem_cache_destroy(mpdu_head_cache);
}

module_init(ieee80215_lib_init);
module_exit(ieee80215_lib_exit);

MODULE_LICENSE("GPL");


/*
 * Copyright (C) 2007, 2008, 2009 Siemens AG
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>

#include <net/ieee802154/mac802154.h>

#include "mac802154.h"

static void __ieee802154_rx_prepare(struct ieee802154_dev *dev,
		struct sk_buff *skb, u8 lqi)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);

	BUG_ON(!skb);

	phy_cb(skb)->lqi = lqi;

	skb->dev = priv->hw.netdev;

	skb->iif = skb->dev->ifindex;

	skb->protocol = htons(ETH_P_IEEE802154);

	skb_reset_mac_header(skb);
}

void ieee802154_rx(struct ieee802154_dev *dev, struct sk_buff *skb, u8 lqi)
{
	struct sk_buff *skb2;

	__ieee802154_rx_prepare(dev, skb, lqi);

	skb2 = skb_clone(skb, GFP_KERNEL);
	netif_rx(skb2);

	ieee802154_subif_rx(dev, skb);
}
EXPORT_SYMBOL(ieee802154_rx);

struct rx_work {
	struct sk_buff *skb;
	struct work_struct work;
	struct ieee802154_dev *dev;
};

static void ieee802154_rx_worker(struct work_struct *work)
{
	struct rx_work *rw = container_of(work, struct rx_work, work);
	struct sk_buff *skb = rw->skb;

	struct sk_buff *skb2 = skb_clone(skb, GFP_KERNEL);
	netif_rx(skb2);

	ieee802154_subif_rx(rw->dev, skb);
	kfree(rw);
}

void ieee802154_rx_irqsafe(struct ieee802154_dev *dev,
		struct sk_buff *skb, u8 lqi)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);
	struct rx_work *work = kzalloc(sizeof(struct rx_work), GFP_ATOMIC);

	if (!work)
		return;

	__ieee802154_rx_prepare(dev, skb, lqi);

	INIT_WORK(&work->work, ieee802154_rx_worker);
	work->skb = skb;
	work->dev = dev;

	queue_work(priv->dev_workqueue, &work->work);
}
EXPORT_SYMBOL(ieee802154_rx_irqsafe);

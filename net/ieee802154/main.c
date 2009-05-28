/*
 * ieee802154_phy.c
 *
 * Description: IEEE 802.15.4 PHY layer
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/workqueue.h>

#include <net/ieee802154/dev.h>
#include <net/ieee802154/netdev.h>
#include <net/ieee802154/nl.h>

struct ieee802154_dev *ieee802154_alloc_device(void)
{
	struct ieee802154_priv *priv = kzalloc(sizeof(struct ieee802154_priv), GFP_KERNEL);
	INIT_LIST_HEAD(&priv->slaves);
	spin_lock_init(&priv->slaves_lock);
	return &priv->hw;
}
EXPORT_SYMBOL(ieee802154_alloc_device);

void ieee802154_free_device(struct ieee802154_dev *hw)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(hw);

	BUG_ON(!list_empty(&priv->slaves));
	BUG_ON(priv->master);

	kfree(priv);
}
EXPORT_SYMBOL(ieee802154_free_device);

int ieee802154_register_device(struct ieee802154_dev *dev, struct ieee802154_ops *ops)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);
	int rc;

	if (!try_module_get(ops->owner))
		return -EFAULT;

	BUG_ON(!dev || !dev->name);
	BUG_ON(!ops || !ops->tx || !ops->cca || !ops->ed || !ops->set_trx_state);

	priv->ops = ops;
	rc = ieee802154_register_netdev_master(priv);
	if (rc < 0)
		goto out;
	priv->dev_workqueue = create_singlethread_workqueue(priv->master->name);
	if (!priv->dev_workqueue)
		goto out_wq;

	return 0;

out_wq:
	ieee802154_unregister_netdev_master(priv);
out:
	return rc;
}
EXPORT_SYMBOL(ieee802154_register_device);

void ieee802154_unregister_device(struct ieee802154_dev *dev)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);

	ieee802154_drop_slaves(dev);
	ieee802154_unregister_netdev_master(priv);
	flush_workqueue(priv->dev_workqueue);
	destroy_workqueue(priv->dev_workqueue);
	module_put(priv->ops->owner);
}
EXPORT_SYMBOL(ieee802154_unregister_device);

static void __ieee802154_rx_prepare(struct ieee802154_dev *dev, struct sk_buff *skb, u8 lqi)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);

	BUG_ON(!skb);

	PHY_CB(skb)->lqi = lqi;

	skb->dev = priv->master;

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

void ieee802154_rx_irqsafe(struct ieee802154_dev *dev, struct sk_buff *skb, u8 lqi)
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

MODULE_DESCRIPTION("IEEE 802.15.4 implementation");
MODULE_LICENSE("GPL v2");


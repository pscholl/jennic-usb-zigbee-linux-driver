/*
 * ieee80215_phy.c
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
#include <linux/rculist.h>

#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>

struct ieee80215_dev *ieee80215_alloc_device(void)
{
	struct ieee80215_priv *priv = kzalloc(sizeof(struct ieee80215_priv), GFP_KERNEL);
	INIT_LIST_HEAD(&priv->slaves);
	return &priv->hw;
}

void ieee80215_free_device(struct ieee80215_dev *hw)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(hw);

	BUG_ON(!list_empty(&priv->slaves));
	BUG_ON(priv->master);

	kfree(priv);
}

int ieee80215_register_device(struct ieee80215_dev *dev, struct ieee80215_ops *ops)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(dev);
	int rc;

	if (!dev || !dev->name)
	if (!ops || ops->tx || !ops->cca || !ops->ed || !ops->ed || !ops->set_trx_state)
		return -EINVAL;

	priv->ops = ops;
	rc = ieee80215_register_netdev_master(priv);

	return rc;
}

void ieee80215_unregister_device(struct ieee80215_dev *dev)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(dev);
	struct ieee80215_netdev_priv *ndp;
	list_for_each_entry_rcu(ndp, &priv->slaves, list)
		ieee80215_del_slave(&priv->hw, ndp);
	ieee80215_unregister_netdev_master(priv);
}

// FIXME: maybe move this:
void ieee80215_rx(struct ieee80215_dev *dev, struct sk_buff *skb)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(dev);

	BUG_ON(!skb);

	skb->dev = priv->master;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = htons(ETH_P_IEEE80215);

	netif_rx(skb);
}

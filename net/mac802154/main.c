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
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/route.h>

#include <net/af_ieee802154.h>
#include <net/mac802154.h>
#include <net/wpan-phy.h>

#include "mac802154.h"

struct ieee802154_dev *ieee802154_alloc_device(size_t priv_size,
		struct ieee802154_ops *ops)
{
	struct wpan_phy *phy;
	struct ieee802154_priv *priv;

	phy = wpan_phy_alloc(ALIGN(sizeof(*priv), NETDEV_ALIGN) + priv_size);
	if (!phy) {
		printk(KERN_ERR
			"Failure to initialize master IEEE802154 device\n");
		return NULL;
	}

	priv = wpan_phy_priv(phy);
	priv->hw.phy = priv->phy = phy;

	priv->hw.priv = (char *)priv + ALIGN(sizeof(*priv), NETDEV_ALIGN);

	BUG_ON(!ops);
	BUG_ON(!ops->xmit);
	BUG_ON(!ops->ed);
	BUG_ON(!ops->start);
	BUG_ON(!ops->stop);

	priv->ops = ops;

	INIT_LIST_HEAD(&priv->slaves);
	mutex_init(&priv->slaves_mtx);

	return &priv->hw;
}
EXPORT_SYMBOL(ieee802154_alloc_device);

void ieee802154_free_device(struct ieee802154_dev *hw)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(hw);

	BUG_ON(!list_empty(&priv->slaves));

	wpan_phy_free(priv->phy);
}
EXPORT_SYMBOL(ieee802154_free_device);

int ieee802154_register_device(struct ieee802154_dev *dev)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);
	int rc;

	priv->dev_workqueue =
		create_singlethread_workqueue(wpan_phy_name(priv->phy));
	if (!priv->dev_workqueue) {
		rc = -ENOMEM;
		goto out;
	}

	rc = wpan_phy_register(priv->hw.parent, priv->phy);
	if (rc < 0)
		goto out_wq;

	return 0;

out_wq:
	destroy_workqueue(priv->dev_workqueue);
out:
	return rc;
}
EXPORT_SYMBOL(ieee802154_register_device);

void ieee802154_unregister_device(struct ieee802154_dev *dev)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);

	flush_workqueue(priv->dev_workqueue);
	destroy_workqueue(priv->dev_workqueue);

	rtnl_lock();

	ieee802154_drop_slaves(dev);

	rtnl_unlock();

	wpan_phy_unregister(priv->phy);
}
EXPORT_SYMBOL(ieee802154_unregister_device);

MODULE_DESCRIPTION("IEEE 802.15.4 implementation");
MODULE_LICENSE("GPL v2");


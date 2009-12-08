/*
 * Copyright 2007, 2008, 2009 Siemens AG
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Sergey Lapin <slapin@ossfans.org>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 */

#include <linux/if_arp.h>

#include <net/mac802154.h>
#include <net/wpan-phy.h>

#include "mac802154.h"
#include "mib.h"

struct phy_chan_notify_work {
	struct work_struct work;
	struct net_device *dev;
};

static void phy_chan_notify(struct work_struct *work)
{
	struct phy_chan_notify_work *nw = container_of(work,
			struct phy_chan_notify_work, work);
	struct ieee802154_priv *hw = ieee802154_slave_get_priv(nw->dev);
	struct ieee802154_sub_if_data *priv = netdev_priv(nw->dev);
	int res;

	res = hw->ops->set_channel(&hw->hw, priv->chan);
	if (res)
		pr_debug("set_channel failed\n");

	kfree(nw);

	return;
}

u16 ieee802154_dev_get_pan_id(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	ret = priv->pan_id;
	spin_unlock_bh(&priv->mib_lock);

	return ret;
}

u16 ieee802154_dev_get_short_addr(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	ret = priv->short_addr;
	spin_unlock_bh(&priv->mib_lock);

	return ret;
}

void ieee802154_dev_set_pan_id(struct net_device *dev, u16 val)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	priv->pan_id = val;
	spin_unlock_bh(&priv->mib_lock);
}

void ieee802154_dev_set_short_addr(struct net_device *dev, u16 val)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	priv->short_addr = val;
	spin_unlock_bh(&priv->mib_lock);
}

void ieee802154_dev_set_channel(struct net_device *dev, u8 val)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	struct phy_chan_notify_work *work;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	priv->chan = val;
	spin_unlock_bh(&priv->mib_lock);

	if (priv->hw->phy->current_channel != priv->chan) {
		work = kzalloc(sizeof(*work), GFP_ATOMIC);
		if (!work)
			return;

		INIT_WORK(&work->work, phy_chan_notify);
		work->dev = dev;
		queue_work(priv->hw->dev_workqueue, &work->work);
	}
}

void ieee802154_dev_set_page(struct net_device *dev, u8 page)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	priv->page = page;
	spin_unlock_bh(&priv->mib_lock);
}

u8 ieee802154_dev_get_dsn(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	ret = priv->dsn++;
	spin_unlock_bh(&priv->mib_lock);

	return ret;
}

u8 ieee802154_dev_get_bsn(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	spin_lock_bh(&priv->mib_lock);
	ret = priv->bsn++;
	spin_unlock_bh(&priv->mib_lock);

	return ret;
}

struct ieee802154_priv *ieee802154_slave_get_priv(struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	BUG_ON(dev->type != ARPHRD_IEEE802154);

	return priv->hw;
}

struct wpan_phy *ieee802154_get_phy(const struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	BUG_ON(dev->type != ARPHRD_IEEE802154);

	return to_phy(get_device(&priv->hw->phy->dev));
}

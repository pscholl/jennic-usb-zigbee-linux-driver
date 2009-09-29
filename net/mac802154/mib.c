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
 * Sergey Lapin <slapin@ossfans.org>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 */

#include <linux/if_arp.h>

#include <net/mac802154.h>

#include "mac802154.h"

u16 ieee802154_dev_get_pan_id(struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	read_lock_bh(&priv->mib_lock);
	ret = priv->pan_id;
	read_unlock_bh(&priv->mib_lock);

	return ret;
}

u16 ieee802154_dev_get_short_addr(struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	read_lock_bh(&priv->mib_lock);
	ret = priv->short_addr;
	read_unlock_bh(&priv->mib_lock);

	return ret;
}

void ieee802154_dev_set_pan_id(struct net_device *dev, u16 val)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	write_lock_bh(&priv->mib_lock);
	priv->pan_id = val;
	write_unlock_bh(&priv->mib_lock);
}
void ieee802154_dev_set_short_addr(struct net_device *dev, u16 val)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	write_lock_bh(&priv->mib_lock);
	priv->short_addr = val;
	write_unlock_bh(&priv->mib_lock);
}
void ieee802154_dev_set_channel(struct net_device *dev, u8 val)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	write_lock_bh(&priv->mib_lock);
	priv->chan = val;
	write_unlock_bh(&priv->mib_lock);
}

void ieee802154_dev_set_page(struct net_device *dev, u8 page)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	write_lock_bh(&priv->mib_lock);
	priv->page = page;
	write_unlock_bh(&priv->mib_lock);
}

u8 ieee802154_dev_get_dsn(struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	write_lock_bh(&priv->mib_lock);
	ret = priv->dsn++;
	write_unlock_bh(&priv->mib_lock);

	return ret;
}

u8 ieee802154_dev_get_bsn(struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	u16 ret;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	write_lock_bh(&priv->mib_lock);
	ret = priv->bsn++;
	write_unlock_bh(&priv->mib_lock);

	return ret;
}

struct ieee802154_priv *ieee802154_slave_get_priv(struct net_device *dev)
{
	struct ieee802154_sub_if_data *priv = netdev_priv(dev);
	BUG_ON(dev->type != ARPHRD_IEEE802154);

	return priv->hw;
}


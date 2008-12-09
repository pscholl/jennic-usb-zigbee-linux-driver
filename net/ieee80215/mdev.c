/*
 * Interface from IEEE80215.4 MAC layer to the userspace, net_device part.
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
 */

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/etherdevice.h>
#include <linux/list.h>

#include <net/ieee80215/phy.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/ieee80215.h>

static int ieee80215_master_open(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv;
	struct ieee80215_netdev_priv *subif;
	int res = -EOPNOTSUPP;
	priv = netdev_priv(dev);
	list_for_each_entry(subif, &priv->interfaces, list) {
		if(netif_running(subif->dev)) {
			res = 0;
			break;
		}
	}
	netif_start_queue(dev);
	return 0;
}

static int ieee80215_master_close(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv;
	struct ieee80215_netdev_priv *subif;
	netif_stop_queue(dev);
	priv = netdev_priv(dev);
	list_for_each_entry(subif, &priv->interfaces, list) {
		if(netif_running(subif->dev))
			dev_close(subif->dev);
	}
	return 0;
}

static void ieee80215_netdev_setup_master(struct net_device *dev)
{
	dev->addr_len		= IEEE80215_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE80215_ADDR_LEN);
	dev->features		= NETIF_F_NO_CSUM;
	dev->hard_header_len	= 0;
	dev->mtu		= 137; /* TODO: check if it is the right value for MAC layer */
	dev->tx_queue_len	= 10;
	dev->type		= ARPHRD_IEEE80215;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;
}

int ieee80215_register_netdev_master(struct ieee80215_phy * phy, struct ieee80215_dev_ops *dev_ops)
{
	struct net_device *dev;
	struct ieee80215_mnetdev_priv *priv;

	dev = alloc_netdev(sizeof(struct ieee80215_mnetdev_priv),
			"mwpan%d", ieee80215_netdev_setup_master);
	if(!dev) {
		printk(KERN_ERR "Failure to initialize master IEEE80215 device\n");
		return -ENOMEM;
	}
	priv = netdev_priv(dev);
	INIT_LIST_HEAD(&priv->interfaces);
	priv->dev = dev;
	priv->dev_ops = dev_ops;
	dev->open = ieee80215_master_open;
	dev->stop = ieee80215_master_close;
	register_netdev(dev);
	phy->dev = dev;
	if(dev_ops->flags && IEEE80215_DEV_SINGLE)
		ieee80215_register_netdev(dev_ops, dev);
	return 0;
}
EXPORT_SYMBOL(ieee80215_register_netdev_master);

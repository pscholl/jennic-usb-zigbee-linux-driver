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

static int ieee80215_master_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv = netdev_priv(dev);
	phy_status_t res;

	if (skb_cow_head(skb, priv->hw->hw.extra_tx_headroom)) {
		dev_kfree_skb(skb);
		return 1;
	}

	res = priv->hw->ops->tx(&priv->hw->hw, skb);
	if (res == PHY_SUCCESS) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	} else
		return NETDEV_TX_BUSY;
}

static int ieee80215_master_open(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv;
	struct ieee80215_netdev_priv *subif;
	int res = -EOPNOTSUPP;
	priv = netdev_priv(dev);
	if(!priv) {
		pr_debug("%s:%s: unable to get master private data\n",
				__FILE__, __FUNCTION__);
		return -ENODEV;
	}
	pr_debug("%s:%s &priv->interfaces->next = %p\n", __FILE__,
				__FUNCTION__, &priv->interfaces.next);
	pr_debug("%s:%s &priv->interfaces->prev = %p\n", __FILE__,
				__FUNCTION__, &priv->interfaces.prev);
	list_for_each_entry(subif, &priv->interfaces, list) {
		if(netif_running(subif->dev)) {
			/* Doing nothing important for now */
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
static struct net_device_stats *ieee80215_get_master_stats(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

static void ieee80215_netdev_setup_master(struct net_device *dev)
{
	dev->addr_len		= 0;
	memset(dev->broadcast, 0xff, IEEE80215_ADDR_LEN);
	dev->features		= NETIF_F_NO_CSUM;
	dev->hard_header_len	= 0;
	dev->mtu		= 127;
	dev->tx_queue_len	= 10;
	dev->type		= ARPHRD_IEEE80215;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;
}

int ieee80215_register_netdev_master(struct ieee80215_priv *hw)
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
	priv->hw = hw;
	hw->master = dev;
	dev->open = ieee80215_master_open;
	dev->stop = ieee80215_master_close;
	dev->hard_start_xmit = ieee80215_master_hard_start_xmit;
	dev->get_stats = ieee80215_get_master_stats;
	register_netdev(dev);
	return 0;
}

void ieee80215_unregister_netdev_master(struct ieee80215_priv *hw)
{
	struct net_device *dev = hw->master;
	BUG_ON(!hw->master);

	unregister_netdev(hw->master);
	hw->master = NULL;
	free_netdev(dev);
}

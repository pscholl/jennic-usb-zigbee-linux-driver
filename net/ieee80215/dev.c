/* 
 * ZigBee socket interface
 *
 * Copyright 2007, 2008 Siemens AG
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
 * Sergey Lapin <sergey.lapin@siemens.com>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 */

#include <linux/net.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/termios.h>	/* For TIOCOUTQ/INQ */
#include <net/datalink.h>
#include <net/psnap.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/route.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>

static int ieee80215_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	skb->iif = dev->ifindex;
	skb->dev = dev->master;
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	dev->trans_start = jiffies;
	dev_queue_xmit(skb);

	return 0;
}

static int ieee80215_slave_open(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *mdev;
	struct ieee80215_netdev_priv *priv;
	int res = -EOPNOTSUPP;
	priv = netdev_priv(dev);
	netif_start_queue(dev);
	return 0;
}

static int ieee80215_slave_close(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *mdev;
	struct ieee80215_netdev_priv *priv;
	netif_stop_queue(dev);
	priv = netdev_priv(dev);
	netif_stop_queue(dev);
	return 0;
}

static struct net_device_stats *ieee80215_get_stats(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

static void ieee80215_netdev_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE80215_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE80215_ADDR_LEN);
	dev->features		= NETIF_F_NO_CSUM;
	dev->hard_header_len	= 0;
	dev->mtu		= 127;
	dev->tx_queue_len	= 10;
	dev->type		= ARPHRD_IEEE80215;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;
}

int ieee80215_add_slave(struct ieee80215_dev *hw, const u8 *addr)
{
	struct net_device *dev;
	struct ieee80215_netdev_priv *priv;
	struct ieee80215_mnetdev_priv *mpriv;

	dev = alloc_netdev(sizeof(struct ieee80215_netdev_priv),
			"wpan%d", ieee80215_netdev_setup);
	if(!dev) {
		printk(KERN_ERR "Failure to initialize IEEE80215 device\n");
		return -ENOMEM;
	}
	priv = netdev_priv(dev);
	priv->dev = dev;
	memcpy(dev->dev_addr, addr, dev->addr_len);
	memcpy(dev->perm_addr, dev->dev_addr, dev->addr_len);
	dev->open = ieee80215_slave_open;
	dev->stop = ieee80215_slave_close;
	dev->hard_start_xmit = ieee80215_net_xmit;
	dev->get_stats = ieee80215_get_stats;
	dev_hold(ieee80215_to_priv(hw)->master);
	dev->master = ieee80215_to_priv(hw)->master;
	mpriv = netdev_priv(ieee80215_to_priv(hw)->master);
	list_add_tail_rcu(&priv->list, &mpriv->interfaces);
	register_netdev(dev);
	return dev->ifindex;
}

void ieee80215_del_slave(struct ieee80215_dev *hw, struct ieee80215_netdev_priv *ndp)
{
	struct net_device *dev = ndp->dev;
	dev_put(ieee80215_to_priv(hw)->master);
	unregister_netdevice(ndp->dev);
	list_del_rcu(&ndp->list);
	free_netdev(dev);
}

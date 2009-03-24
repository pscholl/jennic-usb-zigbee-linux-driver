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

#include <net/ieee80215/phy.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>

struct ieee80215_mnetdev_priv {
	struct ieee80215_priv *hw;
	struct net_device *dev;
	struct net_device_stats stats;
};

struct xmit_work {
	struct sk_buff *skb;
	struct work_struct work;
	struct ieee80215_mnetdev_priv *priv;
};

static void ieee80215_xmit_worker(struct work_struct *work)
{
	struct xmit_work *xw = container_of(work, struct xmit_work, work);
	phy_status_t res;

	if (xw->priv->hw->hw.current_channel != PHY_CB(xw->skb)->chan) {
		res = xw->priv->hw->ops->set_channel(&xw->priv->hw->hw, PHY_CB(xw->skb)->chan);
		if (res != PHY_SUCCESS) {
			pr_debug("set_channel failed\n");
			goto out;
		}
	}

	res = xw->priv->hw->ops->cca(&xw->priv->hw->hw);
	if (res != PHY_IDLE) {
		pr_debug("CCA failed\n");
		goto out;
	}

	res = xw->priv->hw->ops->set_trx_state(&xw->priv->hw->hw, PHY_TX_ON);
	if (res != PHY_SUCCESS && res != PHY_TX_ON) {
		pr_debug("set_trx_state returned %d\n", res);
		goto out;
	}

	res = xw->priv->hw->ops->tx(&xw->priv->hw->hw, xw->skb);

out:
	// FIXME: result processing and/or requeue!!!
	dev_kfree_skb(xw->skb);

	xw->priv->hw->ops->set_trx_state(&xw->priv->hw->hw, PHY_RX_ON);
	kfree(xw);
}

static int ieee80215_master_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv = netdev_priv(dev);
	struct xmit_work *work;

	if (skb_cow_head(skb, priv->hw->hw.extra_tx_headroom)) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	work = kzalloc(sizeof(struct xmit_work), GFP_ATOMIC);
	if (!work)
		return NETDEV_TX_BUSY;

	INIT_WORK(&work->work, ieee80215_xmit_worker);
	work->skb = skb;
	work->priv = priv;

	queue_work(priv->hw->dev_workqueue, &work->work);

	return NETDEV_TX_OK;
}

static int ieee80215_master_open(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv;
	phy_status_t status;
	priv = netdev_priv(dev);
	if (!priv) {
		pr_debug("%s:%s: unable to get master private data\n",
				__FILE__, __func__);
		return -ENODEV;
	}
	status = priv->hw->ops->set_trx_state(&priv->hw->hw, PHY_RX_ON);
	if (status != PHY_SUCCESS) {
		pr_debug("set_trx_state returned %d\n", status);
		return -EBUSY;
	}

	netif_start_queue(dev);
	return 0;
}

static int ieee80215_master_close(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv;
	netif_stop_queue(dev);
	priv = netdev_priv(dev);

	priv->hw->ops->set_trx_state(&priv->hw->hw, PHY_FORCE_TRX_OFF);
	return 0;
}
static struct net_device_stats *ieee80215_get_master_stats(struct net_device *dev)
{
	struct ieee80215_mnetdev_priv *priv = netdev_priv(dev);
	return &priv->stats;
}
static int ieee80215_master_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ieee80215_mnetdev_priv *priv = netdev_priv(dev);
	switch (cmd) {
	case IEEE80215_SIOC_ADD_SLAVE:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return ieee80215_add_slave(&priv->hw->hw, (u8 *) &ifr->ifr_hwaddr.sa_data);
	}
	return -ENOIOCTLCMD;
}

static void ieee80215_netdev_setup_master(struct net_device *dev)
{
	dev->addr_len		= 0;
	memset(dev->broadcast, 0xff, dev->addr_len);
	dev->features		= NETIF_F_NO_CSUM;
	dev->hard_header_len	= 0;
	dev->mtu		= 127;
	dev->tx_queue_len	= 0;
	dev->type		= ARPHRD_IEEE80215_PHY;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;
}

int ieee80215_register_netdev_master(struct ieee80215_priv *hw)
{
	struct net_device *dev;
	struct ieee80215_mnetdev_priv *priv;

	dev = alloc_netdev(sizeof(struct ieee80215_mnetdev_priv),
			"mwpan%d", ieee80215_netdev_setup_master);
	if (!dev) {
		printk(KERN_ERR "Failure to initialize master IEEE80215 device\n");
		return -ENOMEM;
	}
	priv = netdev_priv(dev);
	priv->dev = dev;
	priv->hw = hw;
	hw->master = dev;
	dev->open = ieee80215_master_open;
	dev->stop = ieee80215_master_close;
	dev->hard_start_xmit = ieee80215_master_hard_start_xmit;
	dev->needed_headroom = hw->hw.extra_tx_headroom;
	dev->get_stats = ieee80215_get_master_stats;
	dev->do_ioctl = ieee80215_master_ioctl;
	SET_NETDEV_DEV(dev, hw->hw.parent);
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

/*
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

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>

#include <net/ieee802154/af_ieee802154.h>
#include <net/ieee802154/mac802154.h>

#include "mac802154.h"

struct xmit_work {
	struct sk_buff *skb;
	struct work_struct work;
	struct ieee802154_priv *priv;
};

static void ieee802154_xmit_worker(struct work_struct *work)
{
	struct xmit_work *xw = container_of(work, struct xmit_work, work);
	phy_status_t res;

	if (xw->priv->hw.current_channel != phy_cb(xw->skb)->chan) {
		res = xw->priv->ops->set_channel(&xw->priv->hw,
				phy_cb(xw->skb)->chan);
		if (res != PHY_SUCCESS) {
			pr_debug("set_channel failed\n");
			goto out;
		}
	}

	res = xw->priv->ops->cca(&xw->priv->hw);
	if (res != PHY_IDLE) {
		pr_debug("CCA failed\n");
		goto out;
	}

	res = xw->priv->ops->set_trx_state(&xw->priv->hw, PHY_TX_ON);
	if (res != PHY_SUCCESS && res != PHY_TX_ON) {
		pr_debug("set_trx_state returned %d\n", res);
		goto out;
	}

	res = xw->priv->ops->tx(&xw->priv->hw, xw->skb);

out:
	/* FIXME: result processing and/or requeue!!! */
	dev_kfree_skb(xw->skb);

	xw->priv->ops->set_trx_state(&xw->priv->hw, PHY_RX_ON);
	kfree(xw);
}

static int ieee802154_master_hard_start_xmit(struct sk_buff *skb,
		struct net_device *dev)
{
	struct ieee802154_priv *priv = netdev_priv(dev);
	struct xmit_work *work;

	if (skb_cow_head(skb, priv->hw.extra_tx_headroom)) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	work = kzalloc(sizeof(struct xmit_work), GFP_ATOMIC);
	if (!work)
		return NETDEV_TX_BUSY;

	INIT_WORK(&work->work, ieee802154_xmit_worker);
	work->skb = skb;
	work->priv = priv;

	queue_work(priv->dev_workqueue, &work->work);

	return NETDEV_TX_OK;
}

static int ieee802154_master_open(struct net_device *dev)
{
	struct ieee802154_priv *priv;
	phy_status_t status;
	priv = netdev_priv(dev);
	if (!priv) {
		pr_debug("%s:%s: unable to get master private data\n",
				__FILE__, __func__);
		return -ENODEV;
	}
	status = priv->ops->set_trx_state(&priv->hw, PHY_RX_ON);
	if (status != PHY_SUCCESS) {
		pr_debug("set_trx_state returned %d\n", status);
		return -EBUSY;
	}

	netif_start_queue(dev);
	return 0;
}

static int ieee802154_master_close(struct net_device *dev)
{
	struct ieee802154_priv *priv;
	netif_stop_queue(dev);
	priv = netdev_priv(dev);

	priv->ops->set_trx_state(&priv->hw, PHY_FORCE_TRX_OFF);
	return 0;
}
static int ieee802154_master_ioctl(struct net_device *dev, struct ifreq *ifr,
		int cmd)
{
	struct ieee802154_priv *priv = netdev_priv(dev);
	switch (cmd) {
	case IEEE802154_SIOC_ADD_SLAVE:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		return ieee802154_add_slave(&priv->hw,
				(u8 *) &ifr->ifr_hwaddr.sa_data);
	}
	return -ENOIOCTLCMD;
}

static void ieee802154_netdev_setup_master(struct net_device *dev)
{
	dev->addr_len		= 0;
	dev->features		= NETIF_F_NO_CSUM;
	dev->hard_header_len	= 0;
	dev->mtu		= 127;
	dev->tx_queue_len	= 0;
	dev->type		= ARPHRD_IEEE802154_PHY;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;
}
static ssize_t ieee802154_netdev_show(const struct device *dev,
		   struct device_attribute *attr, char *buf,
		   ssize_t (*format)(const struct net_device *, char *))
{
	struct net_device *netdev = to_net_dev(dev);
	ssize_t ret = -EINVAL;

	if (netdev->reg_state <= NETREG_REGISTERED)
		ret = (*format)(netdev, buf);

	return ret;
}
#define MASTER_SHOW(field, format_string)				\
static ssize_t format_##field(const struct net_device *dev, char *buf)	\
{									\
	struct ieee802154_priv *priv = netdev_priv(dev);		\
	return sprintf(buf, format_string, priv->hw.field);		\
}									\
static ssize_t show_##field(struct device *dev,				\
			    struct device_attribute *attr, char *buf)	\
{									\
	return ieee802154_netdev_show(dev, attr, buf, format_##field);	\
}									\
static DEVICE_ATTR(field, S_IRUGO, show_##field, NULL)

static const char fmt_long_hex[] = "%#lx\n";
static const char fmt_hex[] = "%#x\n";
static const char fmt_dec[] = "%d\n";

MASTER_SHOW(current_channel, fmt_dec);
MASTER_SHOW(channel_mask, fmt_hex);

static struct attribute *pmib_attrs[] = {
	&dev_attr_current_channel.attr,
	&dev_attr_channel_mask.attr,
	NULL
};

static struct attribute_group pmib_group = {
	.name  = "pib",
	.attrs  = pmib_attrs,
};

static const struct net_device_ops ieee802154_master_ops = {
	.ndo_open		= ieee802154_master_open,
	.ndo_stop		= ieee802154_master_close,
	.ndo_start_xmit		= ieee802154_master_hard_start_xmit,
	.ndo_do_ioctl		= ieee802154_master_ioctl,
};

static int ieee802154_register_netdev_master(struct ieee802154_priv *priv)
{
	struct net_device *dev = priv->hw.netdev;

	dev->netdev_ops = &ieee802154_master_ops;
	dev->needed_headroom = priv->hw.extra_tx_headroom;
	SET_NETDEV_DEV(dev, priv->hw.parent);

	dev->sysfs_groups[1] = &pmib_group;

	register_netdev(dev);

	return 0;
}

struct ieee802154_dev *ieee802154_alloc_device(void)
{
	struct net_device *dev;
	struct ieee802154_priv *priv;

	dev = alloc_netdev(sizeof(struct ieee802154_priv),
			"mwpan%d", ieee802154_netdev_setup_master);
	if (!dev) {
		printk(KERN_ERR
			"Failure to initialize master IEEE802154 device\n");
		return NULL;
	}
	priv = netdev_priv(dev);
	priv->hw.netdev = dev;

	INIT_LIST_HEAD(&priv->slaves);
	spin_lock_init(&priv->slaves_lock);
	return &priv->hw;
}
EXPORT_SYMBOL(ieee802154_alloc_device);

void ieee802154_free_device(struct ieee802154_dev *hw)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(hw);

	BUG_ON(!list_empty(&priv->slaves));
	BUG_ON(!priv->hw.netdev);

	free_netdev(priv->hw.netdev);
}
EXPORT_SYMBOL(ieee802154_free_device);

int ieee802154_register_device(struct ieee802154_dev *dev,
		struct ieee802154_ops *ops)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);
	int rc;

	if (!try_module_get(ops->owner))
		return -EFAULT;

	BUG_ON(!dev || !dev->name);
	BUG_ON(!ops || !ops->tx || !ops->cca || !ops->ed ||
			!ops->set_trx_state);

	priv->ops = ops;
	rc = ieee802154_register_netdev_master(priv);
	if (rc < 0)
		goto out;
	priv->dev_workqueue =
		create_singlethread_workqueue(priv->hw.netdev->name);
	if (!priv->dev_workqueue)
		goto out_wq;

	return 0;

out_wq:
	unregister_netdev(priv->hw.netdev);
out:
	return rc;
}
EXPORT_SYMBOL(ieee802154_register_device);

void ieee802154_unregister_device(struct ieee802154_dev *dev)
{
	struct ieee802154_priv *priv = ieee802154_to_priv(dev);

	ieee802154_drop_slaves(dev);
	unregister_netdev(priv->hw.netdev);
	flush_workqueue(priv->dev_workqueue);
	destroy_workqueue(priv->dev_workqueue);
	module_put(priv->ops->owner);
}
EXPORT_SYMBOL(ieee802154_unregister_device);

MODULE_DESCRIPTION("IEEE 802.15.4 implementation");
MODULE_LICENSE("GPL v2");


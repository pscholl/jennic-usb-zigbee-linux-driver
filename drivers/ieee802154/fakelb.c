/*
 * Loopback IEEE 802.15.4 interface
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
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <net/mac802154.h>
#include <net/wpan-phy.h>

struct fake_dev_priv {
	struct ieee802154_dev *dev;

	struct list_head list;
	struct fake_priv *fake;

	unsigned int working:1;
};

struct fake_priv {
	struct list_head list;
	rwlock_t lock;
};

static int
hw_ed(struct ieee802154_dev *dev, u8 *level)
{
	pr_debug("%s\n", __func__);
	might_sleep();
	BUG_ON(!level);
	*level = 0xbe;
	return 0;
}

static int
hw_channel(struct ieee802154_dev *dev, int channel)
{
	pr_debug("%s %d\n", __func__, channel);
	might_sleep();
	dev->phy->current_channel = channel;
	return 0;
}

static void
hw_deliver(struct fake_dev_priv *priv, struct sk_buff *skb)
{
	struct sk_buff *newskb;

	if (!priv->working)
		return;

	newskb = pskb_copy(skb, GFP_ATOMIC);

	ieee802154_rx_irqsafe(priv->dev, newskb, 0xcc);
}

static int
hw_xmit(struct ieee802154_dev *dev, struct sk_buff *skb)
{
	struct fake_dev_priv *priv = dev->priv;
	struct fake_priv *fake = priv->fake;

	might_sleep();

	read_lock_bh(&fake->lock);
	if (priv->list.next == priv->list.prev) {
		/* we are the only one device */
		hw_deliver(priv, skb);
	} else {
		struct fake_dev_priv *dp;
		list_for_each_entry(dp, &priv->fake->list, list)
			if (dp != priv &&
			    dp->dev->phy->current_channel ==
					priv->dev->phy->current_channel)
				hw_deliver(dp, skb);
	}
	read_unlock_bh(&fake->lock);

	return 0;
}

static int
hw_start(struct ieee802154_dev *dev) {
	struct fake_dev_priv *priv = dev->priv;

	if (priv->working)
		return -EBUSY;

	priv->working = 1;

	return 0;
}

static void
hw_stop(struct ieee802154_dev *dev) {
	struct fake_dev_priv *priv = dev->priv;

	priv->working = 0;
}

static struct ieee802154_ops fake_ops = {
	.owner = THIS_MODULE,
	.xmit = hw_xmit,
	.ed = hw_ed,
	.set_channel = hw_channel,
	.start = hw_start,
	.stop = hw_stop,
};

static int ieee802154fake_add_priv(struct device *dev, struct fake_priv *fake)
{
	struct fake_dev_priv *priv;
	int err = -ENOMEM;
	struct ieee802154_dev *ieee;

	ieee = ieee802154_alloc_device(sizeof(*priv), &fake_ops);
	if (!dev)
		goto err_alloc_dev;

	priv = ieee->priv;
	priv->dev = ieee;

	/* 868 MHz BPSK	802.15.4-2003 */
	ieee->phy->channels_supported[0] |= 1;
	/* 915 MHz BPSK	802.15.4-2003 */
	ieee->phy->channels_supported[0] |= 0x7fe;
	/* 2.4 GHz O-QPSK 802.15.4-2003 */
	ieee->phy->channels_supported[0] |= 0x7FFF800;
	/* 868 MHz ASK 802.15.4-2006 */
	ieee->phy->channels_supported[1] |= 1;
	/* 915 MHz ASK 802.15.4-2006 */
	ieee->phy->channels_supported[1] |= 0x7fe;
	/* 868 MHz O-QPSK 802.15.4-2006 */
	ieee->phy->channels_supported[2] |= 1;
	/* 915 MHz O-QPSK 802.15.4-2006 */
	ieee->phy->channels_supported[2] |= 0x7fe;
	/* 2.4 GHz CSS 802.15.4a-2007 */
	ieee->phy->channels_supported[3] |= 0x3fff;
	/* UWB Sub-gigahertz 802.15.4a-2007 */
	ieee->phy->channels_supported[4] |= 1;
	/* UWB Low band 802.15.4a-2007 */
	ieee->phy->channels_supported[4] |= 0x1e;
	/* UWB High band 802.15.4a-2007 */
	ieee->phy->channels_supported[4] |= 0xffe0;

	INIT_LIST_HEAD(&priv->list);
	priv->fake = fake;

	ieee->parent = dev;

	err = ieee802154_register_device(ieee);
	if (err)
		goto err_reg;

	write_lock_bh(&fake->lock);
	list_add_tail(&priv->list, &fake->list);
	write_unlock_bh(&fake->lock);

	return 0;

err_reg:
	ieee802154_free_device(priv->dev);
err_alloc_dev:
	return err;
}

static void ieee802154fake_del_priv(struct fake_dev_priv *priv)
{
	write_lock_bh(&priv->fake->lock);
	list_del(&priv->list);
	write_unlock_bh(&priv->fake->lock);

	ieee802154_unregister_device(priv->dev);
	ieee802154_free_device(priv->dev);
}

static ssize_t
adddev_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t n)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct fake_priv *priv = platform_get_drvdata(pdev);
	int err;

	err = ieee802154fake_add_priv(dev, priv);
	if (err)
		return err;
	return n;
}

static DEVICE_ATTR(adddev, 0200, NULL, adddev_store);

static struct attribute *fake_attrs[] = {
	&dev_attr_adddev.attr,
	NULL,
};

static struct attribute_group fake_group = {
	.name	= NULL /* fake */,
	.attrs	= fake_attrs,
};


static int __devinit ieee802154fake_probe(struct platform_device *pdev)
{
	struct fake_priv *priv;
	struct fake_dev_priv *dp;

	int err = -ENOMEM;
	priv = kzalloc(sizeof(struct fake_priv), GFP_KERNEL);
	if (!priv)
		goto err_alloc;

	INIT_LIST_HEAD(&priv->list);
	rwlock_init(&priv->lock);

	err = sysfs_create_group(&pdev->dev.kobj, &fake_group);
	if (err)
		goto err_grp;

	err = ieee802154fake_add_priv(&pdev->dev, priv);
	if (err < 0)
		goto err_slave;

	platform_set_drvdata(pdev, priv);
	dev_info(&pdev->dev, "Added ieee802154 hardware\n");
	return 0;

err_slave:
	list_for_each_entry(dp, &priv->list, list)
		ieee802154fake_del_priv(dp);
	sysfs_remove_group(&pdev->dev.kobj, &fake_group);
err_grp:
	kfree(priv);
err_alloc:
	return err;
}

static int __devexit ieee802154fake_remove(struct platform_device *pdev)
{
	struct fake_priv *priv = platform_get_drvdata(pdev);
	struct fake_dev_priv *dp, *temp;

	list_for_each_entry_safe(dp, temp, &priv->list, list)
		ieee802154fake_del_priv(dp);
	sysfs_remove_group(&pdev->dev.kobj, &fake_group);
	kfree(priv);
	return 0;
}

static struct platform_device *ieee802154fake_dev;

static struct platform_driver ieee802154fake_driver = {
	.probe = ieee802154fake_probe,
	.remove = __devexit_p(ieee802154fake_remove),
	.driver = {
			.name = "ieee802154fakelb",
			.owner = THIS_MODULE,
	},
};

static __init int fake_init(void)
{
	ieee802154fake_dev = platform_device_register_simple(
			"ieee802154fakelb", -1, NULL, 0);
	return platform_driver_register(&ieee802154fake_driver);
}

static __exit void fake_exit(void)
{
	platform_driver_unregister(&ieee802154fake_driver);
	platform_device_unregister(ieee802154fake_dev);
}

module_init(fake_init);
module_exit(fake_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dmitry Eremin-Solenikov, Sergey Lapin");



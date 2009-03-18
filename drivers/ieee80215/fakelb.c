#include <linux/module.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/spinlock.h>
#include <net/ieee80215/dev.h>

struct fake_dev_priv {
	struct ieee80215_dev *dev;
	phy_status_t cur_state, pend_state;

	struct list_head list;
	struct fake_priv *fake;
};

struct fake_priv {
	struct list_head list;
	rwlock_t lock;
};

static int is_transmitting(struct ieee80215_dev *dev)
{
	return 0;
}

static int is_receiving(struct ieee80215_dev *dev)
{
	return 0;
}

static phy_status_t
hw_ed(struct ieee80215_dev *dev, u8 *level)
{
	pr_debug("%s\n", __func__);
	might_sleep();
	BUG_ON(!level);
	*level = 0xbe;
	return PHY_SUCCESS;
}

static phy_status_t
hw_cca(struct ieee80215_dev *dev)
{
	pr_debug("%s\n", __func__);
	might_sleep();
	return PHY_IDLE;
}

static phy_status_t
hw_state(struct ieee80215_dev *dev, phy_status_t state)
{
	struct fake_dev_priv *priv = dev->priv;
	pr_debug("%s %d %d\n", __func__, priv->cur_state, state);
	might_sleep();
	if (state != PHY_TRX_OFF && state != PHY_RX_ON && state != PHY_TX_ON && state != PHY_FORCE_TRX_OFF)
		return PHY_INVAL;
	else if (state == PHY_FORCE_TRX_OFF) {
		priv->cur_state = PHY_TRX_OFF;
		return PHY_SUCCESS;
	} else if (priv->cur_state == state)
		return state;
	else if ((state == PHY_TRX_OFF || state == PHY_RX_ON) && is_transmitting(dev)) {
		priv->pend_state = state;
		return PHY_BUSY_TX;
	} else if ((state == PHY_TRX_OFF || state == PHY_TX_ON) && is_receiving(dev)) {
		priv->pend_state = state;
		return PHY_BUSY_RX;
	} else {
		priv->cur_state = state;
		return PHY_SUCCESS;
	}
}

static phy_status_t
hw_channel(struct ieee80215_dev *dev, int channel)
{
	pr_debug("%s %d\n", __func__, channel);
	might_sleep();
	return PHY_SUCCESS;
}

static void
hw_deliver(struct fake_dev_priv *priv, struct sk_buff *skb)
{
	struct sk_buff *newskb;

	newskb = pskb_copy(skb, GFP_ATOMIC);

	ieee80215_rx_irqsafe(priv->dev, newskb, 0xcc);
}

static int
hw_tx(struct ieee80215_dev *dev, struct sk_buff *skb)
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
			if (dp != priv)
				hw_deliver(dp, skb);
	}
	read_unlock_bh(&fake->lock);

	return PHY_SUCCESS;
}

static struct ieee80215_ops fake_ops = {
	.owner = THIS_MODULE,
	.tx = hw_tx,
	.ed = hw_ed,
	.cca = hw_cca,
	.set_trx_state = hw_state,
	.set_channel = hw_channel,
};

static int ieee80215fake_add_priv(struct device *dev, struct fake_priv *fake, const u8 *macaddr)
{
	struct fake_dev_priv *priv;
	int err = -ENOMEM;

	priv = kzalloc(sizeof(struct fake_dev_priv), GFP_KERNEL);
	if (!priv)
		goto err_alloc;

	INIT_LIST_HEAD(&priv->list);

	priv->dev = ieee80215_alloc_device();
	if (!priv->dev)
		goto err_alloc_dev;
	priv->dev->name = "IEEE 802.15.4 fake";
	priv->dev->priv = priv;
	priv->dev->parent = dev;
	priv->fake = fake;

	err = ieee80215_register_device(priv->dev, &fake_ops);
	if (err)
		goto err_reg;
	rtnl_lock();
	err = ieee80215_add_slave(priv->dev, macaddr);
	rtnl_unlock();
	if (err < 0)
		goto err_slave;

	write_lock_bh(&fake->lock);
	list_add_tail(&priv->list, &fake->list);
	write_unlock_bh(&fake->lock);

	return 0;

err_slave:
	ieee80215_unregister_device(priv->dev);
err_reg:
	ieee80215_free_device(priv->dev);
err_alloc_dev:
	kfree(priv);
err_alloc:
	return err;
}

static void ieee80215fake_del_priv(struct fake_dev_priv *priv)
{
	write_lock_bh(&priv->fake->lock);
	list_del(&priv->list);
	write_unlock_bh(&priv->fake->lock);

	ieee80215_unregister_device(priv->dev);
	ieee80215_free_device(priv->dev);
	kfree(priv);
}

static ssize_t
adddev_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t n)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct fake_priv *priv = platform_get_drvdata(pdev);
	char hw[8] = {};
	int i, j, ch, err;

	for (i = 0, j = 0; i < 16 && j < n; j++) {
		ch = buf[j];
		switch (buf[j]) {
		default:
			return -EINVAL;
		case '0'...'9':
			ch -= '0';
			break;
		case 'A'...'F':
			ch -= 'A' - 10;
			break;
		case 'a'...'f':
			ch -= 'a' - 10;
			break;
		case ':':
		case '.':
			continue;
		}
		if (i % 2)
			hw[i/2] = (hw[i/2] & 0xf0) | ch;
		else
			hw[i/2] = ch << 4;
		i++;
	}
	if (i != 16)
		return -EINVAL;
	err = ieee80215fake_add_priv(dev, priv, hw);
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


static int __devinit ieee80215fake_probe(struct platform_device *pdev)
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

	err = ieee80215fake_add_priv(&pdev->dev, priv, "\xde\xad\xbe\xaf\xca\xfe\xba\xbe");
	if (err < 0)
		goto err_slave;

/*	err = ieee80215fake_add_priv(priv, "\x67\x45\x23\x01\x67\x45\x23\x01");
	if (err < 0)
		goto err_slave;*/

	platform_set_drvdata(pdev, priv);
	dev_info(&pdev->dev, "Added ieee80215 hardware\n");
	return 0;

err_slave:
	list_for_each_entry(dp, &priv->list, list)
		ieee80215fake_del_priv(dp);
	sysfs_remove_group(&pdev->dev.kobj, &fake_group);
err_grp:
	kfree(priv);
err_alloc:
	return err;
}

static int __devexit ieee80215fake_remove(struct platform_device *pdev)
{
	struct fake_priv *priv = platform_get_drvdata(pdev);
	struct fake_dev_priv *dp, *temp;

	list_for_each_entry_safe(dp, temp, &priv->list, list)
		ieee80215fake_del_priv(dp);
	sysfs_remove_group(&pdev->dev.kobj, &fake_group);
	kfree(priv);
	return 0;
}

static struct platform_device *ieee80215fake_dev;

static struct platform_driver ieee80215fake_driver = {
	.probe = ieee80215fake_probe,
	.remove = __devexit_p(ieee80215fake_remove),
	.driver = {
			.name = "ieee80215fakelb",
			.owner = THIS_MODULE,
	},
};

static __init int fake_init(void)
{
	ieee80215fake_dev = platform_device_register_simple("ieee80215fakelb", -1, NULL, 0);
	return platform_driver_register(&ieee80215fake_driver);
}

static __exit void fake_exit(void)
{
	platform_driver_unregister(&ieee80215fake_driver);
	platform_device_unregister(ieee80215fake_dev);
}

module_init(fake_init);
module_exit(fake_exit);
MODULE_LICENSE("GPL");


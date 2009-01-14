#include <linux/module.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>

struct fake_dev_priv {
	struct ieee80215_dev *dev;
	phy_status_t cur_state, pend_state;
	int id;
};

struct fake_priv {
	struct fake_dev_priv dev1, dev2;
};

static int is_transmitting(struct ieee80215_dev *dev) {
	return 0;
}

static int is_receiving(struct ieee80215_dev *dev) {
	return 0;
}

static phy_status_t
hw_ed(struct ieee80215_dev *dev, u8 *level)
{
	pr_debug("%s\n",__FUNCTION__);
	BUG_ON(!level);
	*level = 0;
	return PHY_SUCCESS;
}

static phy_status_t
hw_cca(struct ieee80215_dev *dev)
{
	pr_debug("%s\n",__FUNCTION__);
	return PHY_IDLE;
}

static phy_status_t
hw_state(struct ieee80215_dev *dev, phy_status_t state)
{
	struct fake_dev_priv *priv = dev->priv;
	pr_debug("%s %d %d\n",__FUNCTION__, priv->cur_state, state);
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
	pr_debug("%s %d\n",__FUNCTION__, channel);
	return PHY_SUCCESS;
}

static int
hw_tx(struct ieee80215_dev *dev, struct sk_buff *skb)
{
	struct sk_buff *newskb;
	struct fake_dev_priv *priv = dev->priv;
	struct fake_priv *fake;
	pr_debug("%s\n",__FUNCTION__);
	newskb = pskb_copy(skb, GFP_ATOMIC);
	PHY_CB(newskb)->lqi = 0xcc;
	if (priv->id == 1) {
		fake = container_of(priv, struct fake_priv, dev1);
		ieee80215_rx(fake->dev2.dev, newskb);
	} else {
		fake = container_of(priv, struct fake_priv, dev2);
		ieee80215_rx(fake->dev1.dev, newskb);
	}
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

static int __devinit ieee80215fake_probe(struct platform_device *pdev)
{
	struct fake_priv *priv;
	int err = -ENOMEM;
	priv = kzalloc(sizeof(struct fake_priv), GFP_KERNEL);
	if (!priv)
		goto err_alloc;

	priv->dev1.dev = ieee80215_alloc_device();
	if (!priv->dev1.dev)
		goto err_alloc_1;
	priv->dev1.dev->name = "IEEE 802.15.4 fake1";
	priv->dev1.dev->priv = &priv->dev1;
	priv->dev1.id = 1;

	priv->dev2.dev = ieee80215_alloc_device();
	if (!priv->dev2.dev)
		goto err_alloc_2;
	priv->dev2.dev->name = "IEEE 802.15.4 fake2";
	priv->dev2.dev->priv = &priv->dev2;
	priv->dev2.id = 2;

	pr_debug("registering devices\n");
	err = ieee80215_register_device(priv->dev1.dev, &fake_ops);
	if(err)
		goto err_reg_1;
	rtnl_lock();
	err = ieee80215_add_slave(priv->dev1.dev, "\xde\xad\xbe\xaf\xca\xfe\xba\xbe");
	rtnl_unlock();
	if (err < 0)
		goto err_slave_1;

	err = ieee80215_register_device(priv->dev2.dev, &fake_ops);
	if(err)
		goto err_reg_2;
	rtnl_lock();
	err = ieee80215_add_slave(priv->dev2.dev, "\x67\x45\x23\x01\x67\x45\x23\x01");
	rtnl_unlock();
	if (err < 0)
		goto err_slave_2;

	platform_set_drvdata(pdev, priv);
	dev_info(&pdev->dev, "Added ieee80215 hardware\n");
	return 0;

err_slave_2:
	ieee80215_unregister_device(priv->dev2.dev);
err_reg_2:
err_slave_1:
	ieee80215_unregister_device(priv->dev1.dev);
err_reg_1:
	ieee80215_free_device(priv->dev2.dev);
err_alloc_2:
	ieee80215_free_device(priv->dev1.dev);
err_alloc_1:
	kfree(priv);
err_alloc:
	return err;
}

static int __devexit ieee80215fake_remove(struct platform_device *pdev)
{
	struct fake_priv *priv = platform_get_drvdata(pdev);
	ieee80215_unregister_device(priv->dev2.dev);
	ieee80215_unregister_device(priv->dev1.dev);
	ieee80215_free_device(priv->dev2.dev);
	ieee80215_free_device(priv->dev1.dev);
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


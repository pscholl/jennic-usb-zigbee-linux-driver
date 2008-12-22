#include <linux/module.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>

struct fake_priv {
	struct ieee80215_dev *dev;
//	struct timer_list rx_timer;
	phy_status_t cur_state, pend_state;
};


#if 0
static u8 msg_values[NUM_MSGS] = {
	IEEE80215_MSG_CHANNEL_CONFIRM,
	IEEE80215_MSG_ED_CONFIRM,
	IEEE80215_MSG_CCA_CONFIRM,
	IEEE80215_MSG_SET_STATE,
	IEEE80215_MSG_XMIT_BLOCK_CONFIRM,
	IEEE80215_MSG_XMIT_STREAM_CONFIRM,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_STREAM,
};
#define NUM_MSGS (sizeof(msg_values)/sizeof(msg_values[0]))

	/* possible statuses '*' = used in driver
	* IEEE80215_BUSY;
	* IEEE80215_BUSY_RX;
	* IEEE80215_BUSY_TX;
	IEEE80215_FORCE_TRX_OFF
	* IEEE80215_IDLE;
	IEEE80215_INVALID_PARAMETER
	* IEEE80215_RX_ON;
	* IEEE80215_PHY_SUCCESS;
	* IEEE80215_TRX_OFF;
	* IEEE80215_TX_ON;
	IEEE80215_UNSUPPORTED_ATTRIBUTE
	* IEEE80215_ERROR;
	*/

static u8 status_values[] = {
	IEEE80215_BUSY,
	IEEE80215_BUSY_RX,
	IEEE80215_BUSY_TX,
	IEEE80215_IDLE,
	IEEE80215_RX_ON,
	IEEE80215_PHY_SUCCESS,
	IEEE80215_TRX_OFF,
	IEEE80215_TX_ON,
	IEEE80215_ERROR,
};
#define NUM_STATUSES (sizeof(status_values)/sizeof(status_values[0]))

static void do_net_rx(unsigned long data)
{
	struct ieee80215_phy * phy = (struct ieee80215_phy *) data;
	u8 lq;
	// struct sk_buff * skb;
	u8 msg, status;
	u8 buf[64];
#if 0
	/* Some APIs */
	ops->phy->set_channel_confirm(ops->phy, status);
	zbdev->phy->ed_confirm(zbdev->phy, status, zbdev->param2 /* level */);
	zbdev->phy->cca_confirm(zbdev->phy, status);
	zbdev->phy->set_state_confirm(zbdev->phy, status);
	zbdev->phy->receive_block(zbdev->phy, zbdev->param2, zbdev->data, zbdev->param1);
	ops->phy->receive_block(ops->phy, zbdev->param2,  zbdev->data, zbdev->param1);
#endif
	get_random_bytes(&msg, 1);
	get_random_bytes(&lq, 1);
	msg %= NUM_MSGS; /* Tune for additional commands, if any */
	msg = msg_values[msg];
	get_random_bytes(&status, 1);
	status %= NUM_STATUSES; /* Tune for additional statuses, if any */
	status = status_values[status];
	switch(msg) {
	case IEEE80215_MSG_RECV_STREAM:
		break;
	case IEEE80215_MSG_RECV_BLOCK:
		pr_debug("Setting RX on\n");
		ieee80215_net_cmd(phy, IEEE80215_MSG_SET_STATE, IEEE80215_RX_ON, data);
		get_random_bytes(buf, sizeof(buf));
		ieee80215_net_rx(phy, buf, sizeof(buf), lq);
		break;
	case IEEE80215_MSG_ED_CONFIRM:
		get_random_bytes(&data, 1);
	default:
		pr_debug("generated event %d status %d\n", msg, status);
		ieee80215_net_cmd(phy, msg, status, data);
	}
        del_timer(&rx_timer);
        rx_timer.expires = jiffies + 200;
        add_timer(&rx_timer);
}

static void __init rx_init(void * data)
{
        /* initialize the timer that will increment the counter */
        init_timer(&rx_timer);
        rx_timer.function = do_net_rx;
        rx_timer.expires = jiffies + 200;
        rx_timer.data = (unsigned long) data;
        add_timer(&rx_timer);
}


/* Valid channels: 1-16 */
static void
hw_set_channel(struct ieee80215_dev *dev, u8 channel)
{
	pr_debug("%s\n",__FUNCTION__);
}
#endif

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
	struct fake_priv *priv = dev->priv;
	pr_debug("%s\n",__FUNCTION__);
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

static int
hw_tx(struct ieee80215_dev *dev, struct sk_buff *skb)
{
	struct sk_buff *newskb;
	pr_debug("%s\n",__FUNCTION__);
	newskb = pskb_copy(skb, GFP_ATOMIC);
	ieee80215_rx(dev, newskb);
	return PHY_SUCCESS;
}

static struct ieee80215_ops fake_ops = {
	.owner = THIS_MODULE,
	.tx = hw_tx,
	.ed = hw_ed,
	.cca = hw_cca,
	.set_trx_state = hw_state,
};

static int __devinit ieee80215fake_probe(struct platform_device *pdev)
{
	struct fake_priv *priv;
	int err;
	priv = kzalloc(sizeof(struct fake_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = ieee80215_alloc_device();
	if (!priv->dev) {
		kfree(priv);
		return -ENOMEM;
	}
	priv->dev->name = "IEEE 802.15.4 fake";
	priv->dev->priv = priv;

	pr_debug("rgistering device\n");
	err = ieee80215_register_device(priv->dev, &fake_ops);
	if(err) {
		kfree(priv);
		return err;
	}
	ieee80215_add_slave(priv->dev, "\xde\xad\xbe\xaf\xca\xfe\xba\xbe");
//	rx_init(dev_op->priv);
	platform_set_drvdata(pdev, priv);
	dev_info(&pdev->dev, "Added ieee80215 hardware\n");
	return 0;
}

static int __devexit ieee80215fake_remove(struct platform_device *pdev)
{
	struct fake_priv *priv = platform_get_drvdata(pdev);
	ieee80215_unregister_device(priv->dev);
	kfree(priv);
	return 0;
}

static struct platform_device *ieee80215fake_dev;

static struct platform_driver ieee80215fake_driver = {
	.probe = ieee80215fake_probe,
	.remove = __devexit_p(ieee80215fake_remove),
	.driver = {
			.name = "ieee80215fake",
			.owner = THIS_MODULE,
	},
};

static __init int fake_init(void)
{
	ieee80215fake_dev = platform_device_register_simple("ieee80215fake", -1, NULL, 0);
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


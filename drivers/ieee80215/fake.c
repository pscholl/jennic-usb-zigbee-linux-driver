#include <linux/module.h>
#include <linux/timer.h>
#include <asm/local.h>
#include <linux/platform_device.h>
#include <net/ieee80215/ieee80215.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/const.h>
#include <linux/netdevice.h>

static struct timer_list rx_timer;

#define NUM_MSGS 9
#define NUM_STATUSES 9

static u8 msg_values[NUM_MSGS] = {
	IEEE80215_MSG_CHANNEL_CONFIRM,
	IEEE80215_MSG_ED_CONFIRM,
	IEEE80215_MSG_CCA_CONFIRM,
	IEEE80215_MSG_SET_STATE,
	IEEE80215_MSG_XMIT_BLOCK_CONFIRM,
	IEEE80215_MSG_XMIT_STREAM_CONFIRM,
	IEEE80215_MSG_RECV_BLOCK,
	IEEE80215_MSG_RECV_STREAM,
};
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

static u8 status_values[NUM_STATUSES] = {
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

static void do_net_rx(unsigned long data)
{
	struct ieee80215_phy * phy = (struct ieee80215_phy *) data;
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
	msg %= NUM_MSGS; /* Tune for additional commands, if any */
	msg = msg_values[msg];
	get_random_bytes(&status, 1);
	status %= NUM_STATUSES; /* Tune for additional statuses, if any */
	status = status_values[status];
	switch(msg) {
	case IEEE80215_MSG_RECV_STREAM:
		break;
	case IEEE80215_MSG_RECV_BLOCK:
		get_random_bytes(buf, sizeof(buf));
		ieee80215_net_rx(phy, buf, sizeof(buf), 0, 0);
		break;
	case IEEE80215_MSG_ED_CONFIRM:
		get_random_bytes(&data, 1);
	default:
		ieee80215_net_cmd(phy, msg, status, data);
	}
        del_timer(&rx_timer);
        rx_timer.expires = jiffies + 2000;
        add_timer(&rx_timer);
	pr_debug("Transferred one frame\n");
}

static void __init rx_init(void * data)
{
        /* initialize the timer that will increment the counter */
        init_timer(&rx_timer);
        rx_timer.function = do_net_rx;
        rx_timer.expires = jiffies + 2000;
        rx_timer.data = (unsigned long) data;
        add_timer(&rx_timer);
}


/* Valid channels: 1-16 */
static void
hw_set_channel(ieee80215_phy_t *phy, u8 channel)
{
	pr_debug("%s\n",__FUNCTION__);
}
 
static void
hw_ed(ieee80215_phy_t *phy)
{
	pr_debug("%s\n",__FUNCTION__);
}
 
static void
hw_cca(ieee80215_phy_t *phy, u8 mode)
{
	pr_debug("%s\n",__FUNCTION__);
}
 
static void
hw_state(ieee80215_phy_t *phy, u8 state)
{
	pr_debug("%s\n",__FUNCTION__);
}
 
static void
hw_xmit(ieee80215_phy_t *phy, u8 *ppdu, size_t len)
{
	pr_debug("%s\n",__FUNCTION__);
}
 
static ieee80215_dev_op_t *alloc_ieee80215_dev(void)
{
	struct ieee80215_dev_ops *dev_op;

	dev_op = kzalloc(sizeof(struct ieee80215_dev_ops), GFP_KERNEL);
	if (!dev_op) {
 		printk(KERN_ERR "%s: unable to allocate memory\n", __FUNCTION__);
 		return NULL;
 	}
	dev_op->name 		= "fakedev";
	dev_op->set_channel	= hw_set_channel;
	dev_op->ed		= hw_ed;
	dev_op->cca		= hw_cca;
	dev_op->set_state	= hw_state;
	dev_op->xmit		= hw_xmit;
	dev_op->flags		= IEEE80215_DEV_SINGLE;

	return dev_op;
}
 
static ssize_t ieee80215fake_debug_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	// struct ieee80215_dev_ops *dev_op = dev_get_drvdata(dev);
	return 0;
}
#if 0
static ssize_t ieee80215fake_control_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	// struct ieee80215_dev_ops *dev_op = dev_get_drvdata(dev);
	// struct ieee80215_phy_t *phy = dev_op->priv;
	return 0;
}
static ssize_t ieee80215fake_control_store(struct device *dev,
		struct device_attribute *attr, char *buf, size_t len)
{
	struct ieee80215_dev_ops *dev_op = dev_get_drvdata(dev);
	struct ieee80215_phy *phy = dev_op->priv;
#warning FIXME
	phy->receive_block(phy, len, buf, 0);
	return 0;
}
#endif 
DEVICE_ATTR(debug, S_IWUSR|S_IRUGO,
	ieee80215fake_debug_show, NULL);
#if 0
DEVICE_ATTR(control, S_IWUSR|S_IRUGO,
	ieee80215fake_control_show,  ieee80215fake_control_store);
static struct device_attribute *devcontrol[] = {
	[0]		= 	&dev_attr_debug,
#if 0
	[1]		= 	&dev_attr_control,
#endif
};
#endif

static int __init ieee80215fake_probe(struct platform_device *pdev)
{
	struct ieee80215_dev_ops * dev_op;
	int err;
	dev_op = alloc_ieee80215_dev();
//	err = ieee80215_register_device(dev_op);
	pr_debug("rgistering device\n");
	err = ieee80215_register_device(dev_op);
	rx_init(dev_op->priv);
	if(err)
		return err;
	platform_set_drvdata(pdev, dev_op);
	dev_info(&pdev->dev, "Adding ieee80215 hardware\n");
#if 0
	err = device_create_file(&pdev->dev, devcontrol);
        if (err) {
                dev_err(&pdev->dev, "cannot create status attribute\n");
        }
#endif
	return 0;
}

static int ieee80215fake_remove(struct platform_device *pdev)
{
	struct ieee80215_dev_op * dev_op = platform_get_drvdata(pdev);
	kfree(dev_op);
	return 0;
}

struct platform_device ieee80215fake_dev = {
	.name = "ieee80215fake",
};

struct platform_driver ieee80215fake = {
	.probe = ieee80215fake_probe,
	.remove = ieee80215fake_remove,
	.driver = {
			.name = "ieee80215fake",
			.owner = THIS_MODULE,
	},
};

static __init int fake_init(void)
{
	platform_device_register(&ieee80215fake_dev);
	return platform_driver_register(&ieee80215fake);
}

static __exit void fake_exit(void)
{
	platform_driver_unregister(&ieee80215fake);
}

module_init(fake_init);
module_exit(fake_exit);
MODULE_LICENSE("GPL");


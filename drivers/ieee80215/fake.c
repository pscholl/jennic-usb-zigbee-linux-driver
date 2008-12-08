#include <linux/module.h>
#include <linux/timer.h>
#include <asm/local.h>
#include <linux/platform_device.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/const.h>
#include <linux/netdevice.h> /* Will go away */

static struct timer_list rx_timer;

/* Will go away */

static struct sk_buff * alloc_cmd_frame(u8 msg, u8 status)
{
	/* We provide our states via special frames
	 * If our frame size is less than 6 bytes (PHY header size)
	 * then this is control message for our stack
	 */
	struct sk_buff * skb = alloc_skb(4, GFP_ATOMIC);
	unsigned char * data = skb->data;

	/* To be not mistaken about this frame type */
	data[0] = 0;
	data[1] = msg;
	data[2] = status;
	data[3] = 0;
	return skb;
}

static void do_net_rx(unsigned long data)
{
	struct ieee80215_dev_ops * ops = (struct ieee80215_dev_ops *) data;
	struct sk_buff * skb;
	u8 msg, status;
#if 0
	/* Some APIs */
	ops->phy->set_channel_confirm(ops->phy, status);
	zbdev->phy->ed_confirm(zbdev->phy, status, zbdev->param2 /* level */);
	zbdev->phy->cca_confirm(zbdev->phy, status);
	zbdev->phy->set_state_confirm(zbdev->phy, status);
	zbdev->phy->receive_block(zbdev->phy, zbdev->param2, zbdev->data, zbdev->param1);
	ops->phy->receive_block(ops->phy, zbdev->param2,  zbdev->data, zbdev->param1);
#endif
	msg = IEEE80215_MSG_SET_STATE;
	status = IEEE80215_PHY_SUCCESS;
	skb = alloc_cmd_frame(msg, status);
	netif_rx(skb);
        del_timer(&rx_timer);
        rx_timer.expires = jiffies + 10000;
        add_timer(&rx_timer);
}

static void __init rx_init(void * data)
{
        /* initialize the timer that will increment the counter */
        init_timer(&rx_timer);
        rx_timer.function = do_net_rx;
        rx_timer.expires = jiffies + 1;
        rx_timer.data = (unsigned long) data;
        add_timer(&rx_timer);
}


/* Valid channels: 1-16 */
static void
hw_set_channel(ieee80215_phy_t *phy, u8 channel)
{
}
 
static void
hw_ed(ieee80215_phy_t *phy)
{
}
 
static void
hw_cca(ieee80215_phy_t *phy, u8 mode)
{
}
 
static void
hw_state(ieee80215_phy_t *phy, u8 state)
{
}
 
static void
hw_xmit(ieee80215_phy_t *phy, u8 *ppdu, size_t len)
{
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
	
	err = ieee80215_register_netdev_master(dev_op);
	rx_init(dev_op);
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


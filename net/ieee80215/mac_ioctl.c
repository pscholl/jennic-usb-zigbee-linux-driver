#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/if_arp.h>
#include <net/sock.h>

#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/mac_struct.h>
#include <net/ieee80215/netdev.h>

static int run_dev_worker(struct ieee80215_priv *hw, void *data)
{
	BUG_ON(!hw);
	hw->work_data = data;
	init_completion(&hw->dev_work_complete);
	queue_work(hw->dev_workqueue, &hw->dev_work);
	return wait_for_completion_interruptible(&hw->dev_work_complete);
}

int ioctl_network_discovery(struct sock *sk, struct ieee80215_user_data __user *data)
{
	struct ieee80215_user_data kdata;
	struct net_device * dev;
	if(copy_from_user(&kdata, data, sizeof(struct ieee80215_user_data))) {
		printk(KERN_ERR "copy_to_user() failed in %s", __func__);
		return -EFAULT;
	}
	dev = dev_get_by_name(sock_net(sk), kdata.ifr_name);
	if(!dev->master)
		return -ENODEV;
/*
int zb_nwk_nlme_discovery(zb_nwk_t *nwk, u32 channels, u8 duration)
{
	if (duration > 0x0e) {
		zb_err("Duration is out of range\n");
		_apsme(nwk)->nlme_discovery_confirm(_apsme(nwk), 0, NULL, INVALID_PARAMETER);
		return 0;
	}
	nwk->mlme_scan_confirm = zb_nwk_scan_confirm;
	nwk->mac->mlme_scan_req(nwk->mac, IEEE80215_SCAN_ACTIVE, channels, duration);
	return 0;
}
	case ZB_SIOC_NETWORK_DISCOVERY: {
		zb_sioc_network_discovery_t data;
		if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
			zb_err("copy_from_user() failed\n");
			return -EFAULT;
		}
		aps->nwk->nlme_nwk_discovery(aps->nwk, data.channels, data.duration);
		return 0;
	}
*/
	dev_put(dev);
	return -ENOIOCTLCMD;
}
int ioctl_network_formation(struct sock *sk, struct ieee80215_user_data __user *data)
{
	struct ieee80215_user_data kdata;
	struct net_device * dev;
	if(copy_from_user(&kdata, data, sizeof(struct ieee80215_user_data))) {
		printk(KERN_ERR "copy_to_user() failed in %s", __func__);
		return -EFAULT;
	}
	dev = dev_get_by_name(sock_net(sk), kdata.ifr_name);
	if(!dev->master)
		return -ENODEV;
/*
	case ZB_SIOC_NETWORK_FORMATION: {
		zb_sioc_network_formation_t data;
		if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
			zb_err("copy_from_user() failed\n");
			return -EFAULT;
		}
		aps->nwk->nlme_nwk_formation(aps->nwk,
			data.channels,
			data.duration,
			data.bo,
			data.so,
			data.panid,
			data.ble);
		return 0;
	}
*/
	dev_put(dev);
	return -ENOIOCTLCMD;
}
int ioctl_permit_joining(struct sock *sk, struct ieee80215_user_data __user *data)
{
	struct ieee80215_user_data kdata;
	struct net_device * dev;
	if(copy_from_user(&kdata, data, sizeof(struct ieee80215_user_data))) {
		printk(KERN_ERR "copy_to_user() failed in %s", __func__);
		return -EFAULT;
	}
	dev = dev_get_by_name(sock_net(sk), kdata.ifr_name);
	if(!dev->master)
		return -ENODEV;
/*
	case ZB_SIOC_PERMIT_JOINING: {
		u8 duration;
		if (copy_from_user(&duration, req.ifr_data, sizeof(duration))) {
			zb_err("copy_from_user() failed\n");
			return -EFAULT;
		}
		aps->nwk->nlme_permit_join(aps->nwk, duration);
		return 0;
	}
*/
	dev_put(dev);
	return -ENOIOCTLCMD;
}
int ioctl_start_router(struct sock *sk, struct ieee80215_user_data __user *data)
{
	struct ieee80215_user_data kdata;
	struct net_device * dev;
	if(copy_from_user(&kdata, data, sizeof(struct ieee80215_user_data))) {
		printk(KERN_ERR "copy_to_user() failed in %s", __func__);
		return -EFAULT;
	}
	dev = dev_get_by_name(sock_net(sk), kdata.ifr_name);
	if(!dev->master)
		return -ENODEV;
/*
	case ZB_SIOC_START_ROUTER: {
		zb_sioc_start_router_t data;
		if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
			zb_err("copy_from_user() failed\n");
			return -EFAULT;
		}
		aps->nwk->nlme_start_router(aps->nwk,
			data.bo,
			data.so,
			data.ble);
		return 0;
	}
*/
	dev_put(dev);
	return -ENOIOCTLCMD;
}
int ioctl_mac_join(struct sock *sk, struct ieee80215_user_data __user *data)
{
	struct ieee80215_user_data kdata;
	struct net_device * dev;
	if(copy_from_user(&kdata, data, sizeof(struct ieee80215_user_data))) {
		printk(KERN_ERR "copy_to_user() failed in %s", __func__);
		return -EFAULT;
	}
	dev = dev_get_by_name(sock_net(sk), kdata.ifr_name);
	if(!dev->master)
		return -ENODEV;
/*
	case ZB_SIOC_JOIN: {
		zb_sioc_join_t data;
		if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
			zb_err("copy_from_user() failed\n");
			return -EFAULT;
		}
		aps->nwk->nlme_join(aps->nwk,
			data.panid,
			data.as_router,
			data.rejoin,
			data.channels,
			data.duration,
			data.power,
			data.rxon,
			data.mac_security);
		return 0;
	}
*/
	dev_put(dev);
	return -ENOIOCTLCMD;
}

/* TMP dirty hack, to be removed */

int ioctl_mac_cmd(struct sock *sk, struct ieee80215_user_data __user *data)
{
	struct ieee80215_user_data kdata;
	struct net_device * dev;
	struct ieee80215_priv * priv;
	int ret;
	struct ieee80215_work_data *wdata;
	if(copy_from_user(&kdata, data, sizeof(struct ieee80215_user_data))) {
		printk(KERN_ERR "copy_to_user() failed in %s", __func__);
		return -EFAULT;
	}
	dev = dev_get_by_name(sock_net(sk), kdata.ifr_name);
	if(!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE80215) {
		dev_put(dev);
		return -EINVAL;
	}
	switch(kdata.cmd) {
	case IEEE80215_MAC_CMD_SCAN:
		/* TODO */
		pr_debug("scanning on %s\n", dev->name);
		priv = ieee80215_slave_get_hw(dev);
		if (!priv)
			return -EFAULT;
		wdata = kzalloc(sizeof(struct ieee80215_work_data), GFP_KERNEL);
		if(!wdata)
			return -ENOMEM;
		wdata->cmd = kdata.cmd;
		wdata->scan.channels = kdata.channels;
		wdata->scan.type = IEEE80215_MAC_SCAN_ED;
		wdata->scan.duration = 14;
		// return ieee80215_mlme_scan_req(priv->master, 0, 0xffffffff, 14);
		ret = run_dev_worker(priv, wdata);
		kfree(wdata);
		dev_put(dev);
		return ret;
	default:
		dev_put(dev);
		return -EINVAL;
	}
/*
*/
	dev_put(dev);
	return -ENOIOCTLCMD;
}


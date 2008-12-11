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
#include <linux/if.h>
#include <linux/termios.h>	/* For TIOCOUTQ/INQ */
#include <net/datalink.h>
#include <net/psnap.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/route.h>

#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/mac.h>
#include <net/ieee80215/phy.h>

#define DBG_DUMP(data, len) { \
	int i; \
	pr_debug("file %s: function: %s: data: len %d:\n", __FILE__, __FUNCTION__, len); \
	for(i = 0; i < len; i++) {\
		pr_debug("%02x: %02x\n", i, data[i]); \
	} \
}

/**
 * Processing control messages
 * @dev - master device
 * @msg - message
 * @status - status
 *
 */

static int ieee80215_process_msg(struct net_device *dev, u8 msg, u8 status, u8 data)
{
	struct ieee80215_mnetdev_priv *priv;
	struct ieee80215_phy *phy;
	int mystatus;
	priv = netdev_priv(dev);
	phy = priv->dev_ops->priv;
	if(!phy)
		return -EFAULT;
	mystatus = (status == IEEE80215_PHY_SUCCESS) ?
				IEEE80215_PHY_SUCCESS : IEEE80215_ERROR;
	switch(status) {
	case IEEE80215_MSG_CHANNEL_CONFIRM:
		phy->set_channel_confirm(phy, mystatus);
		break;
	case IEEE80215_MSG_ED_CONFIRM:
		phy->ed_confirm(phy, mystatus, data /* level */);
		break;
	case IEEE80215_MSG_CCA_CONFIRM:
		mystatus = (IEEE80215_IDLE) ? IEEE80215_IDLE : IEEE80215_BUSY;
		phy->cca_confirm(phy, mystatus);
		break;
	case IEEE80215_MSG_SET_STATE:
		switch(status) {
		case IEEE80215_PHY_SUCCESS:
		case IEEE80215_TRX_OFF:
		case IEEE80215_RX_ON:
		case IEEE80215_TX_ON:
		case IEEE80215_BUSY_RX:
		case IEEE80215_BUSY_TX:
		case IEEE80215_BUSY:
			mystatus = status;
			break;
		default:
			printk(KERN_ERR "%s: bad status received from firmware: %u\n",
				__FUNCTION__, status);
			mystatus = IEEE80215_ERROR;
			break;
		}
		phy->set_state_confirm(phy, mystatus);
		break;

	case IEEE80215_MSG_XMIT_BLOCK_CONFIRM:
	case IEEE80215_MSG_XMIT_STREAM_CONFIRM:
		phy->xmit_confirm(phy, mystatus);
		break;
	default:
		printk(KERN_ERR "%s bad message %d\n", msg);
		break;
	}
	return 0;
}

static int ieee80215_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;

	DBG_DUMP(skb->data, skb->len);
	if(!netif_running(dev))
		return -ENODEV;
	pr_debug("got frame, type %d, dev %p master %p\n", dev->type, dev, dev->master);
	if (dev->type != ARPHRD_IEEE80215 || !net_eq(dev_net(dev), &init_net)) {
		kfree_skb(skb);
		return 0;
	}
	/* Control frame processing */
	if(skb->len < 5 && !dev->master) {
		pr_debug("Got control frame\n");
		pr_debug("We better have some action for control frame here\n");
		/* We won't put control frames to socket buffer, no need to bother */
		ieee80215_process_msg(dev, skb->data[1], skb->data[2], skb->data[3]);
		kfree_skb(skb);
	}

	/* What's wrong with skb->sk here??! */
	/* dev_queue_xmit(skb) */
	/* Will have this test in future */
#if 0
	if (!dev->master && len > 4)
	{
		kfree_skb(skb);
		return 0;
	}
#endif
	sk = ((struct ieee80215_netdev_priv *) netdev_priv(dev))->sk;
	skb->sk = sk;

	if (sock_queue_rcv_skb(sk, skb) < 0) {
		kfree_skb(skb);
	}

	return 0;
}

/* go to <net/ieee80215/af_ieee80215.h> */
struct sockaddr_ieee80215 {
	sa_family_t family; /* AF_IEEE80215 */
	__le64 addr; /* little endian */
};

static struct packet_type ieee80215_packet_type = {
	.type = __constant_htons(ETH_P_IEEE80215),
	.func = ieee80215_rcv,
};

struct proto ieee80215_prot = {
	.name		   = "ieee80215",
	.owner		   = THIS_MODULE,
	.obj_size	   = sizeof(struct sock),
};

static int ieee80215_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		sock_orphan(sk);
		sock->sk = NULL;
		lock_sock(sk);
		release_sock(sk);
		sock_put(sk);
#warning FIXME ieee80215_destroy_socket
#if 0
/* slapin: FIXME */
		ieee80215_destroy_socket(sk);
#endif
	}
	return 0;
}

static int ieee80215_if_ioctl(struct sock *sk, int cmd, void __user *arg)
{
	struct ifreq req;
	struct net_device *dev;
	struct ieee80215_netdev_priv * priv;
	struct ieee80215_mnetdev_priv * mpriv;
	struct ieee80215_user_data data;
	if (copy_from_user(&req, arg, sizeof(req))) {
		pr_debug("copy_from_user() failed\n");
		return -EFAULT;
	}
	dev = __dev_get_by_name(&init_net, req.ifr_name);
	if (!dev) {
		pr_debug("no dev\n");
		return -ENODEV;
	}
	if(dev->master) {
		priv = netdev_priv(dev);
		mpriv = netdev_priv(dev->master);
	} else {
		priv = NULL;
		mpriv = netdev_priv(dev);
	}
	switch (cmd) {
	case SIOCGIFADDR: {
			if(!priv)
				return -EPERM;
#warning FIXME:	move address out from phy to support multi-interface config
			req.ifr_hwaddr.sa_family = AF_IEEE80215;
			memcpy(&req.ifr_hwaddr.sa_data,
				&priv->mac->phy->dev_op->_64bit, sizeof(u64));
			return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;
		}
	
	case SIOCSIFADDR:
#warning FIXME:	move address out from phy to support multi-interface config
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (AF_IEEE80215 != req.ifr_hwaddr.sa_family)
			return -EINVAL;
		if (netif_running(dev)) {
			pr_debug("hardware address may only be changed while device is down\n");
			return -EINVAL;
		}
		if(!priv)
			return -EPERM;
		priv->mac->phy->dev_op->_64bit = *(u64*)req.ifr_hwaddr.sa_data;
		memcpy(&priv->mac->phy->dev_op->_64bit,
				&req.ifr_hwaddr.sa_data, sizeof(u64));
		return 0;

	case SIOCGIFFLAGS:
		req.ifr_flags = dev_get_flags(dev);
		return copy_to_user(arg, &req, sizeof(req)) ? -EFAULT : 0;

	case SIOCSIFFLAGS:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		if(!priv)
			return -EPERM;

		if (req.ifr_flags & (IFF_UP | IFF_RUNNING)) {
			if (netif_running(dev)) {
				pr_debug("device is already running\n");
				return -EBUSY;
			} else {
				if(priv) {
					sk->sk_user_data = dev;
					priv->sk = sk;
				}
			}
		}
		return dev_change_flags(dev, req.ifr_flags);
	case IEEE80215_SIOC_NETWORK_DISCOVERY:
		if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
			pr_debug("copy_from_user() failed\n");
			return -EFAULT;
		}
		priv->mac->mlme_scan_req(priv->mac, IEEE80215_SCAN_ACTIVE,
				data.channels, data.duration);
		break;
	case IEEE80215_SIOC_NETWORK_FORMATION:
		if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
			pr_debug("copy_from_user() failed\n");
			return -EFAULT;
		}
		priv->mac->mlme_scan_req(priv->mac, IEEE80215_SCAN_ED,
				data.channels, data.duration);
		break;
	case IEEE80215_SIOC_PERMIT_JOINING: {
			ieee80215_mlme_pib_t a;
			if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
				pr_debug("copy_from_user() failed\n");
				return -EFAULT;
			}
			a.attr_type = IEEE80215_ASSOCIATION_PERMIT;
			if (data.duration > 0) {
				a.attr.association_permit = true;
				if (0xff == data.duration) {
					pr_debug("Permit join\n");
				} else {
					pr_debug("Permit join for %u seconds\n", data.duration);
				}
			} else {
				pr_debug("Disable permit join\n");
				a.attr.association_permit = false;
			}
			priv->mac->mlme_set_req(priv->mac, a);
		}
		break;
	case IEEE80215_SIOC_START_ROUTER: {
			struct ieee80215_cmd_cap cap;
			u8 cap_info;
			if (copy_from_user(&data, req.ifr_data, sizeof(data))) {
				pr_debug("copy_from_user() failed\n");
				return -EFAULT;
			}
			if (data.rejoin) {
				pr_debug("Joining trough orhpan scan\n");
				priv->mac->mlme_scan_req(priv->mac,
						IEEE80215_SCAN_ORPHAN,
						data.channels, data.duration);
				return 0;
			}
			/* Join trough mlme_association */
			cap.rxon = data.rxon;
			cap.addr_alloc = 1;
			cap.dev_type = data.as_router;
			cap.power_src = data.power;
			cap.cap_sec = data.mac_security;
			memcpy(&cap_info, &cap, 1);
			priv->mac->mlme_assoc_req(priv->mac, data.channel,
						data.panid,
						&data.addr, /* Coordinator address */
						cap_info,
						data.mac_security ? true : false);
		}
		break;
	case IEEE80215_SIOC_JOIN:
		priv->mac->mlme_get_req(priv->mac, IEEE80215_PANID);
		break;
	}
	return 0;
}

/*
 * IEEE80215.4 ioctl calls.
 */
static int ieee80215_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int rc = -ENOIOCTLCMD;
	struct sock *sk = sock->sk;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	/* Protocol layer */
	case TIOCOUTQ: {
		long amount = sk->sk_sndbuf -
			      atomic_read(&sk->sk_wmem_alloc);

		if (amount < 0)
			amount = 0;
		rc = put_user(amount, (int __user *)argp);
		break;
	}
	case TIOCINQ: {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
		long amount = 0;

		if (skb)
			amount = skb->len;
		rc = put_user(amount, (int __user *)argp);
		break;
	}
	case SIOCGSTAMP:
		rc = sock_get_timestamp(sk, argp);
		break;
	case SIOCGSTAMPNS:
		rc = sock_get_timestampns(sk, argp);
		break;
	/* Interface */
	default:
		rtnl_lock();
		rc = ieee80215_if_ioctl(sk, cmd, argp);
		rtnl_unlock();
		break;
	}
	return rc;
}

static int ieee80215_sock_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	// struct sock *sk = sock->sk;
	// int err;
	return 0;
}

static int ieee80215_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
	struct msghdr *msg, size_t size, int flags)
{
	return 0;
}

static const struct proto_ops SOCKOPS_WRAPPED(ieee80215_dgram_ops) = {
	.family		= PF_IEEE80215,
	.owner		= THIS_MODULE,
	.release	= ieee80215_sock_release,
	.bind		= sock_no_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,	/*ieee80215_sock_getname,*/
	.poll		= sock_no_poll,		/*datagram_poll,*/
	.ioctl		= ieee80215_sock_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.sendmsg	= ieee80215_sock_sendmsg,
	.recvmsg	= ieee80215_sock_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
};

SOCKOPS_WRAP(ieee80215_dgram, PF_IEEE80215);

/*
 * A device event has occurred. Watch for devices going down and
 * delete our use of them (iface and route).
 */
static int ieee80215_device_event(struct notifier_block *nb, unsigned long event,
			    void *ptr)
{
	struct net_device *dev = ptr;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

#if 0
	if (event == NETDEV_DOWN)
		/* Discard any use of this */
		ieee80215_dev_down(dev);
#endif

	return NOTIFY_DONE;
}


struct notifier_block ieee80215_notifier = {
	.notifier_call	= ieee80215_device_event,
};

/*
 * Create a socket. Initialise the socket, blank the addresses
 * set the state.
 */
static int ieee80215_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc = -ESOCKTNOSUPPORT;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)
		goto out;
	rc = -ENOMEM;
	sk = sk_alloc(net, PF_IEEE80215, GFP_KERNEL, &ieee80215_prot);
	if (!sk)
		goto out;
	rc = 0;
	sock->ops = &ieee80215_dgram_ops;
	sock_init_data(sock, sk);

	/* Checksums on by default */
	sock_set_flag(sk, SOCK_ZAPPED);
out:
	return rc;
}

static struct net_proto_family ieee80215_family_ops = {
	.family		= PF_IEEE80215,
	.create		= ieee80215_create,
	.owner		= THIS_MODULE,
};

static int __init af_ieee80215_init(void)
{
	int rc = -EINVAL;

	rc = proto_register(&ieee80215_prot, 1);
	if (rc)
		goto out;

	/* Tell SOCKET that we are alive */
	sock_register(&ieee80215_family_ops);
	dev_add_pack(&ieee80215_packet_type);

	rc = 0;
out:
	return rc;
}
static void af_ieee80215_remove(void)
{
	proto_unregister(&ieee80215_prot);
}

int ieee80215_net_rx(struct ieee80215_phy *phy, u8 *data, ssize_t len)
{
	struct sk_buff *skb = alloc_skb(len, GFP_ATOMIC);

	if(!skb) {
		return -ENOMEM;
	}
	pr_debug("%s\n", __FUNCTION__);
	if(!phy->dev) {
		pr_debug("orphane frame recieved\n");
		kfree_skb(skb);
		return -ENODEV;
	}

	/* All frames originate from master interface for now */
	skb->dev = phy->dev;
	skb->protocol = htons(ETH_P_IEEE80215);
	/* TODO look, how to do this without copying */
	memcpy(skb->data, data, len);
	skb_put(skb, len);
	DBG_DUMP(skb->data, skb->len);
	netif_rx(skb);
	return 0;
}
EXPORT_SYMBOL(ieee80215_net_rx);

int ieee80215_net_cmd(struct ieee80215_phy *phy, u8 command, u8 status, u8 data)
{
	char buf[4];
	pr_debug("%s\n", __FUNCTION__);
	buf[0] = 0;
	buf[1] = command;
	buf[2] = status;
	buf[3] = data;
	ieee80215_net_rx(phy, buf, 4);
	return 0;
}
EXPORT_SYMBOL(ieee80215_net_cmd);

module_init(af_ieee80215_init);
module_exit(af_ieee80215_remove);
MODULE_LICENSE("GPL");

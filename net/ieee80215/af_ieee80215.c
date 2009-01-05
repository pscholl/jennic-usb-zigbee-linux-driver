/* 
 * IEEE80215.4 socket interface
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
#include <linux/list.h>
#include <net/datalink.h>
#include <net/psnap.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/route.h>

#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/phy.h>

#define DBG_DUMP(data, len) { \
	int i; \
	pr_debug("file %s: function: %s: data: len %d:\n", __FILE__, __FUNCTION__, len); \
	for(i = 0; i < len; i++) {\
		pr_debug("%02x: %02x\n", i, (data)[i]); \
	} \
}

#if 0
static int recv_ack(ieee80215_mac_t *mac, struct sk_buff *ack)
{
#if 0
	struct sk_buff *msg;
	msg = skb_peek(&mac->to_network);
	if (!msg) {
		pr_debug("no frame pending, ignore ack\n");
		return 0;
	}
	if (!skb_to_mpdu(msg)->on_confirm) {
		pr_info("msg->on_confirm is NULL\n");
		BUG();
	}

	dbg_print(mac, 0, DBG_INFO,
		"ack seq num = %u, pending frame seq num = %u\n",
		skb_to_mpdu(ack)->mhr->seq, skb_to_mpdu(msg)->mhr->seq);

	if (skb_to_mpdu(ack)->mhr->seq != skb_to_mpdu(msg)->mhr->seq) {
		pr_debug("unexpected ACK\n");
		return 0;
	}

	ieee80215_dsn_inc(mac);
	cancel_delayed_work(&mac->ack_wait);

	pr_debug("ack->mhr->fc.pend = %u\n",
		skb_to_mpdu(ack)->mhr->fc.pend);

	skb_to_mpdu(msg)->mhr->fc.pend = skb_to_mpdu(ack)->mhr->fc.pend; /* hack */
	skb_to_mpdu(msg)->on_confirm(mac, msg, IEEE80215_PHY_SUCCESS);
	skb_unlink(msg, &mac->to_network);
	kfree_mpdu(skb_to_mpdu(msg));

	/* if we are retransmitting acknowledged frame, cancel retransmission (CCA) */
	cancel_delayed_work(&mac->csma_dwork);
#endif
	return 0;
}

static void ieee80215_net_parse_skb(struct ieee80215_mac *mac, struct sock *sk,
					struct sk_buff *skb)
{
	int state;
	ieee80215_mpdu_t *mpdu;
	struct ieee80215_netdev_priv *priv;
	u8 promiscuous_mode;
	mpdu = skb_to_mpdu(skb);
	BUG_ON(!mpdu);
	BUG_ON(!skb);
	BUG_ON(!skb->dev);
	if(skb->dev->master) {
		priv = netdev_priv(skb->dev);
		ieee80215_adjust_pointers(priv->mac, skb);
	} else {
		pr_debug("wrong interface to recieve skb from\n");
		kfree_mpdu(mpdu);
		return;
	}

	ieee80215_get_pib(mac, IEEE80215_PROMISCOUS_MODE, &promiscuous_mode);
	if (ieee80215_ignore_mpdu(priv->mac, skb)) {
		pr_debug("Ignoring frame\n");
		kfree_mpdu(mpdu);
		return;
	}
	if (IEEE80215_TYPE_ACK == mpdu->mhr->fc.type) {
		pr_debug("ACK received, seq: %d\n", mpdu->mhr->seq);
			mpdu->filtered = true;
			goto filtered;
	}
	if (ieee80215_filter_af(mac, skb) || !mpdu->filtered) {
		pr_info("Drop frame, it does not match filter rules\n");
		kfree_mpdu(mpdu);
		return;
	}
filtered:
	pr_debug("mpdu = 0x%p\n", mpdu);
	pr_debug("frame type = %d\n", mpdu->mhr->fc.type);
	switch (mpdu->mhr->fc.type) {
	case IEEE80215_TYPE_DATA:
		/* Git data frame, should queue it here */
		break;
	case IEEE80215_TYPE_ACK:
		recv_ack(mac, skb);
		break;
	case IEEE80215_TYPE_MAC_CMD:
		ieee80215_parse_cmd(mac, skb);
		break;
	case IEEE80215_TYPE_BEACON:
		ieee80215_parse_beacon(mac, skb);
		break;
	default:
		pr_debug("unexpected frame type\n");
		break;
	}
	if (mpdu->mhr->fc.ack_req && !mpdu->ack_send) {
		ieee80215_mpdu_t *ack;
		pr_debug("ACK required\n");
		if (!ieee80215_can_process_ack(mac, skb)) {
			pr_debug( "no time slice left, drop frame\n");
			kfree_mpdu(mpdu);
			return;
		}
		ack = ieee80215_create_ack(mac, skb);
		if (ack) {
#warning ieee80215_ack_confirm
			ack->on_confirm = ieee80215_ack_confirm;
			dev_queue_xmit(skb);
			ieee80215_net_set_trx_state(mac, IEEE80215_TX_ON, ieee80215_ack_perform);
		}
		return;
	}
	pr_debug("frame type = %d\n", mpdu->mhr->fc.type);
	if (mac->assoc_pending && IEEE80215_TYPE_MAC_CMD == mpdu->mhr->fc.type
		&& IEEE80215_ASSOCIATION_PERM == mpdu->p.g->cmd_id) {
		mac->assoc_pending = false;
		cancel_delayed_work(&mac->associate_timeout);
	}

	if (mac->poll_pending && IEEE80215_TYPE_DATA == mpdu->mhr->fc.type) {
		mac->poll_pending = false;
		cancel_delayed_work(&mac->poll_request);
#warning FIXME indication/confurm
#if 0
		_nhle(mac)->mlme_poll_confirm(_nhle(mac), IEEE80215_SUCCESS);
#endif
	}

	if (ieee80215_in_scanning(mac) || ieee80215_should_rxon(mac)) {
		state = IEEE80215_RX_ON;
	} else {
		state = IEEE80215_TRX_OFF;
	}
	ieee80215_net_set_trx_state(mac, state, NULL);
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
			if(!dev->master) /* copying from phy data */
				memcpy(&req.ifr_hwaddr.sa_data,
					&priv->mac->phy->dev_op->_64bit, sizeof(u64));
			else { /* Copying from device data */
				memcpy(&req.ifr_hwaddr.sa_data,
					dev->dev_addr, sizeof(u64));
			}

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
		if(!dev->master)
			memcpy(&priv->mac->phy->dev_op->_64bit,
				req.ifr_hwaddr.sa_data, sizeof(u64));
		else {
			memset(dev->dev_addr, 0, sizeof(dev->dev_addr));
			memcpy(dev->dev_addr,
				req.ifr_hwaddr.sa_data, sizeof(u64));
		}
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
		if(dev->master)
			return -EFAULT;
		if(!(mpriv->dev_ops->flags & IEEE80215_DEV_SINGLE))
			/* Here we're to alloc real new device */
			ieee80215_register_netdev(mpriv->dev_ops, mpriv->dev);
		{
			/* Enabling device */
			struct ieee80215_netdev_priv *subif;
			int rc = -EFAULT;
			list_for_each_entry(subif, &mpriv->interfaces, list) {
				if(!netif_running(subif->dev)) {
					memcpy(subif->dev->dev_addr,
							&data.addr._64bit, sizeof(u64));
					netif_start_queue(subif->dev);
					rc = 0;
				}
			}
			if(rc)
				return rc;
		}

		priv->mac->mlme_get_req(priv->mac, IEEE80215_PANID);
		break;
	}
	return 0;
}

#endif

static int ieee80215_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		sock->sk = NULL;
		sk->sk_prot->close(sk, 0);
	}
	return 0;
}
static int ieee80215_sock_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;

	return sk->sk_prot->sendmsg(iocb, sk, msg, len);
}

static int ieee80215_sock_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;

	if (sk->sk_prot->bind) {
		return sk->sk_prot->bind(sk, uaddr, addr_len);
	}

	return sock_no_bind(sock, uaddr, addr_len);
}

static int ieee80215_sock_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (uaddr->sa_family == AF_UNSPEC) {
		return sk->sk_prot->disconnect(sk, flags);
	}

	return sk->sk_prot->connect(sk, uaddr, addr_len);
}

static int ieee80215_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	switch(cmd)
	{
	case SIOCGSTAMP:
		return sock_get_timestamp(sk, (struct timeval __user *)arg);

	case SIOCGSTAMPNS:
		return sock_get_timestampns(sk, (struct timespec __user *)arg);
	default:
		if (!sk->sk_prot->ioctl)
			return -ENOIOCTLCMD;
		return sk->sk_prot->ioctl(sk, cmd, arg);
	}
}

static const struct proto_ops ieee80215_raw_ops = {
	.family		   = PF_IEEE80215,
	.owner		   = THIS_MODULE,
	.release	   = ieee80215_sock_release,
	.bind		   = ieee80215_sock_bind,
	.connect	   = ieee80215_sock_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = sock_no_getname,
	.poll		   = sock_no_poll,
	.ioctl		   = ieee80215_sock_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = sock_no_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = ieee80215_sock_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

static const struct proto_ops ieee80215_dgram_ops = {
	.family		   = PF_IEEE80215,
	.owner		   = THIS_MODULE,
	.release	   = ieee80215_sock_release,
	.bind		   = ieee80215_sock_bind,
	.connect	   = ieee80215_sock_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = sock_no_getname,
	.poll		   = sock_no_poll,
	.ioctl		   = ieee80215_sock_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = sock_no_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = ieee80215_sock_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};


/*
 * Create a socket. Initialise the socket, blank the addresses
 * set the state.
 */
static int ieee80215_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc;
	struct proto *proto;
	const struct proto_ops *ops;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	switch (sock->type) {
	case SOCK_RAW:
		proto = &ieee80215_raw_prot;
		ops = &ieee80215_raw_ops;
		break;
	case SOCK_DGRAM:
		proto = &ieee80215_dgram_prot;
		ops = &ieee80215_dgram_ops;
		break;
	default:
		rc = -ESOCKTNOSUPPORT;
		goto out;
	}

	rc = -ENOMEM;
	sk = sk_alloc(net, PF_IEEE80215, GFP_KERNEL, proto);
	if (!sk)
		goto out;
	rc = 0;

	sock->ops = ops;

	sock_init_data(sock, sk);
	// FIXME: sk->sk_destruct
	sk->sk_family = PF_IEEE80215;

	/* Checksums on by default */
	sock_set_flag(sk, SOCK_ZAPPED);

	if (sk->sk_prot->hash)
		sk->sk_prot->hash(sk);

	if (sk->sk_prot->init) {
		rc = sk->sk_prot->init(sk);
		if (rc)
			sk_common_release(sk);
	}
out:
	return rc;
}

static struct net_proto_family ieee80215_family_ops = {
	.family		= PF_IEEE80215,
	.create		= ieee80215_create,
	.owner		= THIS_MODULE,
};

static int ieee80215_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	DBG_DUMP(skb->data, skb->len);
	if(!netif_running(dev))
		return -ENODEV;
	pr_debug("got frame, type %d, dev %p\n", dev->type, dev);
	if (dev->type != ARPHRD_IEEE80215 || !net_eq(dev_net(dev), &init_net)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return ieee80215_dgram_deliver(dev, skb);
}


static struct packet_type ieee80215_packet_type = {
	.type = __constant_htons(ETH_P_IEEE80215),
	.func = ieee80215_rcv,
};

static int ieee80215_raw_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	DBG_DUMP(skb->data, skb->len);
	if(!netif_running(dev))
		return -ENODEV;
	pr_debug("got RAW frame, type %d, dev %p\n", dev->type, dev);
	if (dev->type != ARPHRD_IEEE80215_PHY || !net_eq(dev_net(dev), &init_net)) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return ieee80215_raw_deliver(dev, skb);
}


static struct packet_type ieee80215_raw_packet_type = {
	.type = __constant_htons(ETH_P_IEEE80215_MAC),
	.func = ieee80215_raw_rcv,
};

static int __init af_ieee80215_init(void)
{
	int rc = -EINVAL;

	rc = proto_register(&ieee80215_raw_prot, 1);
	if (rc)
		goto out;

	rc = proto_register(&ieee80215_dgram_prot, 1);
	if (rc)
		goto err_dgram;

	/* Tell SOCKET that we are alive */
	rc = sock_register(&ieee80215_family_ops);
	if (rc)
		goto err_sock;
	dev_add_pack(&ieee80215_raw_packet_type);
	dev_add_pack(&ieee80215_packet_type);

	rc = 0;
	goto out;

err_sock:
	proto_unregister(&ieee80215_dgram_prot);
err_dgram:
	proto_unregister(&ieee80215_raw_prot);
out:
	return rc;
}
static void af_ieee80215_remove(void)
{
	dev_remove_pack(&ieee80215_packet_type);
	dev_remove_pack(&ieee80215_raw_packet_type);
	sock_unregister(PF_IEEE80215);
	proto_unregister(&ieee80215_dgram_prot);
	proto_unregister(&ieee80215_raw_prot);
}

module_init(af_ieee80215_init);
module_exit(af_ieee80215_remove);
MODULE_LICENSE("GPL");


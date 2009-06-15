/*
 * ZigBee socket interface
 *
 * Copyright 2008, 2009 Siemens AG
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
 * Maxim Yu. Osipov <Maksim.Osipov@siemens.com>
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
#include <net/zigbee/af_zigbee.h>
#include <net/zigbee/nwk.h>

#define DBG_DUMP(data, len) { \
	int i; \
	pr_debug("file %s: function: %s: data: len %d:\n", __FILE__, __func__, len); \
	for (i = 0; i < len; i++) {\
		pr_debug("%02x: %02x\n", i, (data)[i]); \
	} \
}

static int zb_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		sock->sk = NULL;
		sk->sk_prot->close(sk, 0);
	}
	return 0;
}
static int zb_sock_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;

	return sk->sk_prot->sendmsg(iocb, sk, msg, len);
}

static int zb_sock_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;

	if (sk->sk_prot->bind)
		return sk->sk_prot->bind(sk, uaddr, addr_len);

	return sock_no_bind(sock, uaddr, addr_len);
}

static int zb_sock_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (uaddr->sa_family == AF_UNSPEC)
		return sk->sk_prot->disconnect(sk, flags);

	return sk->sk_prot->connect(sk, uaddr, addr_len);
}

#if 0
static int zb_dev_ioctl(struct sock *sk, struct ifreq __user *arg, unsigned int cmd)
{
	struct ifreq ifr;
	int ret = -EINVAL;
	struct net_device *dev;

	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		return -EFAULT;

	ifr.ifr_name[IFNAMSIZ-1] = 0;

	dev_load(sock_net(sk), ifr.ifr_name);
	dev = dev_get_by_name(sock_net(sk), ifr.ifr_name);
	if (dev->type == ARPHRD_ZIGBEE || dev->type == ARPHRD_ZIGBEE_PHY)
		ret = dev->do_ioctl(dev, &ifr, cmd);

	if (!ret && copy_to_user(arg, &ifr, sizeof(struct ifreq)))
		ret = -EFAULT;
	dev_put(dev);

	return ret;
}
#endif

static int zb_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;

	switch (cmd) {
	case SIOCGSTAMP:
		return sock_get_timestamp(sk, (struct timeval __user *)arg);
	case SIOCGSTAMPNS:
		return sock_get_timestampns(sk, (struct timespec __user *)arg);
#if 0
	case SIOCGIFADDR:
	case SIOCSIFADDR:
		return zb_dev_ioctl(sk, (struct ifreq __user *)arg, cmd);
#endif
	default:
		if (!sk->sk_prot->ioctl)
			return -ENOIOCTLCMD;
		return sk->sk_prot->ioctl(sk, cmd, arg);
	}
}

static const struct proto_ops zb_dgram_ops = {
	.family		   = PF_ZIGBEE,
	.owner		   = THIS_MODULE,
	.release	   = zb_sock_release,
	.bind		   = zb_sock_bind,
	.connect	   = zb_sock_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = sock_no_getname,
	.poll		   = datagram_poll,
	.ioctl		   = zb_sock_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = sock_no_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = zb_sock_sendmsg,
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
static int zb_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc;
	struct proto *proto;
	const struct proto_ops *ops;

	// FIXME: init_net
	if (net != &init_net)
		return -EAFNOSUPPORT;

	if (sock->type == SOCK_DGRAM) {
		proto = &zb_dgram_prot;
		ops = &zb_dgram_ops;
	}
	else {
		rc = -ESOCKTNOSUPPORT;
		goto out;
	}

	rc = -ENOMEM;
	sk = sk_alloc(net, PF_ZIGBEE, GFP_KERNEL, proto);
	if (!sk)
		goto out;
	rc = 0;

	sock->ops = ops;

	sock_init_data(sock, sk);
	// FIXME: sk->sk_destruct
	sk->sk_family = PF_ZIGBEE;

#if 0
	/* Checksums on by default */
	// FIXME:
	sock_set_flag(sk, SOCK_ZAPPED);

	// FIXME:
	if (sk->sk_prot->hash)
		sk->sk_prot->hash(sk);
#endif

	if (sk->sk_prot->init) {
		rc = sk->sk_prot->init(sk);
		if (rc)
			sk_common_release(sk);
	}
out:
	return rc;
}

static struct net_proto_family zb_family_ops = {
	.family		= PF_ZIGBEE,
	.create		= zb_create,
	.owner		= THIS_MODULE,
};

/* 
 * Main ZigBEE NWK receive routine.
 */
static int zb_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct nwkhdr *nwkh;
	u32 len;
	
	DBG_DUMP(skb->data, skb->len);
	pr_debug("got frame, type %d, dev %p\n", dev->type, dev);
	// FIXME: init_net
	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	zb_raw_deliver(dev, skb);

	if (skb->pkt_type != PACKET_OTHERHOST)
		return zb_dgram_deliver(dev, skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}


static struct packet_type zb_packet_type = {
	.type = __constant_htons(ETH_P_ZIGBEE),
	.func = zb_rcv,
};

static int __init af_zb_init(void)
{
	int rc = -EINVAL;

	rc = proto_register(&zb_dgram_prot, 1);
	if (rc)
		goto err;

	/* Tell SOCKET that we are alive */
	rc = sock_register(&zb_family_ops);

	if (rc)
		goto err;

	dev_add_pack(&zb_packet_type);

	rc = 0;
	goto out;

err:
	proto_unregister(&zb_dgram_prot);
out:
	return rc;
}

static void af_zb_remove(void)
{
	dev_remove_pack(&zb_packet_type);
	sock_unregister(PF_ZIGBEE);
	proto_unregister(&zb_dgram_prot);
}

module_init(af_zb_init);
module_exit(af_zb_remove);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_ZIGBEE);

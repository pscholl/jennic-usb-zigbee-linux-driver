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
#include <linux/termios.h>	/* For TIOCOUTQ/INQ */
#include <net/datalink.h>
#include <net/psnap.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/route.h>

#include <net/ieee80215/netdev.h>

static int ieee80215_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;

	if (dev->type != ARPHRD_IEEE80215 || !net_eq(dev_net(dev), &init_net)) {
		kfree_skb(skb);
		return 0;
	}

	/* What's wrong with skb->sk here??! */
	/* dev_queue_xmit(skb) */
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
#warning FIXME
#if 0
/* slapin: FIXME */
		ieee80215_destroy_socket(sk);
#endif
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

module_init(af_ieee80215_init);
module_exit(af_ieee80215_remove);
MODULE_LICENSE("GPL");

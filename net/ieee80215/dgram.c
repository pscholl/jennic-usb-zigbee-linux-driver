#include <linux/net.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>

#if 0
static HLIST_HEAD(raw_head);
static DEFINE_RWLOCK(raw_lock);

struct raw_sock {
	struct sock sk;
	int bound;
	int ifindex;
};

static inline struct raw_sock *raw_sk(const struct sock *sk)
{
	return (struct raw_sock *)sk;
}


static void raw_hash(struct sock *sk)
{
	write_lock_bh(&raw_lock);
	sk_add_node(sk, &raw_head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	write_unlock_bh(&raw_lock);
}

static void raw_unhash(struct sock *sk)
{
	write_lock_bh(&raw_lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	write_unlock_bh(&raw_lock);
}

static void raw_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

static int raw_bind(struct sock *sk, struct sockaddr *uaddr, int len)
{
	struct sockaddr_ieee80215 *addr = (struct sockaddr_ieee80215 *)uaddr;
	struct raw_sock *ro = raw_sk(sk);
	int ifindex = 0;
	int err = 0;

	if (len < sizeof(*addr))
		return -EINVAL;

	if (addr->family != AF_IEEE80215)
		return -EINVAL;

	lock_sock(sk);
	if (addr->ifindex) {
		struct net_device *dev;
		dev = dev_get_by_index(&init_net, addr->ifindex);

		if (!dev) {
			err = -ENODEV;
			goto out;
		}

		if (dev->type != ARPHRD_IEEE80215) {
			dev_put(dev);
			err = -ENODEV;
			goto out;
		}

		ifindex = dev->ifindex;
		dev_put(dev);
	} else if (addr->addr) {
		struct net_device *dev;
		rtnl_lock();
		dev = dev_getbyhwaddr(&init_net, ARPHRD_IEEE80215, (u8*)&addr->addr);
		dev_hold(dev);
		rtnl_unlock();

		if (!dev) {
			err = -ENODEV;
			goto out;
		}

		ifindex = dev->ifindex;
		dev_put(dev);
	}

	ro->ifindex = ifindex;
	ro->bound = !!ifindex;
out:
	release_sock(sk);

	return err;
}

static int raw_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t size)
{
	struct net_device *dev;
	unsigned mtu;
	struct sk_buff *skb;
	int err;

	if (msg->msg_flags & MSG_OOB) {
		pr_debug("msg->msg_flags = 0x%x\n", msg->msg_flags);
		return -EOPNOTSUPP;
	}

	dev = dev_getfirstbyhwtype(&init_net, ARPHRD_IEEE80215);
	if (!dev) {
		pr_debug("no dev\n");
		return -ENXIO;
	}
	mtu = dev->mtu;
	pr_debug("name = %s, mtu = %u\n", dev->name, mtu);

	if (size > mtu) {
		pr_debug("size = %u, mtu = %u\n", size, mtu);
		return -EINVAL;
	}

	skb = sock_alloc_send_skb(sk, size, msg->msg_flags & MSG_DONTWAIT,
				  &err);
	if (!skb) {
		dev_put(dev);
		return err;
	}

	err = memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size);
	if (err < 0) {
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}
	skb->dev = dev;
	skb->sk  = sk;

	err = dev_queue_xmit(skb);

	dev_put(dev);

	if (err)
		return err;

	return size;
}

static int raw_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len, int noblock, int flags, int *addr_len)
{
	size_t copied = 0;
	int err = -EOPNOTSUPP;
	struct sk_buff *skb;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err)
		goto done;

	sock_recv_timestamp(msg, sk, skb);

	if (flags & MSG_TRUNC)
		copied = skb->len;
done:
	skb_free_datagram(sk, skb);
out:
	if (err)
		return err;
	return copied;
}

static int raw_rcv_skb(struct sock * sk, struct sk_buff * skb)
{
	if (sock_queue_rcv_skb(sk, skb) < 0) {
		atomic_inc(&sk->sk_drops);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}

#endif

struct proto ieee80215_dgram_prot = {
	.name		= "IEEE-802.15.4-MAC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct sock),
//	.close		= raw_close,
//	.bind		= raw_bind,
//	.sendmsg	= raw_sendmsg,
//	.recvmsg	= raw_recvmsg,
//	.hash		= raw_hash,
//	.unhash		= raw_unhash,
};


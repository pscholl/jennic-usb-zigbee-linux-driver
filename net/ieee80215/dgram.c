#include <linux/net.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/list.h>
#include <linux/crc-itu-t.h>
#include <net/sock.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>

#if 0
static HLIST_HEAD(dgram_head);
static DEFINE_RWLOCK(dgram_lock);
#endif

struct dgram_sock {
	struct sock sk;
	int bound;
	int ifindex;
};

static inline struct dgram_sock *dgram_sk(const struct sock *sk)
{
	return (struct dgram_sock *)sk;
}


static void dgram_hash(struct sock *sk)
{
#if 0
	write_lock_bh(&dgram_lock);
	sk_add_node(sk, &dgram_head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	write_unlock_bh(&dgram_lock);
#endif
}

static void dgram_unhash(struct sock *sk)
{
#if 0
	write_lock_bh(&dgram_lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	write_unlock_bh(&dgram_lock);
#endif
}

static void dgram_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

static int dgram_bind(struct sock *sk, struct sockaddr *uaddr, int len)
{
	struct sockaddr_ieee80215 *addr = (struct sockaddr_ieee80215 *)uaddr;
	struct dgram_sock *ro = dgram_sk(sk);
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
		printk(KERN_ERR "idev: %s\n ", dev->name);

		if (!dev) {
			err = -ENODEV;
			goto out;
		}

		if (dev->type != ARPHRD_IEEE80215) {
			dev_put(dev);
			err = -ENODEV;
			goto out;
		}

		if (!dev->master) {
			dev_put(dev);
			err = -EINVAL;
			goto out;
		}

		ifindex = dev->ifindex;
		dev_put(dev);
	} else if (addr->addr) {
		struct net_device *dev;
		rtnl_lock();
		dev = dev_getbyhwaddr(&init_net, ARPHRD_IEEE80215, (u8*)&addr->addr);
		printk(KERN_ERR "adev: %s\n ", dev->name);
		if (dev)
			dev_hold(dev);
		rtnl_unlock();

		if (!dev) {
			err = -ENODEV;
			goto out;
		}

		if (!dev->master) {
			dev_put(dev);
			err = -EINVAL;
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

#if 0
static __inline__ u16 ieee80215_crc_itu(u8 *data, u8 len)
{
        u16 crc;
        u32 reg;

        reg = 0;
        crc = crc_itu_t(0, data, len-2);
        crc = crc_itu_t(crc, (u8*)&reg, 2);
        return crc;
}
#endif

static int dgram_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t size)
{
	struct net_device *dev;
	unsigned mtu;
	struct sk_buff *skb;
	struct dgram_sock *ro = dgram_sk(sk);
	int hh_len;
	int err;

	if (msg->msg_flags & MSG_OOB) {
		pr_debug("msg->msg_flags = 0x%x\n", msg->msg_flags);
		return -EOPNOTSUPP;
	}

	if (!ro->bound)
		dev = dev_getfirstbyhwtype(&init_net, ARPHRD_IEEE80215);
	else
		dev = dev_get_by_index(&init_net, ro->ifindex);
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

	// FIXME: extra_tx_headroom --- should be done from inside the mdev/dev via net_device setup
	// FIXME: tx alignment ???
	hh_len = LL_ALLOCATED_SPACE(dev);
	skb = sock_alloc_send_skb(sk, hh_len + 2 + 1 + 20 + size + 2, msg->msg_flags & MSG_DONTWAIT,
				  &err);
	if (!skb) {
		dev_put(dev);
		return err;
	}
	skb_reserve(skb, hh_len);

	skb_reset_mac_header(skb);

	do {
		u8 head[24] = {};
		int len = 0;
		head[len ++] = 1 /* data */
			| (1 << 5) /* ack req */
			;
		head[len++] = 0
			| (3 << (10 - 8)) /* dest addr = 64 */
			| (3 << (14 - 8)) /* source addr = 64 */
			;
		// FIXME: DSN
		head[len++] = 0xa5; /* seq number */
		memcpy(head+len, dev->dev_addr, dev->addr_len); len += dev->addr_len;
		memcpy(head+len, dev->dev_addr, dev->addr_len); len += dev->addr_len;
		memcpy(skb_put(skb, len), head, len);

	} while (0);

	skb_reset_network_header(skb);

	err = memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size);
	if (err < 0) {
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}
	{
		u16 crc = crc_itu_t(0, skb->data, skb->len);
		memcpy(skb_put(skb, 2), &crc, 2);
	}
	skb->dev = dev;
	skb->sk  = sk;
	skb->protocol = htons(ETH_P_IEEE80215);

	err = dev_queue_xmit(skb);

	dev_put(dev);

	if (err)
		return err;

	return size;
}

static int dgram_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
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

	// FIXME: skip headers if necessary ?!
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

static int dgram_rcv_skb(struct sock * sk, struct sk_buff * skb)
{
	if (sock_queue_rcv_skb(sk, skb) < 0) {
		atomic_inc(&sk->sk_drops);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}


struct proto ieee80215_dgram_prot = {
	.name		= "IEEE-802.15.4-MAC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct sock),
	.close		= dgram_close,
	.bind		= dgram_bind,
	.sendmsg	= dgram_sendmsg,
	.recvmsg	= dgram_recvmsg,
	.hash		= dgram_hash,
	.unhash		= dgram_unhash,
};


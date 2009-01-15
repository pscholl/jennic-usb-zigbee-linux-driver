#include <linux/net.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/list.h>
#include <linux/crc-itu-t.h>
#include <net/sock.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/mac_def.h>
#include <asm/ioctls.h>

static HLIST_HEAD(dgram_head);
static DEFINE_RWLOCK(dgram_lock);

struct dgram_sock {
	struct sock sk;

	int bound;
	struct ieee80215_addr src_addr;
	struct ieee80215_addr dst_addr;
};

static inline struct dgram_sock *dgram_sk(const struct sock *sk)
{
	return (struct dgram_sock *)sk;
}


static void dgram_hash(struct sock *sk)
{
	write_lock_bh(&dgram_lock);
	sk_add_node(sk, &dgram_head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	write_unlock_bh(&dgram_lock);
}

static void dgram_unhash(struct sock *sk)
{
	write_lock_bh(&dgram_lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	write_unlock_bh(&dgram_lock);
}

static int dgram_init(struct sock *sk)
{
	struct dgram_sock *ro = dgram_sk(sk);

	ro->dst_addr.addr_type = IEEE80215_ADDR_LONG;
	ro->dst_addr.pan_id = 0xffff;
	memset(&ro->dst_addr.hwaddr, 0xff, sizeof(ro->dst_addr.hwaddr));
	return 0;
}

static void dgram_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

static int dgram_bind(struct sock *sk, struct sockaddr *uaddr, int len)
{
	struct sockaddr_ieee80215 *addr = (struct sockaddr_ieee80215 *)uaddr;
	struct dgram_sock *ro = dgram_sk(sk);
	int err = 0;
	struct net_device *dev;

	ro->bound = 0;

	if (len < sizeof(*addr))
		return -EINVAL;

	if (addr->family != AF_IEEE80215)
		return -EINVAL;

	lock_sock(sk);

	dev = ieee80215_get_dev(sock_net(sk), &addr->addr);
	if (!dev) {
		err = -ENODEV;
		goto out;
	}

	if (dev->type != ARPHRD_IEEE80215) {
		err = -ENODEV;
		goto out_put;
	}

	memcpy(&ro->src_addr, &addr->addr, sizeof(struct ieee80215_addr));

	ro->bound = 1;
out_put:
	dev_put(dev);
out:
	release_sock(sk);

	return err;
}

static int dgram_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	{
		int amount = atomic_read(&sk->sk_wmem_alloc);
		return put_user(amount, (int __user *)arg);
	}

	case SIOCINQ:
	{
		struct sk_buff *skb;
		unsigned long amount;

		amount = 0;
		spin_lock_bh(&sk->sk_receive_queue.lock);
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb != NULL) {
			/*
			 * We will only return the amount
			 * of this packet since that is all
			 * that will be read.
			 */
			// FIXME: parse the header for more correct value
			amount = skb->len - (3+8+8);
		}
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		return put_user(amount, (int __user *)arg);
	}

	case IEEE80215_SIOC_NETWORK_DISCOVERY:
		return ioctl_network_discovery(sk, (struct ieee80215_user_data __user *) arg);
		break;
	case IEEE80215_SIOC_NETWORK_FORMATION:
		return ioctl_network_formation(sk, (struct ieee80215_user_data __user *) arg);
		break;
	case IEEE80215_SIOC_PERMIT_JOINING:
		return ioctl_permit_joining(sk, (struct ieee80215_user_data __user *) arg);
		break;
	case IEEE80215_SIOC_START_ROUTER:
		return ioctl_start_router(sk, (struct ieee80215_user_data __user *) arg);
		break;
	case IEEE80215_SIOC_JOIN:
		return ioctl_mac_join(sk, (struct ieee80215_user_data __user *) arg);
		break;
	case IEEE80215_SIOC_MAC_CMD:
		return ioctl_mac_cmd(sk, (struct ieee80215_user_data __user *) arg);
		
		break;
	}
	return -ENOIOCTLCMD;
}

// FIXME: autobind
static int dgram_connect(struct sock *sk, struct sockaddr *uaddr,
			int len)
{
	struct sockaddr_ieee80215 *addr = (struct sockaddr_ieee80215 *)uaddr;
	struct dgram_sock *ro = dgram_sk(sk);
	int err = 0;

	if (len < sizeof(*addr))
		return -EINVAL;

	if (addr->family != AF_IEEE80215)
		return -EINVAL;

	lock_sock(sk);

	if (!ro->bound) {
		err = -ENETUNREACH;
		goto out;
	}

	memcpy(&ro->dst_addr, &addr->addr, sizeof(struct ieee80215_addr));

out:
	release_sock(sk);
	return err;
}

static int dgram_disconnect(struct sock *sk, int flags)
{
	struct dgram_sock *ro = dgram_sk(sk);

	lock_sock(sk);

	ro->dst_addr.addr_type = IEEE80215_ADDR_LONG;
	memset(&ro->dst_addr.hwaddr, 0xff, sizeof(ro->dst_addr.hwaddr));

	release_sock(sk);

	return 0;
}

static int dgram_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t size)
{
	struct net_device *dev;
	unsigned mtu;
	struct sk_buff *skb;
	struct dgram_sock *ro = dgram_sk(sk);
	int err;
	struct ieee80215_priv *priv;

	if (msg->msg_flags & MSG_OOB) {
		pr_debug("msg->msg_flags = 0x%x\n", msg->msg_flags);
		return -EOPNOTSUPP;
	}

	if (!ro->bound)
		dev = dev_getfirstbyhwtype(sock_net(sk), ARPHRD_IEEE80215);
	else
		dev = ieee80215_get_dev(sock_net(sk), &ro->src_addr);

	if (!dev) {
		pr_debug("no dev\n");
		return -ENXIO;
	}
	mtu = dev->mtu;
	pr_debug("name = %s, mtu = %u\n", dev->name, mtu);

	skb = sock_alloc_send_skb(sk, LL_ALLOCATED_SPACE(dev) + size, msg->msg_flags & MSG_DONTWAIT,
				  &err);
	if (!skb) {
		dev_put(dev);
		return err;
	}
	skb_reserve(skb, LL_RESERVED_SPACE(dev));

	skb_reset_network_header(skb);

	err = dev_hard_header(skb, dev, ETH_P_IEEE80215, &ro->dst_addr, ro->bound ? &ro->src_addr : NULL, size);
	if (err < 0) {
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	skb_reset_mac_header(skb);

	err = memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size);
	if (err < 0) {
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}

	if (size > mtu) {
		pr_debug("size = %u, mtu = %u\n", size, mtu);
		return -EINVAL;
	}

	priv = netdev_priv(dev);

	if(!(priv->ops->flags & IEEE80215_OPS_OMIT_CKSUM))
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
	struct sk_buff *ackskb;
	if(MAC_CB_IS_ACKREQ(skb)) {
		u16 fc = IEEE80215_FC_TYPE_ACK;
		u8 * data;
		ackskb = alloc_skb(IEEE80215_ACK_LEN, GFP_ATOMIC);
		data = skb_put(ackskb, 3);
		data[0] = fc & 0xff;
		data[1] = (fc >> 8) & 0xff;
		data[2] = MAC_CB(skb)->seq;
		ackskb->dev = skb->dev;
		pr_debug("ACK frame to %s device", skb->dev->name);
		ackskb->protocol = htons(ETH_P_IEEE80215);
		pr_debug("%s(): flags %02x\n", __FUNCTION__,
				MAC_CB(skb)->flags);
		/* FIXME */
		dev_queue_xmit(ackskb);
	}
	if (sock_queue_rcv_skb(sk, skb) < 0) {
		atomic_inc(&sk->sk_drops);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}

int ieee80215_dgram_deliver(struct net_device *dev, struct sk_buff *skb)
{
	struct sock *sk, *prev = NULL;
	struct hlist_node*node;
	int ret = NET_RX_SUCCESS;

	read_lock(&dgram_lock);
	sk_for_each(sk, node, &dgram_head) {
		struct dgram_sock *ro = dgram_sk(sk);
		if (!ro->bound ||
		  (ro->src_addr.addr_type == IEEE80215_ADDR_LONG &&
		     !memcmp(ro->src_addr.hwaddr, dev->dev_addr, IEEE80215_ADDR_LEN)) ||
		  (ro->src_addr.addr_type == IEEE80215_ADDR_SHORT &&
		     ieee80215_dev_get_pan_id(dev) == ro->src_addr.pan_id &&
		     ieee80215_dev_get_short_addr(dev) == ro->src_addr.short_addr)) {
			if (prev) {
				struct sk_buff *clone;
				clone = skb_clone(skb, GFP_ATOMIC);
				if (clone)
					dgram_rcv_skb(prev, clone);
			}

			prev = sk;
		}
	}

	if (prev)
		dgram_rcv_skb(prev, skb);
	else {
		kfree_skb(skb);
		ret = NET_RX_DROP;
	}

	read_unlock(&dgram_lock);

	return ret;
}

struct proto ieee80215_dgram_prot = {
	.name		= "IEEE-802.15.4-MAC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct sock),
	.init		= dgram_init,
	.close		= dgram_close,
	.bind		= dgram_bind,
	.sendmsg	= dgram_sendmsg,
	.recvmsg	= dgram_recvmsg,
	.hash		= dgram_hash,
	.unhash		= dgram_unhash,
	.connect	= dgram_connect,
	.disconnect	= dgram_disconnect,
	.ioctl		= dgram_ioctl,
};


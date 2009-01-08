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
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>

static int ieee80215_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv;
	priv = netdev_priv(dev);
	skb->iif = dev->ifindex;
	skb->dev = priv->hw->master;
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;

	dev->trans_start = jiffies;
	dev_queue_xmit(skb);

	return 0;
}

static int ieee80215_slave_open(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv;
	priv = netdev_priv(dev);
	netif_start_queue(dev);
	return 0;
}

static int ieee80215_slave_close(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv;
	netif_stop_queue(dev);
	priv = netdev_priv(dev);
	netif_stop_queue(dev);
	return 0;
}

static struct net_device_stats *ieee80215_get_stats(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

static int ieee80215_slave_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (netif_running(dev))
		return -EBUSY;
	// FIXME: validate addr
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}

static int ieee80215_header_create(struct sk_buff *skb, struct net_device *dev,
			   unsigned short type, const void *daddr,
			   const void *saddr, unsigned len)
{
	u8 head[24] = {};
	int pos = 0;
	head[pos ++] = 1 /* data */
		| (1 << 5) /* ack req */
		;
	head[pos++] = 0
		| (3 << (10 - 8)) /* dest addr = 64 */
		| (3 << (14 - 8)) /* source addr = 64 */
		;
	// FIXME: DSN
	head[pos++] = 0xa5; /* seq number */
	if (!saddr)
		saddr = dev->dev_addr;
	memcpy(head+pos, saddr, dev->addr_len); pos += dev->addr_len;
	if (daddr)
		memcpy(head+pos, daddr, IEEE80215_ADDR_LEN); pos += IEEE80215_ADDR_LEN;

	memcpy(skb_push(skb, pos), head, pos);

	return pos;
}

static int ieee80215_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	const char *hdr = skb_mac_header(skb);
	memcpy(haddr, hdr + 3, IEEE80215_ADDR_LEN);
	return IEEE80215_ADDR_LEN;
}

static struct header_ops ieee80215_header_ops = {
	.create		= ieee80215_header_create,
	.parse		= ieee80215_header_parse,
};

static void ieee80215_netdev_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE80215_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE80215_ADDR_LEN);
	dev->features		= NETIF_F_NO_CSUM;
	dev->hard_header_len	= 2 + 1 + 20 + 14;
	dev->header_ops		= &ieee80215_header_ops;
	dev->needed_tailroom	= 2; // FCS
	dev->set_mac_address	= ieee80215_slave_mac_addr;
	dev->mtu		= 127;
	dev->tx_queue_len	= 10;
	dev->type		= ARPHRD_IEEE80215;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;
}

int ieee80215_add_slave(struct ieee80215_dev *hw, const u8 *addr)
{
	struct net_device *dev;
	struct ieee80215_netdev_priv *priv;

	dev = alloc_netdev(sizeof(struct ieee80215_netdev_priv),
			"wpan%d", ieee80215_netdev_setup);
	if(!dev) {
		printk(KERN_ERR "Failure to initialize IEEE80215 device\n");
		return -ENOMEM;
	}
	priv = netdev_priv(dev);
	priv->dev = dev;
	priv->hw = ieee80215_to_priv(hw);
	memcpy(dev->dev_addr, addr, dev->addr_len);
	memcpy(dev->perm_addr, dev->dev_addr, dev->addr_len);
	dev->open = ieee80215_slave_open;
	dev->stop = ieee80215_slave_close;
	dev->hard_start_xmit = ieee80215_net_xmit;
	dev->get_stats = ieee80215_get_stats;
	dev->priv_flags = IFF_SLAVE_INACTIVE;

	rtnl_lock();
	dev_hold(priv->hw->master);
	rtnl_unlock();

	dev->needed_headroom = priv->hw->master->needed_headroom;

	list_add_tail_rcu(&priv->list, &ieee80215_to_priv(hw)->slaves);

	register_netdev(dev);

	return dev->ifindex;
}

void ieee80215_del_slave(struct ieee80215_dev *hw, struct ieee80215_netdev_priv *ndp)
{
	struct net_device *dev = ndp->dev;
	rtnl_lock();
	dev_put(ndp->hw->master);
	rtnl_unlock();
	unregister_netdev(ndp->dev);
	list_del_rcu(&ndp->list);
	free_netdev(dev);
}

void ieee80215_subif_rx(struct ieee80215_dev *hw, struct sk_buff *skb)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(hw);

	struct ieee80215_netdev_priv *ndp;
	unsigned char *head;
	unsigned int head_off, tail_off;

	if (skb->len < /*3 + 4 + 2*/ 3 + 8 + 8 + 2)
		return;

	/* FIXME: We currently support only simple 64bit addressing */
	head_off = 3 + IEEE80215_ADDR_LEN + IEEE80215_ADDR_LEN;
	head = skb->data;
	skb_pull(skb, head_off);
//	DBG_DUMP(head+3+IEEE80215_ADDR_LEN, 8);

	// FIXME: check CRC if necessary
	tail_off = 2;
	skb_trim(skb, skb->len - tail_off); // CRC

	rcu_read_lock();

	list_for_each_entry_rcu(ndp, &priv->slaves, list)
	{
		struct sk_buff *skb2 = NULL;
//		DBG_DUMP(ndp->dev->dev_addr, 8);

		skb2 = skb_clone(skb, GFP_ATOMIC);

		if (!memcmp(head + 3 + IEEE80215_ADDR_LEN , ndp->dev->dev_addr, IEEE80215_ADDR_LEN))
			skb2->pkt_type = PACKET_HOST;
		else if (!memcmp(head + 3 + IEEE80215_ADDR_LEN , ndp->dev->broadcast, IEEE80215_ADDR_LEN))
			skb2->pkt_type = PACKET_BROADCAST;
		else
			skb2->pkt_type = PACKET_OTHERHOST;

		skb2->dev = ndp->dev;
		netif_rx(skb2);
	}

	rcu_read_unlock();

	skb_push(skb, head_off);
	skb_put(skb, tail_off);

}

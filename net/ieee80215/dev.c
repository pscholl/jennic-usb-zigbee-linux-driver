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
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/mac_struct.h>
#include <net/ieee80215/mac_def.h>

struct ieee80215_netdev_priv {
	struct list_head list;
	struct ieee80215_priv *hw;
	struct net_device *dev;
	struct net_device_stats stats;
	struct ieee80215_mac mac;

	__le16 pan_id;
	__le16 short_addr;
};

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

static int ieee80215_slave_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ieee80215_netdev_priv * priv = netdev_priv(dev);
	struct sockaddr_ieee80215 *sa = (struct sockaddr_ieee80215 *)&ifr->ifr_addr;
	switch (cmd) {
	case SIOCGIFADDR:
		if (priv->pan_id == IEEE80215_PANID_BROADCAST || priv->short_addr == IEEE80215_ADDR_BROADCAST)
			return -EADDRNOTAVAIL;

		sa->family = AF_IEEE80215;
		sa->addr.addr_type = IEEE80215_ADDR_SHORT;
		sa->addr.pan_id = priv->pan_id;
		sa->addr.short_addr = priv->short_addr;
		return 0;
	case SIOCSIFADDR:
		dev_warn(&dev->dev, "Using DEBUGing ioctl SIOCSIFADDR isn't recommened!\n");
		if (sa->family != AF_IEEE80215 || sa->addr.addr_type != IEEE80215_ADDR_SHORT ||
			sa->addr.pan_id == IEEE80215_PANID_BROADCAST || sa->addr.short_addr == IEEE80215_ADDR_BROADCAST || sa->addr.short_addr == IEEE80215_ADDR_UNDEF)
			return -EINVAL;

		priv->pan_id = sa->addr.pan_id;
		priv->short_addr = sa->addr.short_addr;
		return 0;
	}
	return -ENOIOCTLCMD;
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
			   unsigned short type, const void *_daddr,
			   const void *_saddr, unsigned len)
{
	u8 head[24] = {};
	int pos = 0;

	u16 fc;
	const struct ieee80215_addr *saddr = _saddr;
	const struct ieee80215_addr *daddr = _daddr;
	struct ieee80215_addr dev_addr;
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);

	fc = (IEEE80215_FC_TYPE_DATA << IEEE80215_FC_TYPE_SHIFT)
		| IEEE80215_FC_ACK_REQ;

	pos = 2;

	// FIXME: DSN
	head[pos++] = 0xa5;

	if (!daddr)
		return -EINVAL;

	if (!saddr) {
		if (priv->short_addr == IEEE80215_ADDR_BROADCAST || priv->short_addr == IEEE80215_ADDR_UNDEF) {
			dev_addr.addr_type = IEEE80215_ADDR_LONG;
			memcpy(dev_addr.hwaddr, dev->dev_addr, IEEE80215_ADDR_LEN);
		} else {
			dev_addr.addr_type = IEEE80215_ADDR_SHORT;
			dev_addr.short_addr = priv->short_addr;
		}

		dev_addr.pan_id = priv->pan_id;
		saddr = &dev_addr;
	}

	if (saddr->addr_type != IEEE80215_ADDR_NONE) {
		fc |= (saddr->addr_type << IEEE80215_FC_SAMODE_SHIFT);

		if ((saddr->pan_id == daddr->pan_id) && (saddr->pan_id != IEEE80215_PANID_BROADCAST))
			fc |= IEEE80215_FC_INTRA_PAN; /* PANID compression/ intra PAN */
		else {
			head[pos++] = saddr->pan_id & 0xff;
			head[pos++] = saddr->pan_id >> 8;
		}

		if (saddr->addr_type == IEEE80215_ADDR_SHORT) {
			head[pos++] = saddr->short_addr & 0xff;
			head[pos++] = saddr->short_addr >> 8;
		} else {
			memcpy(head + pos, saddr->hwaddr, IEEE80215_ADDR_LEN);
			pos += IEEE80215_ADDR_LEN;
		}
	}

	if (daddr->addr_type != IEEE80215_ADDR_NONE) {
		fc |= (daddr->addr_type << IEEE80215_FC_DAMODE_SHIFT);

		head[pos++] = daddr->pan_id & 0xff;
		head[pos++] = daddr->pan_id >> 8;

		if (daddr->addr_type == IEEE80215_ADDR_SHORT) {
			head[pos++] = daddr->short_addr & 0xff;
			head[pos++] = daddr->short_addr >> 8;
		} else {
			memcpy(head + pos, daddr->hwaddr, IEEE80215_ADDR_LEN);
			pos += IEEE80215_ADDR_LEN;
		}
	}

	head[0] = fc;
	head[1] = fc >> 8;

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
	int err;

	ASSERT_RTNL();

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
	dev->do_ioctl = ieee80215_slave_ioctl;

	priv->pan_id = IEEE80215_PANID_DEF;
	priv->short_addr = IEEE80215_SHORT_ADDRESS_DEF;

	dev_hold(priv->hw->master);

	dev->needed_headroom = priv->hw->master->needed_headroom;

	list_add_tail_rcu(&priv->list, &ieee80215_to_priv(hw)->slaves);
	/*
	 * If the name is a format string the caller wants us to do a
	 * name allocation.
	 */
	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto out;
	}

	err = register_netdevice(dev);
	if(err < 0)
		goto out;

	return dev->ifindex;
out:
	return err;
}
EXPORT_SYMBOL(ieee80215_add_slave);

static void __ieee80215_del_slave(struct ieee80215_netdev_priv *ndp)
{
	struct net_device *dev = ndp->dev;
	rtnl_lock();
	dev_put(ndp->hw->master);
	rtnl_unlock();
	unregister_netdev(ndp->dev);
	list_del_rcu(&ndp->list);
	free_netdev(dev);
}

void ieee80215_drop_slaves(struct ieee80215_dev *hw)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(hw);
	struct ieee80215_netdev_priv *ndp;

	rcu_read_lock();
	list_for_each_entry_rcu(ndp, &priv->slaves, list)
		__ieee80215_del_slave(ndp);
	rcu_read_unlock();
}
EXPORT_SYMBOL(ieee80215_drop_slaves);

void ieee80215_subif_rx(struct ieee80215_dev *hw, struct sk_buff *skb)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(hw);

	struct ieee80215_netdev_priv *ndp;
	unsigned char *head;
	unsigned int tail_off;

	u16 fc;

	/* FIXME: need to have parameter in hw to set if we have hardware CRC
	 * and change this number according to that */

	if (skb->len < 3) {
		pr_debug("%s(): got too short frame\n", __FUNCTION__);
		return;
	}

	pr_debug("%s()\n", __FUNCTION__);

	head = skb->data;
	skb_pull(skb, 3);

	fc = head[0] | (head[1] << 8);

	printk("%s: %04x dsn%02x\n", __func__, fc, head[2]);

	MAC_CB(skb)->flags = IEEE80215_FC_TYPE(fc);

	if(fc & IEEE80215_FC_ACK_REQ) {
		pr_debug("%s(): ACKNOWLEDGE required\n", __FUNCTION__);
		MAC_CB(skb)->flags |= MAC_CB_FLAG_ACKREQ;
	}

	if(fc & IEEE80215_FC_SECEN)
		MAC_CB(skb)->flags |= MAC_CB_FLAG_SECEN;
	/* TODO */
	if(MAC_CB_IS_SECEN(skb)) {
		pr_info("security support is not implemented, dropping frame\n");
		kfree_skb(skb);
		return;
	}

	MAC_CB(skb)->sa.addr_type =
			(fc & IEEE80215_FC_SAMODE_MASK) >> IEEE80215_FC_SAMODE_SHIFT;

	if(MAC_CB(skb)->sa.addr_type == IEEE80215_ADDR_NONE)
		pr_debug("%s(): src addr_type is NONE\n", __FUNCTION__);

	if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_NONE) {
		pr_debug("%s(): got src non-NONE address\n", __FUNCTION__);
		if (!(fc & IEEE80215_FC_INTRA_PAN)) { // ! panid compress
			MAC_CB(skb)->sa.pan_id = skb->data[0] | (skb->data[1] << 8);
			skb_pull(skb, 2);
			pr_debug("%s(): src IEEE80215_FC_INTRA_PAN\n", __FUNCTION__);
		}

		if (MAC_CB(skb)->sa.addr_type == IEEE80215_ADDR_SHORT) {
			MAC_CB(skb)->sa.short_addr = skb->data[0] | (skb->data[1] << 8);
			skb_pull(skb, 2);
			pr_debug("%s(): src IEEE80215_ADDR_SHORT\n", __FUNCTION__);
		} else {
			memcpy(MAC_CB(skb)->sa.hwaddr, skb->data, IEEE80215_ADDR_LEN);
			skb_pull(skb, IEEE80215_ADDR_LEN);
			pr_debug("%s(): src hardware addr\n", __FUNCTION__);
		}
	}

	MAC_CB(skb)->da.addr_type = (fc & IEEE80215_FC_DAMODE_MASK) >> IEEE80215_FC_DAMODE_SHIFT;
	if(MAC_CB(skb)->da.addr_type == IEEE80215_ADDR_NONE)
		pr_debug("%s(): dst addr_type is NONE\n", __FUNCTION__);

	if (MAC_CB(skb)->da.addr_type != IEEE80215_ADDR_NONE) {
		if (fc & IEEE80215_FC_INTRA_PAN) { // ! panid compress
			MAC_CB(skb)->sa.pan_id = skb->data[0] | (skb->data[1] << 8);
			pr_debug("%s(): src PAN address %04x\n",
					__FUNCTION__, MAC_CB(skb)->sa.pan_id);
		}
		MAC_CB(skb)->da.pan_id = skb->data[0] | (skb->data[1] << 8);
		skb_pull(skb, 2);
		pr_debug("%s(): dst PAN address %04x\n",
				__FUNCTION__, MAC_CB(skb)->da.pan_id);

		if (MAC_CB(skb)->da.addr_type == IEEE80215_ADDR_SHORT) {
			MAC_CB(skb)->da.short_addr = skb->data[0] | (skb->data[1] << 8);
			skb_pull(skb, 2);
			pr_debug("%s(): dst SHORT address %04x\n",
					__FUNCTION__, MAC_CB(skb)->da.short_addr);

		} else {
			memcpy(MAC_CB(skb)->da.hwaddr, skb->data, IEEE80215_ADDR_LEN);
			skb_pull(skb, IEEE80215_ADDR_LEN);
			pr_debug("%s(): dst hardware addr\n", __FUNCTION__);
		}
	}

	// FIXME: check CRC if necessary
	tail_off = 2;
	skb_trim(skb, skb->len - tail_off); // CRC

	rcu_read_lock();

	list_for_each_entry_rcu(ndp, &priv->slaves, list)
	{
		struct sk_buff *skb2 = NULL;

		skb2 = skb_clone(skb, GFP_ATOMIC);

		switch (MAC_CB(skb2)->da.addr_type) {
		case IEEE80215_ADDR_NONE:
			// FIXME: check if we are PAN coordinator :)
			skb2->pkt_type = PACKET_OTHERHOST;
			break;
		case IEEE80215_ADDR_LONG:
			if (MAC_CB(skb2)->da.pan_id != ndp->pan_id && MAC_CB(skb2)->da.pan_id != IEEE80215_PANID_BROADCAST)
				skb2->pkt_type = PACKET_OTHERHOST;
			else if (!memcmp(MAC_CB(skb2)->da.hwaddr, ndp->dev->dev_addr, IEEE80215_ADDR_LEN))
				skb2->pkt_type = PACKET_HOST;
			else if (!memcmp(MAC_CB(skb2)->da.hwaddr, ndp->dev->broadcast, IEEE80215_ADDR_LEN)) // FIXME: is this correct?
				skb2->pkt_type = PACKET_BROADCAST;
			else
				skb2->pkt_type = PACKET_OTHERHOST;
			break;
		case IEEE80215_ADDR_SHORT:
			if (MAC_CB(skb2)->da.pan_id != ndp->pan_id && MAC_CB(skb2)->da.pan_id != IEEE80215_PANID_BROADCAST)
				skb2->pkt_type = PACKET_OTHERHOST;
			else if (MAC_CB(skb2)->da.short_addr == ndp->short_addr)
				skb2->pkt_type = PACKET_HOST;
			else if (MAC_CB(skb2)->da.short_addr == IEEE80215_ADDR_BROADCAST)
				skb2->pkt_type = PACKET_BROADCAST;
			else
				skb2->pkt_type = PACKET_OTHERHOST;
			break;
		}

		skb2->dev = ndp->dev;
		pr_debug("%s Getting packet via slave interface %s\n",
				__FUNCTION__, skb2->dev->name);
		netif_rx(skb2);
	}

	rcu_read_unlock();

	skb_push(skb, skb->data - head);
	skb_put(skb, tail_off);

}

struct net_device *ieee80215_get_dev(struct net *net, struct ieee80215_addr *addr)
{
	struct net_device *dev = NULL;

	switch (addr->addr_type) {
	case IEEE80215_ADDR_LONG:
		rtnl_lock();
		dev = dev_getbyhwaddr(net, ARPHRD_IEEE80215, addr->hwaddr);
		if (dev)
			dev_hold(dev);
		rtnl_unlock();
		break;
	case IEEE80215_ADDR_SHORT:
		if (addr->pan_id != 0xffff && addr->short_addr != IEEE80215_ADDR_UNDEF && addr->short_addr != 0xffff) {
			struct net_device *tmp;

			rtnl_lock();

			for_each_netdev(net, tmp) {
				if (tmp->type == ARPHRD_IEEE80215) {
					struct ieee80215_netdev_priv *priv = netdev_priv(tmp);
					if (priv->pan_id == addr->pan_id && priv->short_addr == addr->short_addr) {
						dev = tmp;
						dev_hold(dev);
						break;
					}
				}
			}

			rtnl_unlock();
		}
		break;
	default:
		pr_warning("Unsupported ieee80215 address type: %d\n", addr->addr_type);
		break;
	}

	return dev;
}

struct ieee80215_mac * ieee80215_get_mac_bydev(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv;
	priv = netdev_priv(dev);
	BUG_ON(!priv);
	return &priv->mac;
}
EXPORT_SYMBOL(ieee80215_get_mac_bydev);

u16 ieee80215_dev_get_pan_id(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	return priv->pan_id;
}

u16 ieee80215_dev_get_short_addr(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	return priv->short_addr;
}


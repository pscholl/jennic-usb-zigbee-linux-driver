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
#include <linux/notifier.h>
#include <linux/random.h>
#include <net/datalink.h>
#include <net/psnap.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/route.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/crc.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/mac_def.h>
#include <net/ieee80215/beacon.h>
#include <net/ieee80215/beacon_hash.h>

struct ieee80215_netdev_priv {
	struct list_head list;
	struct ieee80215_priv *hw;
	struct net_device *dev;
	struct net_device_stats stats;

	__le16 pan_id;
	__le16 short_addr;

	/* This one is used to provide notifications */
	struct blocking_notifier_head events;
};

static int ieee80215_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv;
	priv = netdev_priv(dev);

	if (!(priv->hw->hw.flags & IEEE80215_OPS_OMIT_CKSUM)) {
		u16 crc = ieee80215_crc(0, skb->data, skb->len);
		u8 *data = skb_put(skb, 2);
		data[0] = crc & 0xff;
		data[1] = crc >> 8;
	}
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
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);
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

	fc = MAC_CB_TYPE(skb);
	if (MAC_CB_IS_ACKREQ(skb))
		fc |= IEEE80215_FC_ACK_REQ;

	pos = 2;

	head[pos++] = MAC_CB(skb)->seq; /* DSN/BSN */

	if (!daddr)
		return -EINVAL;

	if (!saddr) {
		if (priv->short_addr == IEEE80215_ADDR_BROADCAST || priv->short_addr == IEEE80215_ADDR_UNDEF || priv->pan_id == IEEE80215_PANID_BROADCAST) {
			dev_addr.addr_type = IEEE80215_ADDR_LONG;
			memcpy(dev_addr.hwaddr, dev->dev_addr, IEEE80215_ADDR_LEN);
		} else {
			dev_addr.addr_type = IEEE80215_ADDR_SHORT;
			dev_addr.short_addr = priv->short_addr;
		}

		dev_addr.pan_id = priv->pan_id;
		saddr = &dev_addr;
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

	head[0] = fc;
	head[1] = fc >> 8;

	memcpy(skb_push(skb, pos), head, pos);

	return pos;
}

static int ieee80215_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	const u8 *hdr = skb_mac_header(skb), *tail = skb_tail_pointer(skb);
	struct ieee80215_addr *addr = (struct ieee80215_addr *)haddr;
	u16 fc;
	int da_type;

	if (hdr + 3 > tail)
		goto malformed;

	fc = hdr[0] | (hdr[1] << 8);

	hdr += 3;

	da_type = IEEE80215_FC_DAMODE(fc);
	addr->addr_type = IEEE80215_FC_SAMODE(fc);

	switch (da_type) {
	case IEEE80215_ADDR_NONE:
		if (fc & IEEE80215_FC_INTRA_PAN)
			goto malformed;
		break;

	case IEEE80215_ADDR_LONG:
		if (hdr + 2 > tail)
			goto malformed;
		if (fc & IEEE80215_FC_INTRA_PAN) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + IEEE80215_ADDR_LEN > tail)
			goto malformed;
		hdr += IEEE80215_ADDR_LEN;
		break;

	case IEEE80215_ADDR_SHORT:
		if (hdr + 2 > tail)
			goto malformed;
		if (fc & IEEE80215_FC_INTRA_PAN) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + 2 > tail)
			goto malformed;
		hdr += 2;
		break;

	default:
		goto malformed;

	}

	switch (addr->addr_type) {
	case IEEE80215_ADDR_NONE:
		break;

	case IEEE80215_ADDR_LONG:
		if (hdr + 2 > tail)
			goto malformed;
		if (!(fc & IEEE80215_FC_INTRA_PAN)) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + IEEE80215_ADDR_LEN > tail)
			goto malformed;
		memcpy(addr->hwaddr, hdr, IEEE80215_ADDR_LEN);
		hdr += IEEE80215_ADDR_LEN;
		break;

	case IEEE80215_ADDR_SHORT:
		if (hdr + 2 > tail)
			goto malformed;
		if (!(fc & IEEE80215_FC_INTRA_PAN)) {
			addr->pan_id = hdr[0] | (hdr[1] << 8);
			hdr += 2;
		}

		if (hdr + 2 > tail)
			goto malformed;
		addr->short_addr = hdr[0] | (hdr[1] << 8);
		hdr += 2;
		break;

	default:
		goto malformed;

	}

	return sizeof(struct ieee80215_addr);

malformed:
	pr_debug("malformed packet\n");
	return 0;
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
	dev->needed_tailroom	= 2; /* FCS */
	dev->set_mac_address	= ieee80215_slave_mac_addr;
	dev->mtu		= 127;
	dev->tx_queue_len	= 10;
	dev->type		= ARPHRD_IEEE80215;
	dev->flags		= IFF_NOARP | IFF_BROADCAST;
	dev->watchdog_timeo	= 0;
}

static void ieee80215_init_seq(struct ieee80215_priv *priv)
{
	get_random_bytes(&priv->bsn, 1);
	get_random_bytes(&priv->dsn, 1);
}

int ieee80215_add_slave(struct ieee80215_dev *hw, const u8 *addr)
{
	struct net_device *dev;
	struct ieee80215_netdev_priv *priv;
	struct ieee80215_priv *ipriv = ieee80215_to_priv(hw);
	int err;

	ASSERT_RTNL();

	dev = alloc_netdev(sizeof(struct ieee80215_netdev_priv),
			"wpan%d", ieee80215_netdev_setup);
	if (!dev) {
		printk(KERN_ERR "Failure to initialize IEEE80215 device\n");
		return -ENOMEM;
	}
	priv = netdev_priv(dev);
	priv->dev = dev;
	priv->hw = ieee80215_to_priv(hw);
	ieee80215_init_seq(priv->hw);
	BLOCKING_INIT_NOTIFIER_HEAD(&priv->events);
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

	spin_lock(&ieee80215_to_priv(hw)->slaves_lock);
	list_add_tail(&priv->list, &ieee80215_to_priv(hw)->slaves);
	spin_unlock(&ieee80215_to_priv(hw)->slaves_lock);
	/*
	 * If the name is a format string the caller wants us to do a
	 * name allocation.
	 */
	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto out;
	}

	SET_NETDEV_DEV(dev, &ipriv->master->dev);

	err = register_netdevice(dev);
	if (err < 0)
		goto out;

	return dev->ifindex;
out:
	return err;
}
EXPORT_SYMBOL(ieee80215_add_slave);

static void __ieee80215_del_slave(struct ieee80215_netdev_priv *ndp)
{
	struct net_device *dev = ndp->dev;
	dev_put(ndp->hw->master);
	unregister_netdev(ndp->dev);

	spin_lock(&ndp->hw->slaves_lock);
	list_del(&ndp->list);
	spin_unlock(&ndp->hw->slaves_lock);

	free_netdev(dev);
}

void ieee80215_drop_slaves(struct ieee80215_dev *hw)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(hw);
	struct ieee80215_netdev_priv *ndp, *next;

	spin_lock(&priv->slaves_lock);
	list_for_each_entry_safe(ndp, next, &priv->slaves, list) {
		spin_unlock(&priv->slaves_lock);
		__ieee80215_del_slave(ndp);
		spin_lock(&priv->slaves_lock);
	}
	spin_unlock(&priv->slaves_lock);
}
EXPORT_SYMBOL(ieee80215_drop_slaves);

static int ieee80215_send_ack(struct sk_buff *skb)
{
	u16 fc = IEEE80215_FC_TYPE_ACK;
	u8 *data;
	struct sk_buff *ackskb;

	BUG_ON(!skb || !skb->dev);
	BUG_ON(!MAC_CB_IS_ACKREQ(skb));

	ackskb = alloc_skb(LL_ALLOCATED_SPACE(skb->dev) + IEEE80215_ACK_LEN, GFP_ATOMIC);

	skb_reserve(ackskb, LL_RESERVED_SPACE(skb->dev));

	skb_reset_network_header(ackskb);

	data = skb_push(ackskb, IEEE80215_ACK_LEN);
	data[0] = fc & 0xff;
	data[1] = (fc >> 8) & 0xff;
	data[2] = MAC_CB(skb)->seq;

	skb_reset_mac_header(ackskb);

	ackskb->dev = skb->dev;
	pr_debug("ACK frame to %s device\n", skb->dev->name);
	ackskb->protocol = htons(ETH_P_IEEE80215);
	/* FIXME */

	return dev_queue_xmit(ackskb);
}

static int ieee80215_process_beacon(struct net_device *dev, struct sk_buff *skb)
{
	int flags;
	int ret;
	ret = parse_beacon_frame(skb, NULL, &flags, NULL);

	/* Here we have cb->sa = coordinator address, and PAN address */

	if (ret < 0) {
		ret = NET_RX_DROP;
		goto fail;
	}
	printk("got beacon from pan %d\n", MAC_CB(skb)->sa.pan_id);
	ieee80215_beacon_hash_add(&MAC_CB(skb)->sa);
	ieee80215_beacon_hash_dump();
	ret = NET_RX_SUCCESS;
fail:
	kfree_skb(skb);
	return ret;
}

static int ieee80215_process_ack(struct net_device *dev, struct sk_buff *skb)
{
	pr_debug("got ACK for SEQ=%d\n", MAC_CB(skb)->seq);

	kfree_skb(skb);
	return NET_RX_SUCCESS;
}

static int ieee80215_process_data(struct net_device *dev, struct sk_buff *skb)
{
	return netif_rx(skb);
}

static int ieee80215_subif_frame(struct ieee80215_netdev_priv *ndp, struct sk_buff *skb)
{
	pr_debug("%s Getting packet via slave interface %s\n",
				__func__, ndp->dev->name);

	switch (MAC_CB(skb)->da.addr_type) {
	case IEEE80215_ADDR_NONE:
		if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_NONE)
			// FIXME: check if we are PAN coordinator :)
			skb->pkt_type = PACKET_OTHERHOST;
		else
			/* ACK comes with both addresses empty */
			skb->pkt_type = PACKET_HOST;
		break;
	case IEEE80215_ADDR_LONG:
		if (MAC_CB(skb)->da.pan_id != ndp->pan_id && MAC_CB(skb)->da.pan_id != IEEE80215_PANID_BROADCAST)
			skb->pkt_type = PACKET_OTHERHOST;
		else if (!memcmp(MAC_CB(skb)->da.hwaddr, ndp->dev->dev_addr, IEEE80215_ADDR_LEN))
			skb->pkt_type = PACKET_HOST;
		else if (!memcmp(MAC_CB(skb)->da.hwaddr, ndp->dev->broadcast, IEEE80215_ADDR_LEN))
			// FIXME: is this correct?
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	case IEEE80215_ADDR_SHORT:
		if (MAC_CB(skb)->da.pan_id != ndp->pan_id && MAC_CB(skb)->da.pan_id != IEEE80215_PANID_BROADCAST)
			skb->pkt_type = PACKET_OTHERHOST;
		else if (MAC_CB(skb)->da.short_addr == ndp->short_addr)
			skb->pkt_type = PACKET_HOST;
		else if (MAC_CB(skb)->da.short_addr == IEEE80215_ADDR_BROADCAST)
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_OTHERHOST;
		break;
	}

	skb->dev = ndp->dev;

	if (MAC_CB_IS_ACKREQ(skb))
		ieee80215_send_ack(skb);

	switch (MAC_CB_TYPE(skb)) {
	case IEEE80215_FC_TYPE_BEACON:
		return ieee80215_process_beacon(ndp->dev, skb);
	case IEEE80215_FC_TYPE_ACK:
		return ieee80215_process_ack(ndp->dev, skb);
	case IEEE80215_FC_TYPE_MAC_CMD:
		return ieee80215_process_cmd(ndp->dev, skb);
	case IEEE80215_FC_TYPE_DATA:
		return ieee80215_process_data(ndp->dev, skb);
	default:
		pr_warning("ieee802154: Bad frame received (type = %d)\n", MAC_CB_TYPE(skb));
		kfree_skb(skb);
		return NET_RX_DROP;
	}
}

static u8 fetch_skb_u8(struct sk_buff *skb)
{
	u8 ret;

	BUG_ON(skb->len < 1);

	ret = skb->data[0];
	skb_pull(skb, 1);

	return ret;
}

static u16 fetch_skb_u16(struct sk_buff *skb)
{
	u16 ret;

	BUG_ON(skb->len < 2);

	ret = skb->data[0] + (skb->data[1] * 256);
	skb_pull(skb, 2);
	return ret;
}

static void fetch_skb_u64(struct sk_buff *skb, void *data)
{
	BUG_ON(skb->len < IEEE80215_ADDR_LEN);

	memcpy(data, skb->data, IEEE80215_ADDR_LEN);
	skb_pull(skb, IEEE80215_ADDR_LEN);
}

#define IEEE80215_FETCH_U8(skb, var)		\
	do {					\
		if (skb->len < 1)		\
			goto exit_error;	\
		var = fetch_skb_u8(skb);	\
	} while (0)

#define IEEE80215_FETCH_U16(skb, var)		\
	do {					\
		if (skb->len < 2)		\
			goto exit_error;	\
		var = fetch_skb_u16(skb);	\
	} while (0)

#define IEEE80215_FETCH_U64(skb, var)			\
	do {						\
		if (skb->len < IEEE80215_ADDR_LEN)	\
			goto exit_error;		\
		fetch_skb_u64(skb, &var);		\
	} while (0)

static int parse_frame_start(struct sk_buff *skb)
{
	u8 *head = skb->data;
	u16 fc;

	if (skb->len < 3) {
		pr_debug("frame size %d bytes is too short\n", skb->len);
		return -EINVAL;
	}

	IEEE80215_FETCH_U16(skb, fc);
	IEEE80215_FETCH_U8(skb, MAC_CB(skb)->seq);

	pr_debug("%s: %04x dsn%02x\n", __func__, fc, head[2]);

	MAC_CB(skb)->flags = IEEE80215_FC_TYPE(fc);

	if (fc & IEEE80215_FC_ACK_REQ) {
		pr_debug("%s(): ACKNOWLEDGE required\n", __func__);
		MAC_CB(skb)->flags |= MAC_CB_FLAG_ACKREQ;
	}

	if (fc & IEEE80215_FC_SECEN)
		MAC_CB(skb)->flags |= MAC_CB_FLAG_SECEN;

	if (fc & IEEE80215_FC_INTRA_PAN)
		MAC_CB(skb)->flags |= MAC_CB_FLAG_INTRAPAN;

	/* TODO */
	if (MAC_CB_IS_SECEN(skb)) {
		pr_info("security support is not implemented\n");
		return -EINVAL;
	}

	MAC_CB(skb)->sa.addr_type = IEEE80215_FC_SAMODE(fc);
	if (MAC_CB(skb)->sa.addr_type == IEEE80215_ADDR_NONE)
		pr_debug("%s(): src addr_type is NONE\n", __func__);

	MAC_CB(skb)->da.addr_type = IEEE80215_FC_DAMODE(fc);
	if (MAC_CB(skb)->da.addr_type == IEEE80215_ADDR_NONE)
		pr_debug("%s(): dst addr_type is NONE\n", __func__);

	if (IEEE80215_FC_TYPE(fc) == IEEE80215_FC_TYPE_ACK) {
		/* ACK can only have NONE-type addresses */
		if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_NONE ||
		    MAC_CB(skb)->da.addr_type != IEEE80215_ADDR_NONE)
			return -EINVAL;
	}

	if (MAC_CB(skb)->da.addr_type != IEEE80215_ADDR_NONE) {
		IEEE80215_FETCH_U16(skb, MAC_CB(skb)->da.pan_id);

		if (MAC_CB_IS_INTRAPAN(skb)) { /* ! panid compress */
			pr_debug("%s(): src IEEE80215_FC_INTRA_PAN\n", __func__);
			MAC_CB(skb)->sa.pan_id = MAC_CB(skb)->da.pan_id;
			pr_debug("%s(): src PAN address %04x\n",
					__func__, MAC_CB(skb)->sa.pan_id);
		}

		pr_debug("%s(): dst PAN address %04x\n",
				__func__, MAC_CB(skb)->da.pan_id);

		if (MAC_CB(skb)->da.addr_type == IEEE80215_ADDR_SHORT) {
			IEEE80215_FETCH_U16(skb, MAC_CB(skb)->da.short_addr);
			pr_debug("%s(): dst SHORT address %04x\n",
					__func__, MAC_CB(skb)->da.short_addr);

		} else {
			IEEE80215_FETCH_U64(skb, MAC_CB(skb)->da.hwaddr);
			pr_debug("%s(): dst hardware addr\n", __func__);
		}
	}

	if (MAC_CB(skb)->sa.addr_type != IEEE80215_ADDR_NONE) {
		pr_debug("%s(): got src non-NONE address\n", __func__);
		if (!(MAC_CB_IS_INTRAPAN(skb))) { /* ! panid compress */
			IEEE80215_FETCH_U16(skb, MAC_CB(skb)->sa.pan_id);
			pr_debug("%s(): src IEEE80215_FC_INTRA_PAN\n", __func__);
		}

		if (MAC_CB(skb)->sa.addr_type == IEEE80215_ADDR_SHORT) {
			IEEE80215_FETCH_U16(skb, MAC_CB(skb)->sa.short_addr);
			pr_debug("%s(): src IEEE80215_ADDR_SHORT\n", __func__);
		} else {
			IEEE80215_FETCH_U64(skb, MAC_CB(skb)->sa.hwaddr);
			pr_debug("%s(): src hardware addr\n", __func__);
		}
	}

	return 0;

exit_error:
	return -EINVAL;
}

void ieee80215_subif_rx(struct ieee80215_dev *hw, struct sk_buff *skb)
{
	struct ieee80215_priv *priv = ieee80215_to_priv(hw);
	struct ieee80215_netdev_priv *ndp, *prev = NULL;
	int ret;

	BUILD_BUG_ON(sizeof(struct ieee80215_mac_cb) > sizeof(skb->cb));
	pr_debug("%s()\n", __func__);

	ret = parse_frame_start(skb); /* 3 bytes pulled after this */
	if (ret) {
		pr_debug("%s(): Got invalid frame\n", __func__);
		goto out;
	}

	if (!(priv->hw.flags & IEEE80215_OPS_OMIT_CKSUM)) {
		if (skb->len < 2) {
			pr_debug("%s(): Got invalid frame\n", __func__);
			goto out;
		}
		// FIXME: check CRC if necessary
		skb_trim(skb, skb->len - 2); /* CRC */
	}

	pr_debug("%s() frame %d\n", __func__, MAC_CB_TYPE(skb));

	rcu_read_lock();

	list_for_each_entry_rcu(ndp, &priv->slaves, list)
	{
		if (prev) {
			struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
			if (skb2)
				ieee80215_subif_frame(prev, skb2);
		}

		prev = ndp;
	}

	if (prev)
		ieee80215_subif_frame(prev, skb);
	else
		kfree_skb(skb);

	rcu_read_unlock();
	return;

out:
	kfree_skb(skb);
	return;
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
EXPORT_SYMBOL(ieee80215_get_dev);

u16 ieee80215_dev_get_pan_id(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	return priv->pan_id;
}
EXPORT_SYMBOL(ieee80215_dev_get_pan_id);

u16 ieee80215_dev_get_short_addr(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	return priv->short_addr;
}
EXPORT_SYMBOL(ieee80215_dev_get_short_addr);

void ieee80215_dev_set_pan_id(struct net_device *dev, u16 val)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	priv->pan_id = val;
}
void ieee80215_dev_set_short_addr(struct net_device *dev, u16 val)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);

	BUG_ON(dev->type != ARPHRD_IEEE80215);

	priv->short_addr = val;
}

// FIXME: come with better solution
struct ieee80215_priv *ieee80215_slave_get_hw(struct net_device *dev)
{
	struct ieee80215_netdev_priv *priv;
	priv = netdev_priv(dev);
	return priv->hw;
}
EXPORT_SYMBOL(ieee80215_slave_get_hw);

int ieee80215_pib_set(struct ieee80215_dev *hw, struct ieee80215_pib *pib)
{
	int ret;
	struct ieee80215_priv *priv = ieee80215_to_priv(hw);
	BUG_ON(!hw);
	BUG_ON(!pib);
	switch (pib->type) {
	case IEEE80215_PIB_CURCHAN:
		/* Our internal mask is inverted
		 * 0 = channel is available
		 * 1 = channel is unavailable
		 * this saves initialization */
		if (hw->channel_mask & (1 << (pib->val - 1)))
			return -EINVAL;
		ret = priv->ops->set_channel(hw, pib->val);
		if (ret == PHY_ERROR)
			return -EINVAL; /* FIXME */
		hw->current_channel =  pib->val;
		break;
	case IEEE80215_PIB_CHANSUPP:
		hw->channel_mask = ~(pib->val);
		break;
	case IEEE80215_PIB_TRPWR:
		/* TODO */
		break;
	case IEEE80215_PIB_CCAMODE:
		/* TODO */
		break;
	default:
		pr_debug("Unknown PIB type value\n");
		return -ENOTSUPP;
	}
	return 0;
}

int ieee80215_pib_get(struct ieee80215_dev *hw, struct ieee80215_pib *pib)
{
	BUG_ON(!hw);
	BUG_ON(!pib);
	switch (pib->type) {
	case IEEE80215_PIB_CURCHAN:
		pib->val = hw->current_channel;
		break;
	case IEEE80215_PIB_CHANSUPP:
		pib->val = ~(hw->channel_mask);
		break;
	case IEEE80215_PIB_TRPWR:
		pib->val = 0;
		break;
	case IEEE80215_PIB_CCAMODE:
		pib->val = 0;
		break;
	default:
		pr_debug("Unknown PIB type value\n");
		return -ENOTSUPP;
	}
	return 0;
}

int ieee80215_slave_register_notifier(struct net_device *dev, struct notifier_block *nb)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);
	return blocking_notifier_chain_register(&priv->events, nb);
}
EXPORT_SYMBOL(ieee80215_slave_register_notifier);
int ieee80215_slave_unregister_notifier(struct net_device *dev, struct notifier_block *nb)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);
	return blocking_notifier_chain_unregister(&priv->events, nb);
}
EXPORT_SYMBOL(ieee80215_slave_unregister_notifier);
int ieee80215_slave_event(struct net_device *dev, int event, void *data)
{
	struct ieee80215_netdev_priv *priv = netdev_priv(dev);
	return blocking_notifier_call_chain(&priv->events, event, data);
}
EXPORT_SYMBOL(ieee80215_slave_event);


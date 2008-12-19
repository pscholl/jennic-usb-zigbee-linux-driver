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
#include <net/ieee80215/mac.h>
#include <net/ieee80215/mac_lib.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/ieee80215.h>
#include <net/ieee80215/beacon.h>

#define DBG_DUMP(data, len) { \
	int i; \
	pr_debug("file %s: function: %s: data: len %d:\n", __FILE__, __FUNCTION__, len); \
	for(i = 0; i < len; i++) {\
		pr_debug("%02x: %02x\n", i, data[i]); \
	} \
}

void ieee80215_net_set_trx_request(struct ieee80215_phy *phy, int state)
{
	int ret = IEEE80215_PHY_SUCCESS;
	BUG_ON(!phy);
	BUG_ON(!_mac(phy));
	pr_info("requested state = %d\n", state);

#if 0
	if (phy_lock(phy)) {
		dbg_print(phy, 0, DBG_ALL, "Unable to lock phy\n");
		ret = IEEE80215_BUSY;
		goto err_exit;
	}
#endif
	if ((PHY_RX_ON == phy->state && IEEE80215_RX_ON == state)
		|| (PHY_TX_ON == phy->state && IEEE80215_TX_ON == state)
		|| (PHY_TRX_OFF == phy->state && IEEE80215_TRX_OFF == state)) {
		ret = state;
		goto err_exit;
	}
	if ((state == IEEE80215_TRX_OFF || state == IEEE80215_RX_ON)
		&& phy->state & PHY_BUSY_TX) {
		ret = IEEE80215_BUSY_TX;
		goto err_exit;
	}
	if ((state == IEEE80215_TX_ON || state == IEEE80215_TRX_OFF)
		&& phy->state & PHY_BUSY_RX) {
		ret = IEEE80215_BUSY_RX;
		goto err_exit;
	}
	switch (state) {
	case IEEE80215_RX_ON:
		phy->pending_state = PHY_RX_ON;
		break;
	case IEEE80215_TX_ON:
		phy->pending_state = PHY_TX_ON;
		break;
	case IEEE80215_TRX_OFF:
	case IEEE80215_FORCE_TRX_OFF:
		phy->pending_state = PHY_TRX_OFF;
		break;
	default:
		pr_info("unsupported requested state %d\n", state);
		BUG();
	}
	/*
	Can anybody explain what was locked?
	Why it was not in the _set_state_confirm()?
	phy_unlock(phy);
	*/
	phy->dev_op->set_state(phy, state);
	return;
err_exit:
	/*phy_unlock(phy);*/
	_mac(phy)->plme_set_trx_state_confirm(_mac(phy), ret);
	return;
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
	BUG_ON(!dev);
	BUG_ON(!priv);
	BUG_ON(!priv->dev_ops);
	BUG_ON(!priv->dev_ops->priv);
	phy = priv->dev_ops->priv;
	if(!phy)
		return -EFAULT;
	mystatus = (status == IEEE80215_PHY_SUCCESS) ?
				IEEE80215_PHY_SUCCESS : IEEE80215_ERROR;
	switch(msg) {
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
		case IEEE80215_TRX_OFF:
		case IEEE80215_RX_ON:
		case IEEE80215_TX_ON:
			ieee80215_net_set_trx_request(phy, status);
			break;
		case IEEE80215_PHY_SUCCESS:
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
		if(mystatus == IEEE80215_RX_ON)
			pr_debug("RX_ON\n");

		pr_debug("Setting status %d\n", mystatus);
		phy->set_state_confirm(phy, mystatus);
		// set_trx_state(_mac(phy), mystatus, NULL);
		break;

	case IEEE80215_MSG_XMIT_BLOCK_CONFIRM:
	case IEEE80215_MSG_XMIT_STREAM_CONFIRM:
		phy->xmit_confirm(phy, mystatus);
		break;
	default:
		printk(KERN_ERR "%s:%s bad message %d\n",
					__FILE__, __FUNCTION__, msg);
		break;
	}
	return 0;
}

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

/* TODO */
int ieee80215_filter_af(ieee80215_mac_t *mac, struct sk_buff *skb);
int ieee80215_ack_confirm(void *obj, struct sk_buff *ack, int code);
void ieee80215_ack_perform(ieee80215_mac_t *mac);

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

static int ieee80215_rcv(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct sock *sk;
	BUG_ON(!skb->data);

	DBG_DUMP(skb->data, skb->len);
	if(!netif_running(dev))
		return -ENODEV;
	pr_debug("got frame, type %d, dev %p master %p\n", dev->type, dev, dev->master);
	if (dev->type != ARPHRD_IEEE80215 || !net_eq(dev_net(dev), &init_net)) {
		pr_debug("Crap crap crap\n");
		kfree_skb(skb);
		return 0;
	}
	/* Control frame processing */
	if(skb->len < 5 && !dev->master) {
		struct ieee80215_netdev_priv *mpriv = netdev_priv(dev);
		pr_debug("Got control frame %d %d %d\n", skb->data[1], skb->data[2], skb->data[3]);
		/* We won't put control frames to socket buffer, no need to bother */
		ieee80215_process_msg(dev, skb->data[1], skb->data[2], skb->data[3]);
		mpriv->stats.tx_bytes += skb->len;
		mpriv->stats.tx_packets++;
		kfree_skb(skb);
		return 0;
	}

	pr_debug("%s:%s dev->master = %p, skb->len = %d\n",
			__FILE__, __FUNCTION__, dev->master, skb->len);
	if(dev->master) {
		struct ieee80215_netdev_priv *priv = netdev_priv(dev);
		sk = priv->sk;
		skb->sk = sk;
		pr_debug("got data frame\n");
		if(!sk) {/* Nothing is binded */
				pr_debug("no valid socket, tossing crap\n");
				kfree_skb(skb);
				priv->stats.tx_dropped++;
		}

	/* Write function to recognize frame addresses */

		BUG_ON(!sk);
		BUG_ON(!skb);
		//ieee80215_pd_data_indicate(priv->mac, skb);
		ieee80215_net_parse_skb(priv->mac, sk, skb);
		if (sock_queue_rcv_skb(sk, skb) < 0) {
			kfree_skb(skb);
			priv->stats.tx_dropped++;
		}
	} else {
		struct ieee80215_mnetdev_priv *mpriv = netdev_priv(dev);
		pr_debug("%s:%s: Got some junk from master interface\n",
				__FILE__, __FUNCTION__);
		kfree_skb(skb);
		mpriv->stats.tx_dropped++;
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
	struct net_device *dev = sk->sk_user_data;
	struct ieee80215_netdev_priv *priv;
	if(dev->master) {
		priv = netdev_priv(dev);
		priv->sk = NULL;
	}

	if (sk) {
		sock_orphan(sk);
		sock->sk = NULL;
		lock_sock(sk);
		release_sock(sk);
		sock_put(sk);
	}
	return 0;
}

static int ieee80215_sock_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct net_device * dev;
	struct ieee80215_netdev_priv *priv;
	u8 * addr = (u8 *)uaddr;
	if (addr_len != sizeof(u64))
		return -EINVAL;
	dev = dev_getbyhwaddr (&init_net, ARPHRD_IEEE80215, addr);
	if(!dev)
		return -EINVAL;
	if(dev->master && netif_running(dev)) {
		priv = netdev_priv(dev);
		sock->sk->sk_user_data = dev;
		priv->sk = sock->sk;
		return 0;
	}
	return -EACCES;
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

/* TODO: endianness */
static int ieee80215_sock_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	int err;
	unsigned mtu;
	zb_npdu_head_t *h;
	struct sk_buff *skb;
	struct ieee80215_mpdu *mpdu;
	struct net_device *dev;
	struct sockaddr_zb *dst;

	pr_debug("sock = 0x%p\n", sock);

	err = sock_error(sk);
	if (err) {
		pr_debug("sock_error() returned 0x%x\n", err);
		return err;
	}

	if (msg->msg_flags & MSG_OOB) {
		pr_debug("msg->msg_flags = 0x%x\n", msg->msg_flags);
		return -EOPNOTSUPP;
	}
	
	dev = sk->sk_user_data;
	if (!dev) {
		pr_debug("no dev\n");
		return -ENXIO;
	}
	mtu = dev->mtu;
	pr_debug("name = %s, mtu = %u\n", dev->name, mtu);

	if (len > mtu) {
		pr_debug("len = %u, mtu = %u\n", len, mtu);
		return -EINVAL;
	}

	mpdu = mac_alloc_mpdu(len + ZB_NWK_FRAME_OVERHEAD);
	if (!mpdu) {
		pr_debug("unable to allocate memory\n");
		return -ENOMEM;
	}
	skb = mpdu_to_skb(mpdu);
#if 0
	h = (zb_npdu_head_t *)skb_put(skb, ZB_NWK_FRAME_OVERHEAD);
	mpdu->p.h = h;

	if (!msg->msg_name || msg->msg_namelen < sizeof(*dst)) {
		pr_debug("msg->msg_name = 0x%p, msg->msg_namelen = %u\n",
			msg->msg_name, msg->msg_namelen);
		return -EINVAL;
	}
	dst = (u64*)msg->msg_name;
	h->dst = dst;
	pr_debug("h->dst = 0x%x\n", h->dst);
#endif
	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (err < 0) {
		pr_debug("unable to memcpy_fromiovec()\n");
		kfree_mpdu(mpdu);
		return err;
	}

	skb->dev = dev;
	skb->sk = sk;
	dev_queue_xmit(skb);

	if (err)
		return err;

	return len;
}

static int ieee80215_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
	struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk;
	int noblock;
	struct sk_buff *skb;
	int err = 0;

	pr_debug("sock = 0x%p\n", sock);

	sk = sock->sk;
	noblock = flags & MSG_DONTWAIT;
	flags &= ~MSG_DONTWAIT;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		return err;
	
	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;
	
	err = memcpy_toiovec(msg->msg_iov, skb->data, size);
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

	sock_recv_timestamp(msg, sk, skb);
	skb_free_datagram(sk, skb);
	return size;
}


static const struct proto_ops SOCKOPS_WRAPPED(ieee80215_dgram_ops) = {
	.family		= PF_IEEE80215,
	.owner		= THIS_MODULE,
	.release	= ieee80215_sock_release,
	.bind		= ieee80215_sock_bind,
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

static int ieee80215_net_rx_cmd(struct ieee80215_phy *phy, u8 *data, ssize_t len)
{
	struct sk_buff *skb;
	pr_debug("submitting control frame\n");
	skb = dev_alloc_skb(len);
	if(!skb)
		return -ENOMEM;
	skb_put(skb, len);
	skb_copy_to_linear_data(skb, data, len);
	/* All frames originate from master interface for now */
	skb->dev = phy->dev;
	skb->protocol = htons(ETH_P_IEEE80215);
	/* TODO look, how to do this without copying */
	/* Copying only PHY payload into ppdu, check for linearize */
	DBG_DUMP(skb->data, skb->len);
	netif_rx(skb);
	return 0;
}

#define IEEE80215_CFRAME_SIZE 4
int ieee80215_net_rx(struct ieee80215_phy *phy, u8 *data, ssize_t len, u8 lq)
{
	ieee80215_mpdu_t *msdu;
	ieee80215_PPDU_t *ppdu;
	struct sk_buff *skb;

	pr_debug("%s: %s, submitting data frame, len = %d\n", __FILE__, __FUNCTION__, len);
	if(!phy->dev) {
		pr_debug("orphane frame recieved\n");
		return -ENODEV;
	}
	if (!(phy->state & PHY_RX_ON)) {
		pr_debug("RX is not on\n");
		return -EINVAL;
	}
	if (len > IEEE80215_MAX_PHY_PACKET_SIZE) {
		pr_debug("PHY pkt is longer than allowed\n");
		return -EINVAL;
	}
	ppdu = (struct ieee80215_PPDU *) data;
	if (ppdu->sfd != DEF_SFD) {
		pr_debug("received frame have no valid SFD\n");
		return -EINVAL;
	}
	pr_debug("submitting psdu len: %u\n", ppdu->flen);
	msdu = dev_alloc_mpdu(ppdu->flen);
	if (!msdu) {
		pr_debug("Cannot allocate msdu skb\n");
		return -ENOMEM;
	}
	skb = msdu->skb;
	msdu->lq = lq;
	msdu->timestamp = jiffies;
	skb_put(msdu->skb, ppdu->flen);
	skb_copy_to_linear_data(msdu->skb, data + IEEE80215_MAX_PHY_OVERHEAD,
			ppdu->flen);

	/* All frames originate from master interface for now */
	skb->dev = phy->dev;
	skb->protocol = htons(ETH_P_IEEE80215);
	/* TODO look, how to do this without copying */
	/* Copying only PHY payload into ppdu, check for linearize */
	DBG_DUMP(skb->data, skb->len);
	netif_rx(skb);
	return 0;
}
EXPORT_SYMBOL(ieee80215_net_rx);

int ieee80215_net_cmd(struct ieee80215_phy *phy, u8 command, u8 status, u8 data)
{
	char buf[IEEE80215_CFRAME_SIZE];
	pr_debug("%s\n", __FUNCTION__);
	buf[0] = 0;
	buf[1] = command;
	buf[2] = status;
	buf[3] = data;
	ieee80215_net_rx_cmd(phy, buf, IEEE80215_CFRAME_SIZE);
	return 0;
}
EXPORT_SYMBOL(ieee80215_net_cmd);

static const char* state_to_str(int state)
{
        switch (state) {
        case IEEE80215_RX_ON:
                return "RX_ON";
        case IEEE80215_TRX_OFF:
                return "TRX_OFF";
        case IEEE80215_TX_ON:
                return "TX_ON";
        default:
                return "unknown";
        }
}

static int set_trx_state_confirm(struct ieee80215_mac *mac, int code)
{
	if (IEEE80215_PHY_SUCCESS == code || mac->pending_trx_state == code) {
		pr_info("%s: %s: set %s: ok\n", __FILE__, __FUNCTION__,
			state_to_str(mac->pending_trx_state));
		if (mac->pending_trx_state_func) {
			mac->pending_trx_state_func(mac);
		}
	} else {
		pr_info("set state attempt failed, retry\n");
		ieee80215_net_cmd(mac->phy, IEEE80215_MSG_SET_STATE,
				mac->pending_trx_state, 0);	
	}
	return 0;
}


int ieee80215_net_set_trx_state(struct ieee80215_mac *mac,
				int state, set_trx_state_func_t func)
{
	switch(state) {
	case IEEE80215_RX_ON:
	case IEEE80215_TX_ON:
	case IEEE80215_TRX_OFF:
		pr_debug("state %s\n", state_to_str(state));
		break;
	default:
		return -EINVAL;	
		break;
	}
	mac->pending_trx_state = state;
	mac->pending_trx_state_func = func;
	mac->plme_set_trx_state_confirm = set_trx_state_confirm;
	ieee80215_net_cmd(mac->phy, IEEE80215_MSG_SET_STATE,
				state, 0);	
	return 0;
}
EXPORT_SYMBOL(ieee80215_net_set_trx_state);

module_init(af_ieee80215_init);
module_exit(af_ieee80215_remove);
MODULE_LICENSE("GPL");


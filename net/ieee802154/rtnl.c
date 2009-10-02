/*
 * Copyright 2007, 2008, 2009 Siemens AG
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Sergey Lapin <slapin@ossfans.org>
 */

#include <linux/net.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/rculist.h>
#include <linux/random.h>
#include <linux/crc-ccitt.h>
#include <linux/mac802154.h>
#include <net/rtnetlink.h>

#include <net/af_ieee802154.h>
#include <net/mac802154.h>
#include <net/ieee802154_netdev.h>
#include <net/ieee802154.h>
#include <net/wpan-phy.h>

#include "ieee802154.h"

static int wpan_netdev_validate(struct nlattr *tb[],
		struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS])
		if (nla_len(tb[IFLA_ADDRESS]) != IEEE802154_ADDR_LEN)
			return -EINVAL;

	if (tb[IFLA_BROADCAST])
		return -EINVAL;

	return 0;
}

static size_t wpan_netdev_get_size(const struct net_device *dev)
{
	struct ieee802154_mlme_ops *ops = ieee802154_mlme_ops(dev);
	struct wpan_phy *phy = ops->get_phy(dev);

	return	nla_total_size(2) +	/* IFLA_WPAN_CHANNEL */
		nla_total_size(2) +	/* IFLA_WPAN_PAN_ID */
		nla_total_size(2) +	/* IFLA_WPAN_SHORT_ADDR */
					/* IFLA_WPAN_PHY */
		nla_total_size(strlen(wpan_phy_name(phy)) + 1) +
		nla_total_size(2) +	/* IFLA_WPAN_COORD_SHORT_ADDR */
		nla_total_size(8);	/* IFLA_WPAN_COORD_EXT_ADDR */
}

static int wpan_netdev_fill_info(struct sk_buff *skb,
					const struct net_device *dev)
{
	struct ieee802154_mlme_ops *ops = ieee802154_mlme_ops(dev);
	struct wpan_phy *phy = ops->get_phy(dev);

	u16 channel;
	u8 page;

	mutex_lock(&phy->pib_lock);
	channel = phy->current_channel;
	page = phy->current_page;
	mutex_unlock(&phy->pib_lock);


	NLA_PUT_U16(skb, IFLA_WPAN_CHANNEL, channel);
	NLA_PUT_U8(skb, IFLA_WPAN_PAGE, page);
	NLA_PUT_U16(skb, IFLA_WPAN_PAN_ID, ops->get_pan_id(dev));
	NLA_PUT_U16(skb, IFLA_WPAN_SHORT_ADDR, ops->get_short_addr(dev));
	NLA_PUT_STRING(skb, IFLA_WPAN_PHY, wpan_phy_name(phy));
	/* TODO: IFLA_WPAN_COORD_SHORT_ADDR */
	/* TODO: IFLA_WPAN_COORD_EXT_ADDR */

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}


/*
 * mostly a placeholder, as we don't permit creation of wpan devices
 * from here
 */
static void wpan_netdev_setup(struct net_device *dev)
{
	dev->addr_len		= IEEE802154_ADDR_LEN;
	memset(dev->broadcast, 0xff, IEEE802154_ADDR_LEN);
	dev->destructor		= free_netdev;
}

static int wpan_netdev_newlink(struct net_device *dev,
					   struct nlattr *tb[],
					   struct nlattr *data[])
{
	return -EOPNOTSUPP;
}

static void wpan_netdev_dellink(struct net_device *dev)
{
	struct wpan_phy *phy;

	BUG_ON(dev->type != ARPHRD_IEEE802154);

	phy = ieee802154_mlme_ops(dev)->get_phy(dev);

	if (phy->del_iface)
		phy->del_iface(phy, dev);
}

struct rtnl_link_ops wpan_link_ops __read_mostly = {
	.kind		= "wpan",
	.maxtype	= IFLA_WPAN_MAX,
	/* TODO: policy */
	.priv_size	= 0,
	.setup		= wpan_netdev_setup,
	.validate	= wpan_netdev_validate,
	.newlink	= wpan_netdev_newlink,
	.dellink	= wpan_netdev_dellink,
	.get_size	= wpan_netdev_get_size,
	.fill_info	= wpan_netdev_fill_info,
};

int register_wpandev(struct net_device *dev)
{
	dev->rtnl_link_ops = &wpan_link_ops;
	return register_netdev(dev);
}
EXPORT_SYMBOL(register_wpandev);

int __init wpan_rtnl_init(void)
{
	return rtnl_link_register(&wpan_link_ops);
}

void __exit wpan_rtnl_exit(void)
{
	rtnl_link_unregister(&wpan_link_ops);
}

MODULE_ALIAS_RTNL_LINK("wpan");


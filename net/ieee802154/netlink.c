/*
 * Netlink intefcace for IEEE 802.15.4 stack
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
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/netdevice.h>
#include <net/ieee802154/af_ieee802154.h>
#define IEEE802154_NL_WANT_POLICY
#include <net/ieee802154/nl.h>
#include <net/ieee802154/mac_def.h>
#include <net/ieee802154/netdev.h>

static unsigned int ieee802154_seq_num;

static struct genl_family ieee802154_coordinator_family = {
	.id		= GENL_ID_GENERATE,
	.hdrsize	= 0,
	.name		= IEEE802154_NL_NAME,
	.version	= 1,
	.maxattr	= IEEE802154_ATTR_MAX,
};

static struct genl_multicast_group ieee802154_coord_mcgrp = {
	.name		= IEEE802154_MCAST_COORD_NAME,
};

static struct genl_multicast_group ieee802154_beacon_mcgrp = {
	.name		= IEEE802154_MCAST_BEACON_NAME,
};

/* Requests to userspace */

int ieee802154_nl_assoc_indic(struct net_device *dev, struct ieee802154_addr *addr, u8 cap)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee802154_seq_num++, &ieee802154_coordinator_family, /* flags*/ 0, IEEE802154_ASSOCIATE_INDIC);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE802154_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE802154_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_HW_ADDR, dev->dev_addr);

	/* FIXME: check that we really received hw address */
	NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_SRC_HW_ADDR, addr->hwaddr);

	NLA_PUT_U8(msg, IEEE802154_ATTR_CAPABILITY, cap);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee802154_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee802154_nl_beacon_indic(struct net_device *dev, u16 panid, u16 coord_addr) /* TODO */
{
	struct sk_buff *msg;
	void *hdr;
	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;
	hdr = genlmsg_put(msg, 0, ieee802154_seq_num++, &ieee802154_coordinator_family, /* flags*/ 0, IEEE802154_ASSOCIATE_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE802154_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE802154_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_HW_ADDR, dev->dev_addr);
	NLA_PUT_U16(msg, IEEE802154_ATTR_COORD_SHORT_ADDR, coord_addr);
	NLA_PUT_U16(msg, IEEE802154_ATTR_COORD_PAN_ID, panid);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	/* FIXME different multicast group needed */
	return genlmsg_multicast(msg, 0, ieee802154_beacon_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee802154_nl_assoc_confirm(struct net_device *dev, u16 short_addr, u8 status)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee802154_seq_num++, &ieee802154_coordinator_family, /* flags*/ 0, IEEE802154_ASSOCIATE_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE802154_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE802154_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_HW_ADDR, dev->dev_addr);

	NLA_PUT_U16(msg, IEEE802154_ATTR_SHORT_ADDR, short_addr);
	NLA_PUT_U8(msg, IEEE802154_ATTR_STATUS, status);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee802154_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee802154_nl_disassoc_indic(struct net_device *dev, struct ieee802154_addr *addr, u8 reason)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee802154_seq_num++, &ieee802154_coordinator_family, /* flags*/ 0, IEEE802154_DISASSOCIATE_INDIC);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE802154_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE802154_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_HW_ADDR, dev->dev_addr);

	if (addr->addr_type == IEEE802154_ADDR_LONG)
		NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_SRC_HW_ADDR, addr->hwaddr);
	else
		NLA_PUT_U16(msg, IEEE802154_ATTR_SRC_SHORT_ADDR, addr->short_addr);

	NLA_PUT_U8(msg, IEEE802154_ATTR_REASON, reason);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee802154_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee802154_nl_disassoc_confirm(struct net_device *dev, u8 status)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee802154_seq_num++, &ieee802154_coordinator_family, /* flags*/ 0, IEEE802154_DISASSOCIATE_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE802154_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE802154_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_HW_ADDR, dev->dev_addr);

	NLA_PUT_U8(msg, IEEE802154_ATTR_STATUS, status);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee802154_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee802154_nl_scan_confirm(struct net_device *dev, u8 status, u8 scan_type, u32 unscanned,
		u8 *edl/* , struct list_head *pan_desc_list */)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee802154_seq_num++, &ieee802154_coordinator_family, /* flags*/ 0, IEEE802154_SCAN_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE802154_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE802154_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE802154_ATTR_HW_ADDR, dev->dev_addr);

	NLA_PUT_U8(msg, IEEE802154_ATTR_STATUS, status);
	NLA_PUT_U8(msg, IEEE802154_ATTR_SCAN_TYPE, scan_type);
	NLA_PUT_U32(msg, IEEE802154_ATTR_CHANNELS, unscanned);

	if (edl)
		NLA_PUT(msg, IEEE802154_ATTR_ED_LIST, 27, edl);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee802154_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

/* Requests from userspace */

static int ieee802154_associate_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ieee802154_addr addr, saddr;
	u8 buf[2];
	int pos = 0;
	int ret = -EINVAL;

	if (!info->attrs[IEEE802154_ATTR_CHANNEL]
	 || !info->attrs[IEEE802154_ATTR_COORD_PAN_ID]
	 || (!info->attrs[IEEE802154_ATTR_COORD_HW_ADDR] && !info->attrs[IEEE802154_ATTR_COORD_SHORT_ADDR])
	 || !info->attrs[IEEE802154_ATTR_CAPABILITY])
		return -EINVAL;

	if (info->attrs[IEEE802154_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE802154_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE802154_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE802154_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE802154) {
		dev_put(dev);
		return -EINVAL;
	}

	if (info->attrs[IEEE802154_ATTR_COORD_HW_ADDR]) {
		addr.addr_type = IEEE802154_ADDR_LONG;
		NLA_GET_HW_ADDR(info->attrs[IEEE802154_ATTR_COORD_HW_ADDR], addr.hwaddr);
	} else {
		addr.addr_type = IEEE802154_ADDR_SHORT;
		addr.short_addr = nla_get_u16(info->attrs[IEEE802154_ATTR_COORD_SHORT_ADDR]);
	}
	addr.pan_id = nla_get_u16(info->attrs[IEEE802154_ATTR_COORD_PAN_ID]);

	saddr.addr_type = IEEE802154_ADDR_LONG;
	saddr.pan_id = IEEE802154_PANID_BROADCAST;
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE802154_ADDR_LEN);

	/* FIXME: set PIB/MIB info */
	ieee802154_dev_set_pan_id(dev, addr.pan_id);
	ieee802154_dev_set_channel(dev, nla_get_u8(info->attrs[IEEE802154_ATTR_CHANNEL]));

	buf[pos++] = IEEE802154_CMD_ASSOCIATION_REQ;
	buf[pos++] = nla_get_u8(info->attrs[IEEE802154_ATTR_CAPABILITY]);
	ret = ieee802154_send_cmd(dev, &addr, &saddr, buf, pos);

	dev_put(dev);
	return ret;
}

static int ieee802154_associate_resp(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ieee802154_addr addr, saddr;
	u8 buf[4];
	int pos = 0;
	u16 short_addr;
	int ret = -EINVAL;

	if (!info->attrs[IEEE802154_ATTR_STATUS]
	 || !info->attrs[IEEE802154_ATTR_DEST_HW_ADDR]
	 || !info->attrs[IEEE802154_ATTR_DEST_SHORT_ADDR])
		return -EINVAL;

	if (info->attrs[IEEE802154_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE802154_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE802154_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE802154_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE802154) {
		dev_put(dev);
		return -EINVAL;
	}

	addr.addr_type = IEEE802154_ADDR_LONG;
	NLA_GET_HW_ADDR(info->attrs[IEEE802154_ATTR_DEST_HW_ADDR], addr.hwaddr);
	addr.pan_id = ieee802154_dev_get_pan_id(dev);

	saddr.addr_type = IEEE802154_ADDR_LONG;
	saddr.pan_id = addr.pan_id;
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE802154_ADDR_LEN);

	short_addr = nla_get_u16(info->attrs[IEEE802154_ATTR_DEST_SHORT_ADDR]);

	buf[pos++] = IEEE802154_CMD_ASSOCIATION_RESP;
	buf[pos++] = short_addr;
	buf[pos++] = short_addr >> 8;
	buf[pos++] = nla_get_u8(info->attrs[IEEE802154_ATTR_STATUS]);

	ret = ieee802154_send_cmd(dev, &addr, &saddr, buf, pos);

	dev_put(dev);
	return ret;
}

static int ieee802154_disassociate_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ieee802154_addr addr, saddr;
	u8 buf[2];
	int pos = 0;
	int ret = -EINVAL;

	if ((!info->attrs[IEEE802154_ATTR_DEST_HW_ADDR] && !info->attrs[IEEE802154_ATTR_DEST_SHORT_ADDR])
	 || !info->attrs[IEEE802154_ATTR_REASON])
		return -EINVAL;

	if (info->attrs[IEEE802154_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE802154_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE802154_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE802154_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE802154) {
		dev_put(dev);
		return -EINVAL;
	}

	if (info->attrs[IEEE802154_ATTR_DEST_HW_ADDR]) {
		addr.addr_type = IEEE802154_ADDR_LONG;
		NLA_GET_HW_ADDR(info->attrs[IEEE802154_ATTR_DEST_HW_ADDR], addr.hwaddr);
	} else {
		addr.addr_type = IEEE802154_ADDR_SHORT;
		addr.short_addr = nla_get_u16(info->attrs[IEEE802154_ATTR_DEST_SHORT_ADDR]);
	}
	addr.pan_id = ieee802154_dev_get_pan_id(dev);

	saddr.addr_type = IEEE802154_ADDR_LONG;
	saddr.pan_id = ieee802154_dev_get_pan_id(dev);
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE802154_ADDR_LEN);

	buf[pos++] = IEEE802154_CMD_DISASSOCIATION_NOTIFY;
	buf[pos++] = nla_get_u8(info->attrs[IEEE802154_ATTR_REASON]);
	ret = ieee802154_send_cmd(dev, &addr, &saddr, buf, pos);

	/* FIXME: this should be after the ack receved */
	ieee802154_dev_set_pan_id(dev, 0xffff);
	ieee802154_dev_set_short_addr(dev, 0xffff);
	ieee802154_nl_disassoc_confirm(dev, 0x00);

	dev_put(dev);
	return ret;
}

/*
 * PANid, channel, beacon_order = 15, superframe_order = 15,
 * PAN_coordinator, battery_life_extension = 0,
 * coord_realignment = 0, security_enable = 0
*/
static int ieee802154_start_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	u16 panid;
	u8 channel = 0, bcn_ord = 15, sf_ord = 15;
	int pan_coord, blx = 0, coord_realign = 0, sec = 0;
	u16 short_addr;
	int ret;

	if (!info->attrs[IEEE802154_ATTR_COORD_PAN_ID]
	 || !info->attrs[IEEE802154_ATTR_COORD_SHORT_ADDR]
/*
	 || !info->attrs[IEEE802154_ATTR_CHANNEL]
	 || !info->attrs[IEEE802154_ATTR_BCN_ORD]
	 || !info->attrs[IEEE802154_ATTR_SF_ORD]
*/
	 || !info->attrs[IEEE802154_ATTR_PAN_COORD]
/*
	 || !info->attrs[IEEE802154_ATTR_BAT_EXT]
	 || !info->attrs[IEEE802154_ATTR_COORD_REALIGN]
	 || !info->attrs[IEEE802154_ATTR_SEC] */)
		return -EINVAL;
	if (info->attrs[IEEE802154_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE802154_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE802154_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE802154_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;


	if (dev->type != ARPHRD_IEEE802154) {
		dev_put(dev);
		return -EINVAL;
	}
	panid = nla_get_u16(info->attrs[IEEE802154_ATTR_COORD_PAN_ID]);
#if 0
	channel = nla_get_u8(info->attrs[IEEE802154_ATTR_CHANNEL]);
	bcn_ord = nla_get_u8(info->attrs[IEEE802154_ATTR_BCN_ORD]);
	sf_ord = nla_get_u8(info->attrs[IEEE802154_ATTR_SF_ORD]);
#endif
	pan_coord = nla_get_u8(info->attrs[IEEE802154_ATTR_PAN_COORD]);
#if 0
	blx = nla_get_u8(info->attrs[IEEE802154_ATTR_BAT_EXT]);
	coord_realign = nla_get_u8(info->attrs[IEEE802154_ATTR_COORD_REALIGN]);
	sec = nla_get_u8(info->attrs[IEEE802154_ATTR_COORD_SEC]);
#endif
	short_addr = nla_get_u16(info->attrs[IEEE802154_ATTR_COORD_SHORT_ADDR]);
	ret = ieee802154_mlme_start_req(dev, panid, channel, bcn_ord, sf_ord,
		pan_coord, blx, coord_realign, sec);
	if (ret < 0)
		goto out;
	ieee802154_dev_set_short_addr(dev, short_addr);
out:
	dev_put(dev);
	return ret;
}

static int ieee802154_scan_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	int ret;
	u8 type;
	u32 channels;
	u8 duration;

	if (!info->attrs[IEEE802154_ATTR_SCAN_TYPE]
	 || !info->attrs[IEEE802154_ATTR_CHANNELS]
	 || !info->attrs[IEEE802154_ATTR_DURATION])
		return -EINVAL;

	if (info->attrs[IEEE802154_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE802154_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE802154_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE802154_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE802154) {
		dev_put(dev);
		return -EINVAL;
	}

	type = nla_get_u8(info->attrs[IEEE802154_ATTR_SCAN_TYPE]);
	channels = nla_get_u32(info->attrs[IEEE802154_ATTR_CHANNELS]);
	duration = nla_get_u8(info->attrs[IEEE802154_ATTR_DURATION]);

	ret = ieee802154_mlme_scan_req(dev, type, channels, duration);

	dev_put(dev);
	return ret;
}

#define IEEE802154_OP(_cmd, _func)			\
	{						\
		.cmd	= _cmd,				\
		.policy	= ieee802154_policy,		\
		.doit	= _func,			\
		.dumpit	= NULL,				\
		.flags	= GENL_ADMIN_PERM,		\
	}

static struct genl_ops ieee802154_coordinator_ops[] = {
	IEEE802154_OP(IEEE802154_ASSOCIATE_REQ, ieee802154_associate_req),
	IEEE802154_OP(IEEE802154_ASSOCIATE_RESP, ieee802154_associate_resp),
	IEEE802154_OP(IEEE802154_DISASSOCIATE_REQ, ieee802154_disassociate_req),
	IEEE802154_OP(IEEE802154_SCAN_REQ, ieee802154_scan_req),
	IEEE802154_OP(IEEE802154_START_REQ, ieee802154_start_req),
};

#if 0
static int ieee802154_coordinator_rcv(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	char name[IFNAMSIZ + 1];
	struct net_device *dev;


	pr_debug("%s\n", __func__);

	if (!info->attrs[IEEE802154_ATTR_DEV_NAME])
		return -EINVAL;

	nla_strlcpy(name, info->attrs[IEEE802154_ATTR_DEV_NAME], sizeof(name));

	dev = dev_get_by_name(&init_net, name);
	if (!dev)
		goto out_dev;

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq, &ieee802154_coordinator_family, /* flags*/ 0, /* cmd */ 1);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE802154_ATTR_DEV_NAME, name);
	NLA_PUT_U64(msg, IEEE802154_ATTR_HW_ADDR, *(u64 *)&dev->dev_addr);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_unicast(msg, info->snd_pid);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	dev_put(dev);
out_dev:
	return -ENOBUFS;
}
#endif

int __init ieee802154_nl_init(void)
{
	int rc;
	int i;

	rc = genl_register_family(&ieee802154_coordinator_family);
	if (rc)
		goto fail;

	rc = genl_register_mc_group(&ieee802154_coordinator_family, &ieee802154_coord_mcgrp);
	if (rc)
		goto fail;

	rc = genl_register_mc_group(&ieee802154_coordinator_family, &ieee802154_beacon_mcgrp);
	if (rc)
		goto fail;


	for (i = 0; i < ARRAY_SIZE(ieee802154_coordinator_ops); i++) {
		rc = genl_register_ops(&ieee802154_coordinator_family, &ieee802154_coordinator_ops[i]);
		if (rc)
			goto fail;
	}

	return 0;

fail:
	genl_unregister_family(&ieee802154_coordinator_family);
	return rc;
}

void __exit ieee802154_nl_exit(void)
{
	genl_unregister_family(&ieee802154_coordinator_family);
}

#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/netdevice.h>
#include <net/ieee80215/af_ieee80215.h>
#define IEEE80215_NL_WANT_POLICY
#include <net/ieee80215/nl.h>
#include <net/ieee80215/mac_def.h>
#include <net/ieee80215/netdev.h>

static unsigned int ieee80215_seq_num;

static struct genl_family ieee80215_coordinator_family = {
	.id		= GENL_ID_GENERATE,
	.hdrsize	= 0,
	.name		= IEEE80215_NL_NAME,
	.version	= 1,
	.maxattr	= IEEE80215_ATTR_MAX,
};

static struct genl_multicast_group ieee80215_coord_mcgrp = {
	.name		= IEEE80215_MCAST_COORD_NAME,
};

static struct genl_multicast_group ieee80215_beacon_mcgrp = {
	.name		= IEEE80215_MCAST_BEACON_NAME,
};

/* Requests to userspace */

int ieee80215_nl_assoc_indic(struct net_device *dev, struct ieee80215_addr *addr, u8 cap)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee80215_seq_num++, &ieee80215_coordinator_family, /* flags*/ 0, IEEE80215_ASSOCIATE_INDIC);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE80215_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_HW_ADDR, dev->dev_addr);

	// FIXME: check that we really received hw address
	NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_SRC_HW_ADDR, addr->hwaddr);

	NLA_PUT_U8(msg, IEEE80215_ATTR_CAPABILITY, cap);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee80215_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee80215_nl_beacon_indic(struct net_device *dev, u16 panid, u16 coord_addr) /* TODO */
{
	struct sk_buff *msg;
	void *hdr;
	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;
	hdr = genlmsg_put(msg, 0, ieee80215_seq_num++, &ieee80215_coordinator_family, /* flags*/ 0, IEEE80215_ASSOCIATE_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE80215_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_HW_ADDR, dev->dev_addr);
	NLA_PUT_U16(msg, IEEE80215_ATTR_COORD_SHORT_ADDR, coord_addr);
	NLA_PUT_U16(msg, IEEE80215_ATTR_COORD_PAN_ID, panid);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	/* FIXME different multicast group needed */
	return genlmsg_multicast(msg, 0, ieee80215_beacon_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee80215_nl_assoc_confirm(struct net_device *dev, u16 short_addr, u8 status)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee80215_seq_num++, &ieee80215_coordinator_family, /* flags*/ 0, IEEE80215_ASSOCIATE_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE80215_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_HW_ADDR, dev->dev_addr);

	NLA_PUT_U16(msg, IEEE80215_ATTR_SHORT_ADDR, short_addr);
	NLA_PUT_U8(msg, IEEE80215_ATTR_STATUS, status);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee80215_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee80215_nl_disassoc_indic(struct net_device *dev, struct ieee80215_addr *addr, u8 reason)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee80215_seq_num++, &ieee80215_coordinator_family, /* flags*/ 0, IEEE80215_DISASSOCIATE_INDIC);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE80215_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_HW_ADDR, dev->dev_addr);

	if (addr->addr_type == IEEE80215_ADDR_LONG)
		NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_SRC_HW_ADDR, addr->hwaddr);
	else
		NLA_PUT_U16(msg, IEEE80215_ATTR_SRC_SHORT_ADDR, addr->short_addr);

	NLA_PUT_U8(msg, IEEE80215_ATTR_REASON, reason);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee80215_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee80215_nl_disassoc_confirm(struct net_device *dev, u8 status)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee80215_seq_num++, &ieee80215_coordinator_family, /* flags*/ 0, IEEE80215_DISASSOCIATE_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE80215_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_HW_ADDR, dev->dev_addr);

	NLA_PUT_U8(msg, IEEE80215_ATTR_STATUS, status);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee80215_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

int ieee80215_nl_scan_confirm(struct net_device *dev, u8 status, u8 scan_type, u32 unscanned,
		u8 *edl/* , struct list_head *pan_desc_list */)
{
	struct sk_buff *msg;
	void *hdr;

	pr_debug("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, 0, ieee80215_seq_num++, &ieee80215_coordinator_family, /* flags*/ 0, IEEE80215_SCAN_CONF);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, dev->name);
	NLA_PUT_U32(msg, IEEE80215_ATTR_DEV_INDEX, dev->ifindex);
	NLA_PUT_HW_ADDR(msg, IEEE80215_ATTR_HW_ADDR, dev->dev_addr);

	NLA_PUT_U8(msg, IEEE80215_ATTR_STATUS, status);
	NLA_PUT_U8(msg, IEEE80215_ATTR_SCAN_TYPE, scan_type);
	NLA_PUT_U32(msg, IEEE80215_ATTR_CHANNELS, unscanned);

	if (edl)
		NLA_PUT(msg, IEEE80215_ATTR_ED_LIST, 27, edl);

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_multicast(msg, 0, ieee80215_coord_mcgrp.id, GFP_ATOMIC);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
out_free:
	nlmsg_free(msg);
out_msg:
	return -ENOBUFS;
}

/* Requests from userspace */

static int ieee80215_associate_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ieee80215_addr addr, saddr;
	u8 buf[2];
	int pos = 0;
	int ret = -EINVAL;

	if (!info->attrs[IEEE80215_ATTR_CHANNEL]
	 || !info->attrs[IEEE80215_ATTR_COORD_PAN_ID]
	 || (!info->attrs[IEEE80215_ATTR_COORD_HW_ADDR] && !info->attrs[IEEE80215_ATTR_COORD_SHORT_ADDR])
	 || !info->attrs[IEEE80215_ATTR_CAPABILITY])
		return -EINVAL;

	if (info->attrs[IEEE80215_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE80215_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE80215_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE80215_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE80215) {
		dev_put(dev);
		return -EINVAL;
	}

	if (info->attrs[IEEE80215_ATTR_COORD_HW_ADDR]) {
		addr.addr_type = IEEE80215_ADDR_LONG;
		NLA_GET_HW_ADDR(info->attrs[IEEE80215_ATTR_COORD_HW_ADDR], addr.hwaddr);
	} else {
		addr.addr_type = IEEE80215_ADDR_SHORT;
		addr.short_addr = nla_get_u16(info->attrs[IEEE80215_ATTR_COORD_SHORT_ADDR]);
	}
	addr.pan_id = nla_get_u16(info->attrs[IEEE80215_ATTR_COORD_PAN_ID]);

	saddr.addr_type = IEEE80215_ADDR_LONG;
	saddr.pan_id = IEEE80215_PANID_BROADCAST;
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE80215_ADDR_LEN);

	// FIXME: set PIB/MIB info
	// FIXME: set channel
	ieee80215_dev_set_pan_id(dev, addr.pan_id);

	buf[pos++] = IEEE80215_CMD_ASSOCIATION_REQ;
	buf[pos++] = nla_get_u8(info->attrs[IEEE80215_ATTR_CAPABILITY]);
	ret = ieee80215_send_cmd(dev, &addr, &saddr, buf, pos);

	dev_put(dev);
	return ret;
}

static int ieee80215_associate_resp(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ieee80215_addr addr, saddr;
	u8 buf[4];
	int pos = 0;
	u16 short_addr;
	int ret = -EINVAL;

	if (!info->attrs[IEEE80215_ATTR_STATUS]
	 || !info->attrs[IEEE80215_ATTR_DEST_HW_ADDR]
	 || !info->attrs[IEEE80215_ATTR_DEST_SHORT_ADDR])
		return -EINVAL;

	if (info->attrs[IEEE80215_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE80215_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE80215_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE80215_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE80215) {
		dev_put(dev);
		return -EINVAL;
	}

	addr.addr_type = IEEE80215_ADDR_LONG;
	NLA_GET_HW_ADDR(info->attrs[IEEE80215_ATTR_DEST_HW_ADDR], addr.hwaddr);
	addr.pan_id = ieee80215_dev_get_pan_id(dev);

	saddr.addr_type = IEEE80215_ADDR_LONG;
	saddr.pan_id = addr.pan_id;
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE80215_ADDR_LEN);

	short_addr = nla_get_u16(info->attrs[IEEE80215_ATTR_DEST_SHORT_ADDR]);

	buf[pos++] = IEEE80215_CMD_ASSOCIATION_RESP;
	buf[pos++] = short_addr;
	buf[pos++] = short_addr >> 8;
	buf[pos++] = nla_get_u8(info->attrs[IEEE80215_ATTR_STATUS]);

	ret = ieee80215_send_cmd(dev, &addr, &saddr, buf, pos);

	dev_put(dev);
	return ret;
}

static int ieee80215_disassociate_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ieee80215_addr addr, saddr;
	u8 buf[2];
	int pos = 0;
	int ret = -EINVAL;

	if ((!info->attrs[IEEE80215_ATTR_DEST_HW_ADDR] && !info->attrs[IEEE80215_ATTR_DEST_SHORT_ADDR])
	 || !info->attrs[IEEE80215_ATTR_REASON])
		return -EINVAL;

	if (info->attrs[IEEE80215_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE80215_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE80215_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE80215_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE80215) {
		dev_put(dev);
		return -EINVAL;
	}

	if (info->attrs[IEEE80215_ATTR_DEST_HW_ADDR]) {
		addr.addr_type = IEEE80215_ADDR_LONG;
		NLA_GET_HW_ADDR(info->attrs[IEEE80215_ATTR_DEST_HW_ADDR], addr.hwaddr);
	} else {
		addr.addr_type = IEEE80215_ADDR_SHORT;
		addr.short_addr = nla_get_u16(info->attrs[IEEE80215_ATTR_DEST_SHORT_ADDR]);
	}
	addr.pan_id = ieee80215_dev_get_pan_id(dev);

	saddr.addr_type = IEEE80215_ADDR_LONG;
	saddr.pan_id = ieee80215_dev_get_pan_id(dev);
	memcpy(saddr.hwaddr, dev->dev_addr, IEEE80215_ADDR_LEN);

	buf[pos++] = IEEE80215_CMD_DISASSOCIATION_NOTIFY;
	buf[pos++] = nla_get_u8(info->attrs[IEEE80215_ATTR_REASON]);
	ret = ieee80215_send_cmd(dev, &addr, &saddr, buf, pos);

	//FIXME: this should be after the ack receved
	ieee80215_dev_set_pan_id(dev, 0xffff);
	ieee80215_dev_set_short_addr(dev, 0xffff);
	ieee80215_nl_disassoc_confirm(dev, 0x00);

	dev_put(dev);
	return ret;
}

static int ieee80215_scan_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	int ret;
	u8 type;
	u32 channels;
	u8 duration;

	if (!info->attrs[IEEE80215_ATTR_SCAN_TYPE]
	 || !info->attrs[IEEE80215_ATTR_CHANNELS]
	 || !info->attrs[IEEE80215_ATTR_DURATION])
		return -EINVAL;

	if (info->attrs[IEEE80215_ATTR_DEV_NAME]) {
		char name[IFNAMSIZ + 1];
		nla_strlcpy(name, info->attrs[IEEE80215_ATTR_DEV_NAME], sizeof(name));
		dev = dev_get_by_name(&init_net, name);
	} else if (info->attrs[IEEE80215_ATTR_DEV_INDEX]) {
		dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE80215_ATTR_DEV_INDEX]));
	} else
		return -ENODEV;

	if (!dev)
		return -ENODEV;
	if (dev->type != ARPHRD_IEEE80215) {
		dev_put(dev);
		return -EINVAL;
	}

	type = nla_get_u8(info->attrs[IEEE80215_ATTR_SCAN_TYPE]);
	channels = nla_get_u32(info->attrs[IEEE80215_ATTR_CHANNELS]);
	duration = nla_get_u8(info->attrs[IEEE80215_ATTR_DURATION]);

	ret = ieee80215_mlme_scan_req(dev, type, channels, duration);

	dev_put(dev);
	return ret;
}

#define IEEE80215_OP(_cmd, _func)			\
	{						\
		.cmd	= _cmd,				\
		.policy	= ieee80215_policy,		\
		.doit	= _func,			\
		.dumpit	= NULL,				\
		.flags	= GENL_ADMIN_PERM,		\
	}

static struct genl_ops ieee80215_coordinator_ops[] = {
	IEEE80215_OP(IEEE80215_ASSOCIATE_REQ, ieee80215_associate_req),
	IEEE80215_OP(IEEE80215_ASSOCIATE_RESP, ieee80215_associate_resp),
	IEEE80215_OP(IEEE80215_DISASSOCIATE_REQ, ieee80215_disassociate_req),
	IEEE80215_OP(IEEE80215_SCAN_REQ, ieee80215_scan_req),
};

#if 0
static int ieee80215_coordinator_rcv(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	char name[IFNAMSIZ + 1];
	struct net_device *dev;


	pr_debug("%s\n", __func__);

	if (!info->attrs[IEEE80215_ATTR_DEV_NAME])
		return -EINVAL;

	nla_strlcpy(name, info->attrs[IEEE80215_ATTR_DEV_NAME], sizeof(name));

	dev = dev_get_by_name(&init_net, name);
	if (!dev)
		goto out_dev;

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq, &ieee80215_coordinator_family, /* flags*/ 0, /* cmd */ 1);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, name);
	NLA_PUT_U64(msg, IEEE80215_ATTR_HW_ADDR, *(u64 *)&dev->dev_addr);

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

int __init ieee80215_nl_init(void)
{
	int rc;
	int i;

	rc = genl_register_family(&ieee80215_coordinator_family);
	if (rc)
		goto fail;

	rc = genl_register_mc_group(&ieee80215_coordinator_family, &ieee80215_coord_mcgrp);
	if (rc)
		goto fail;

	rc = genl_register_mc_group(&ieee80215_coordinator_family, &ieee80215_beacon_mcgrp);
	if (rc)
		goto fail;


	for (i = 0; i < ARRAY_SIZE(ieee80215_coordinator_ops); i++) {
		rc = genl_register_ops(&ieee80215_coordinator_family, &ieee80215_coordinator_ops[i]);
		if (rc)
			goto fail;
	}

	return 0;

fail:
	genl_unregister_family(&ieee80215_coordinator_family);
	return rc;
}

void __exit ieee80215_nl_exit(void)
{
	genl_unregister_family(&ieee80215_coordinator_family);
}

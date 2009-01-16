#include <linux/kernel.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/netdevice.h>
#define IEEE80215_NL_WANT_POLICY
#include <net/ieee80215/nl.h>
#include <net/ieee80215/mac_def.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>

static int ieee80215_coordinator_rcv(struct sk_buff *skb, struct genl_info *info);

static struct genl_family ieee80215_coordinator_family = {
	.id		= GENL_ID_GENERATE,
	.hdrsize	= 0,
	.name		= "802.15.4 MAC",
	.version	= 1,
	.maxattr	= __IEEE80215_CMD_MAX, // FIXME
};

static int ieee80215_associate_req(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ieee80215_addr addr;
	u8 buf[2];
	int pos = 0;
	int ret = -EINVAL;

	if (!info->attrs[IEEE80215_ATTR_DEV_INDEX]
	 || !info->attrs[IEEE80215_ATTR_CHANNEL]
	 || !info->attrs[IEEE80215_ATTR_COORD_PAN_ID]
	 || (!info->attrs[IEEE80215_ATTR_COORD_HW_ADDR] && !info->attrs[IEEE80215_ATTR_COORD_SHORT_ADDR])
	 || !info->attrs[IEEE80215_ATTR_CAPABILITY])
		return -EINVAL;
	dev = dev_get_by_index(&init_net, nla_get_u32(info->attrs[IEEE80215_ATTR_DEV_INDEX]));
	if (!dev) {
		pr_warning("%s: No such device!\n", __func__);
		return -ENODEV;
	}

	if (info->attrs[IEEE80215_ATTR_COORD_HW_ADDR]) {
		addr.addr_type = IEEE80215_ADDR_LONG;
		NLA_GET_HW_ADDR(info->attrs[IEEE80215_ATTR_COORD_HW_ADDR], addr.hwaddr);
	} else {
		addr.addr_type = IEEE80215_ADDR_SHORT;
		addr.short_addr = nla_get_u16(info->attrs[IEEE80215_ATTR_COORD_SHORT_ADDR]);
	}
	addr.pan_id = nla_get_u16(info->attrs[IEEE80215_ATTR_COORD_PAN_ID]);

	// FIXME: set PIB/MIB info
	// FIXME: set channel

	buf[pos++] = IEEE80215_ASSOCIATION_REQ;
	buf[pos++] = nla_get_u8(info->attrs[IEEE80215_ATTR_CAPABILITY]);
	ret = ieee80215_send_cmd(dev, &addr, buf, pos);

	dev_put(dev);
	return ret;
}

static struct genl_ops ieee80215_coordinator_ops[] = {
	{
		.cmd	= IEEE80215_ASSOCIATE_REQ,
		.policy	= ieee80215_policy,
		.doit	= ieee80215_associate_req,
		.dumpit	= NULL,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IEEE80215_DISASSOCIATE_REQ,
		.policy	= ieee80215_policy,
		.doit	= ieee80215_coordinator_rcv,
		.dumpit	= NULL,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IEEE80215_ASSOCIATE_RESP,
		.policy	= ieee80215_policy,
		.doit	= ieee80215_coordinator_rcv,
		.dumpit	= NULL,
		.flags	= GENL_ADMIN_PERM,
	},
};

static int ieee80215_coordinator_rcv(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	char name[IFNAMSIZ + 1];
	struct net_device *dev;


	printk("%s\n", __func__);

	if (!info->attrs[IEEE80215_ATTR_DEV_NAME])
		return -EINVAL;

	nla_strlcpy(name, info->attrs[IEEE80215_ATTR_DEV_NAME], sizeof(name));

	dev = dev_get_by_name(&init_net, name);
	if (!dev)
		goto out_dev;

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		goto out_msg;

	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq, &ieee80215_coordinator_family, /* flags*/ 0, /* cmd */ 1);
	if (!hdr)
		goto out_free;

	NLA_PUT_STRING(msg, IEEE80215_ATTR_DEV_NAME, name);
	NLA_PUT_U64(msg, IEEE80215_ATTR_HW_ADDR, *(u64*)&dev->dev_addr);

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

int __init ieee80215_nl_init(void)
{
	int rc;
	int i;

	rc = genl_register_family(&ieee80215_coordinator_family);
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

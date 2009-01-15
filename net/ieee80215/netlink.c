#include <linux/kernel.h>
#include <net/netlink.h>
#include <net/genetlink.h>

static int ieee80215_coordinator_rcv(struct sk_buff *skb, struct genl_info *info);

enum {
	__IEEE80215_ATTR_MAX,
};

#define IEEE80215_ATTR_MAX (__IEEE80215_ATTR_MAX - 1)

static struct nla_policy ieee80215_policy[IEEE80215_ATTR_MAX + 1] = {
};

/* commands */
/* REQ should be responded with CONF
 * and INDIC with RESP
 */
enum {
	IEEE80215_ASSOCIATE_REQ,
	IEEE80215_ASSOCIATE_CONF,
	IEEE80215_DISASSOCIATE_REQ,
	IEEE80215_DISASSOCIATE_CONF,

	IEEE80215_ASSOCIATE_INDIC,
	IEEE80215_ASSOCIATE_RESP,
	IEEE80215_DISASSOCIATE_INDIC,

	__IEEE80215_CMD_MAX,
};

#define IEEE80215_CMD_MAX (__IEEE80215_CMD_MAX - 1)

static struct genl_family ieee80215_coordinator_family = {
	.id		= GENL_ID_GENERATE,
	.hdrsize	= 0,
	.name		= "802.15.4 MAC",
	.version	= 1,
	.maxattr	= __IEEE80215_CMD_MAX, // FIXME
};

static struct genl_ops ieee80215_coordinator_ops[] = {
	{
		.cmd	= IEEE80215_ASSOCIATE_REQ,
		.flags	= 0,
		.policy	= ieee80215_policy,
		.doit	= ieee80215_coordinator_rcv,
		.dumpit	= NULL,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IEEE80215_DISASSOCIATE_REQ,
		.flags	= 0,
		.policy	= ieee80215_policy,
		.doit	= ieee80215_coordinator_rcv,
		.dumpit	= NULL,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= IEEE80215_ASSOCIATE_RESP,
		.flags	= 0,
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

	printk("%s\n", __func__);

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		goto err;

	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq, &ieee80215_coordinator_family, /* flags*/ 0, /* cmd */ 1);
	if (!hdr)
		goto out_free;

	if (!genlmsg_end(msg, hdr))
		goto out_free;

	return genlmsg_unicast(msg, info->snd_pid);
out_free:
	nlmsg_free(msg);

err:
	return -ENOBUFS;


	return 0;
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

#ifndef  _AF_IEEE80215_H
#define  _AF_IEEE80215_H
#include <linux/if.h>
//#include <net/ieee80215/lib.h>
#include <net/ieee80215/const.h>
#define  IEEE80215_MSG_CHANNEL_CONFIRM		1
#define  IEEE80215_MSG_ED_CONFIRM		2
#define  IEEE80215_MSG_CCA_CONFIRM		3
#define  IEEE80215_MSG_SET_STATE		4
#define  IEEE80215_MSG_XMIT_BLOCK_CONFIRM	5
#define  IEEE80215_MSG_XMIT_STREAM_CONFIRM	6
#define  IEEE80215_MSG_RECV_BLOCK		7
#define  IEEE80215_MSG_RECV_STREAM		8

enum {
	IEEE80215_ADDR_NONE = 0x0,
	// RESERVER = 0x01,
	IEEE80215_ADDR_SHORT = 0x2, /* 16-bit address + PANid */
	IEEE80215_ADDR_LONG = 0x3, /* 64-bit address + PANid */
};

struct ieee80215_addr {
	int addr_type;
	u16 pan_id;
	union {
		u8 hwaddr[IEEE80215_ADDR_LEN];
		u16 short_addr;
	};
};

struct sockaddr_ieee80215 {
	sa_family_t family; /* AF_IEEE80215 */
	struct ieee80215_addr addr;
};

struct ieee80215_user_data {
	/* This is used as ifr_name */
	union
	{
		char	ifrn_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	} ifr_ifrn;
	int channels;
	int channel;
	int duration;
	int rejoin;
	int rxon;
	int as_router;
	int power;
	int mac_security;
	u16 panid;
	int cmd;
//	struct ieee80215_dev_address addr; /**< Peer address */
};

/* PF_IEEE80215, SOCK_DGRAM */
#define IEEE80215_SIOC_NETWORK_DISCOVERY	(SIOCPROTOPRIVATE + 0)
#define IEEE80215_SIOC_NETWORK_FORMATION	(SIOCPROTOPRIVATE + 1)
#define IEEE80215_SIOC_PERMIT_JOINING		(SIOCPROTOPRIVATE + 2)
#define IEEE80215_SIOC_START_ROUTER		(SIOCPROTOPRIVATE + 3)
#define IEEE80215_SIOC_JOIN			(SIOCPROTOPRIVATE + 4)
#define IEEE80215_SIOC_MAC_CMD			(SIOCPROTOPRIVATE + 5)

/* master device */
#define IEEE80215_SIOC_ADD_SLAVE		(SIOCDEVPRIVATE + 0)

#ifdef __KERNEL__
/* Per spec; optimizations are needed */
struct ieee80215_pandsc {
	struct list_head	list;
	struct ieee80215_addr	addr; /* Contains panid */
	int			channel;
	u16			sf;
	bool			gts_permit;
	u8			lqi;
	u32			timestamp; /* FIXME */
	bool			security;
	u8			mac_sec;
	bool			sec_fail;
};

int ioctl_network_discovery(struct sock *sk, struct ieee80215_user_data __user *data);
int ioctl_network_formation(struct sock *sk, struct ieee80215_user_data __user *data);
int ioctl_permit_joining(struct sock *sk, struct ieee80215_user_data __user *data);
int ioctl_start_router(struct sock *sk, struct ieee80215_user_data __user *data);
int ioctl_mac_join(struct sock *sk, struct ieee80215_user_data __user *data);
int ioctl_mac_cmd(struct sock *sk, struct ieee80215_user_data __user *data);

extern struct proto ieee80215_raw_prot;
extern struct proto ieee80215_dgram_prot;
void ieee80215_raw_deliver(struct net_device *dev, struct sk_buff *skb);
int ieee80215_dgram_deliver(struct net_device *dev, struct sk_buff *skb);
#endif

#endif

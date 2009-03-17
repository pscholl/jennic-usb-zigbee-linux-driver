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

extern struct proto ieee80215_raw_prot;
extern struct proto ieee80215_dgram_prot;
void ieee80215_raw_deliver(struct net_device *dev, struct sk_buff *skb);
int ieee80215_dgram_deliver(struct net_device *dev, struct sk_buff *skb);
#endif

#endif

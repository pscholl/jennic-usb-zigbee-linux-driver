#ifndef  _AF_IEEE80215_H
#define  _AF_IEEE80215_H

#include <linux/socket.h> /* for sa_family_t */

enum {
	IEEE80215_ADDR_NONE = 0x0,
	// RESERVED = 0x01,
	IEEE80215_ADDR_SHORT = 0x2, /* 16-bit address + PANid */
	IEEE80215_ADDR_LONG = 0x3, /* 64-bit address + PANid */
};

/* address length, octets */
#define IEEE80215_ADDR_LEN	8

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
#include <linux/skbuff.h>
#include <linux/netdevice.h>
extern struct proto ieee80215_raw_prot;
extern struct proto ieee80215_dgram_prot;
void ieee80215_raw_deliver(struct net_device *dev, struct sk_buff *skb);
int ieee80215_dgram_deliver(struct net_device *dev, struct sk_buff *skb);
#endif

#endif

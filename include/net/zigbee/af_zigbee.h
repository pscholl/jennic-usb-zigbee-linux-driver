#ifndef  _AF_ZIGBEE_H
#define  _AF_ZIGBEE_H
#include <linux/if.h>

struct sockaddr_zb {
	sa_family_t family; /* AF_ZIGBEE */
	u16 addr;
};

#ifdef __KERNEL__
extern struct proto zb_raw_prot;
extern struct proto zb_dgram_prot;
void zb_raw_deliver(struct net_device *dev, struct sk_buff *skb);
int zb_dgram_deliver(struct net_device *dev, struct sk_buff *skb);
#endif

#endif /* _AF_ZIGBEE_H */

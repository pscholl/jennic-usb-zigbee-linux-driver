#ifndef  _AF_IEEE80215_H
#define  _AF_IEEE80215_H
#include <net/ieee80215/lib.h>
#define  IEEE80215_MSG_CHANNEL_CONFIRM		1
#define  IEEE80215_MSG_ED_CONFIRM		2
#define  IEEE80215_MSG_CCA_CONFIRM		3
#define  IEEE80215_MSG_SET_STATE		4
#define  IEEE80215_MSG_XMIT_BLOCK_CONFIRM	5
#define  IEEE80215_MSG_XMIT_STREAM_CONFIRM	6
#define  IEEE80215_MSG_RECV_BLOCK		7
#define  IEEE80215_MSG_RECV_STREAM		8
#endif

struct ieee80215_user_data {
	int channels;
	int channel;
	int duration;
	int rejoin;
	int rxon;
	int as_router;
	int power;
	int mac_security;
	u16 panid; 
	struct ieee80215_dev_address addr; /**< Peer address */
};

#define IEEE80215_SIOC_NETWORK_DISCOVERY	SIOCPROTOPRIVATE
#define IEEE80215_SIOC_NETWORK_FORMATION	(SIOCPROTOPRIVATE + 1)
#define IEEE80215_SIOC_PERMIT_JOINING		(SIOCPROTOPRIVATE + 2)
#define IEEE80215_SIOC_START_ROUTER		(SIOCPROTOPRIVATE + 3)
#define IEEE80215_SIOC_JOIN			(SIOCPROTOPRIVATE + 4)


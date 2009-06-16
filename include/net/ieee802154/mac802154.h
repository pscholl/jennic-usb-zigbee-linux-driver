/*
 * IEEE802.15.4-2003 specification
 *
 * Copyright (C) 2007, 2008 Siemens AG
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
 */
#ifndef IEEE802154_MAC802154_H
#define IEEE802154_MAC802154_H

/* FIXME: this can be merged with const.h ? */
typedef enum {
	PHY_BUSY = 0, /* cca */
	PHY_BUSY_RX, /* state */
	PHY_BUSY_TX, /* state */
	PHY_FORCE_TRX_OFF,
	PHY_IDLE, /* cca */
	PHY_INVALID_PARAMETER, /* pib get/set */
	PHY_RX_ON, /* state */
	PHY_SUCCESS, /* ed */
	PHY_TRX_OFF, /* cca, ed, state */
	PHY_TX_ON, /* cca, ed, state */
	PHY_UNSUPPORTED_ATTRIBUTE, /* pib get/set */
	PHY_READ_ONLY, /* pib get/set */

	PHY_INVAL = -1, /* all */
	PHY_ERROR = -2, /* all */
} phy_status_t;

struct ieee802154_dev {
	const char *name;
	int	extra_tx_headroom; /* headroom to reserve for tx skb */
	void	*priv;		/* driver-specific data */
	u32	channel_mask;
	u8	current_channel;
	u32 flags; /* Flags for device to set */
	struct device *parent;
	struct net_device *netdev; /* mwpanX device */
};

/* Checksum is in hardware and is omitted from packet */
#define IEEE802154_FLAGS_OMIT_CKSUM	(1 << 0)

struct sk_buff;

struct ieee802154_ops {
	struct module	*owner;
	phy_status_t (*tx)(struct ieee802154_dev *dev, struct sk_buff *skb);
	phy_status_t (*cca)(struct ieee802154_dev *dev);
	phy_status_t (*ed)(struct ieee802154_dev *dev, u8 *level);
	phy_status_t (*set_trx_state)(struct ieee802154_dev *dev,
			phy_status_t state);
	phy_status_t (*set_channel)(struct ieee802154_dev *dev, int channel);
	/* FIXME: PIB get/set ??? */
};

struct ieee802154_dev *ieee802154_alloc_device(void);
int ieee802154_register_device(struct ieee802154_dev *dev,
		struct ieee802154_ops *ops);
void ieee802154_unregister_device(struct ieee802154_dev *dev);
void ieee802154_free_device(struct ieee802154_dev *dev);

int ieee802154_add_slave(struct ieee802154_dev *hw, const u8 *addr);
void ieee802154_del_slave(struct net_device *dev);

void ieee802154_rx(struct ieee802154_dev *dev, struct sk_buff *skb, u8 lqi);
void ieee802154_rx_irqsafe(struct ieee802154_dev *dev, struct sk_buff *skb,
		u8 lqi);
#endif


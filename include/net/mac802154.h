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
#ifndef NET_MAC802154_H
#define NET_MAC802154_H

#include <net/af_ieee802154.h>

/**
 * enum ieee802154_hw_addr_filt_flags - hardware flags
 *
 * These flags are used to indicate changed address settings from
 * the stack to the hardware.
 *
 * @IEEE802515_SADDR_CHANGED:
 *	Indicates that the Short Address changed
 *
 * @IEEE802515_IEEEADDR_CHANGED:
 *	Indicates that the IEEE Address changed
 *
 * @IEEE802515_PANID_CHANGED:
 *	Indicates that the PAN ID changed
 *
 * @IEEE802515_PANC_CHANGED:
 *	Indicates that PAN Coordinator status changed
 */
enum ieee802154_hw_addr_filt_flags {
	IEEE802515_SADDR_CHANGED	= 1 << 0,
	IEEE802515_IEEEADDR_CHANGED	= 1 << 1,
	IEEE802515_PANID_CHANGED	= 1 << 2,
	IEEE802515_PANC_CHANGED	 = 1 << 3,
};

struct ieee802154_hw_addr_filt {
	u16 pan_id;
	u16 short_addr;
	u8 ieee_addr[IEEE802154_ADDR_LEN];
	u8 pan_coord;
};

struct ieee802154_dev {
	/* filled by the driver */
	int	extra_tx_headroom; /* headroom to reserve for tx skb */
	u32	flags; /* Flags for device to set */
	struct device *parent;

	/* filled by mac802154 core */
	struct ieee802154_hw_addr_filt hw_filt;
	void	*priv;		/* driver-specific data */
	struct wpan_phy *phy;
};

/* Checksum is in hardware and is omitted from packet */
/**
 * enum ieee802154_hw_flags - hardware flags
 *
 * These flags are used to indicate hardware capabilities to
 * the stack. Generally, flags here should have their meaning
 * done in a way that the simplest hardware doesn't need setting
 * any particular flags. There are some exceptions to this rule,
 * however, so you are advised to review these flags carefully.
 *
 * @IEEE802154_HW_OMIT_CKSUM:
 *	Indicates that receiver omits FCS and transmitter will add
 *	FCS on it's own.
 *
 * @IEEE802154_HW_AACK:
 * 	Indicates that receiver will autorespond with ACK frames.
 */
enum ieee802154_hw_flags {
	IEEE802154_HW_OMIT_CKSUM			= 1 << 0,
	IEEE802154_HW_AACK				= 1 << 1,
};

struct sk_buff;

/**
 * struct ieee802154_ops - callbacks from mac802154 to the driver
 *
 * This structure contains various callbacks that the driver may
 * handle or, in some cases, must handle, for example to transmit
 * a frame.
 *
 * @start: Handler that 802.15.4 module calls for device initialisation.
 * 	This function is called before the first interface is attached.
 *
 * @stop: Handler that 802.15.4 module calls for device cleanup
 * 	This function is called after the last interface is removed.
 *
 * @xmit: Handler that 802.15.4 module calls for each transmitted frame.
 *	skb cntains the buffer starting from the IEEE 802.15.4 header.
 *	The low-level driver should send the frame based on available
 *	configuration.
 *	This function should return zero or negative errno.
 *	Called with pib_lock held.
 *
 * @ed: Handler that 802.15.4 module calls for Energy Detection.
 *	This function should place the value for detected energy
 *	(usually device-dependant) in the level pointer and return
 *	either zero or negative errno.
 *	Called with pib_lock held.
 *
 * @set_channel: Set radio for listening on specific channel.
 *	Set the device for listening on specified channel.
 *	Returns either zero, or negative errno.
 *	Called with pib_lock held.
 *
 * @set_hw_addr_filt: Set radio for listening on specific address.
 *	Set the device for listening on specified address.
 *	Returns either zero, or negative errno.
 */
struct ieee802154_ops {
	struct module	*owner;
	int		(*start)(struct ieee802154_dev *dev);
	void		(*stop)(struct ieee802154_dev *dev);
	int		(*xmit)(struct ieee802154_dev *dev,
					struct sk_buff *skb);
	int		(*ed)(struct ieee802154_dev *dev, u8 *level);
	int		(*set_channel)(struct ieee802154_dev *dev,
					int channel);
	int		(*set_hw_addr_filt)(struct ieee802154_dev *dev,
					struct ieee802154_hw_addr_filt *filt,
					unsigned long changed);
};

struct ieee802154_dev *ieee802154_alloc_device(size_t priv_size,
						struct ieee802154_ops *ops);
int ieee802154_register_device(struct ieee802154_dev *dev);
void ieee802154_unregister_device(struct ieee802154_dev *dev);
void ieee802154_free_device(struct ieee802154_dev *dev);

void ieee802154_rx(struct ieee802154_dev *dev, struct sk_buff *skb, u8 lqi);
void ieee802154_rx_irqsafe(struct ieee802154_dev *dev, struct sk_buff *skb,
		u8 lqi);
#endif


/*
 * IEEE802.15.4-2003 specification
 * Physical interface.
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
 * Pavel Smolenskiy <pavel.smolenskiy@gmail.com>
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Maxim Osipov <maxim.osipov@siemens.com>
 */

#ifndef IEEE80215_PHY_H
#define IEEE80215_PHY_H

/******************************************************************************/
/* PHY constants */
/******************************************************************************/
/** The maximum PSDU size (in octets) the PHY shall be able to receive,
 * 127 octets
 */
#define IEEE80215_MAX_PHY_PACKET_SIZE	127

/** RX-to-TX or TX-to-RX maximum turnaround time in symbol periods */
#define IEEE80215_TURNAROUND_TIME 	12

/******************************************************************************/
/* PAN Information Base (PIB), PHY attribute identifiers */
/* See IEEE802.15.4-2003 draft, Table 19 */
/******************************************************************************/
/**
 * The RF channel to use for all following transmissions and receptions
 * (Integer, 0-26)
 */
#define IEEE80215_PHY_CURRENT_CHANNEL		0x00

/**
 * The 5 most significant bits (MSBs) (b27,... ,b31) of phyChannelsSupported
 * shall be reserved and set to 0, and the 27 LSBs (b0,b1, ... b26) shall
 * indicate the status (1=available, 0=unavailable) for each of the 27 valid
 * channels (bk shall indicate the status of channel k) (Bitmap)
 */
#define IEEE80215_PHY_CHANNELS_SUPPORTED	0x01

/**
 * The 2 MSBs represent the tolerance on the transmit power:
 *
 * 00 = +- 1 dB
 * 01 = +- 3 dB
 * 02 = +- 6 dB
 *
 * The 6 LSBs represent a signed integer in twos-complement format,
 * corresponding to the nominal transmit power of the device in decibels
 * relative to 1 mW. The lowest value of phyTransmitPower shall be interpreted
 * as less than or equal -32 dBm (Bitmap, 0x00-0xBF)
 */
#define IEEE80215_PHY_TRANSMIT_POWER	0x02

/** The CCA mode (Integer, 1-3) */
#define IEEE80215_PHY_CCA_MODE		0x03

#define IEEE80215_CCA_ED		0x1
#define IEEE80215_CCA_CS		0x2
#define IEEE80215_CCA_CSED		0x3

/******************************************************************************/
/* PAN Information Base (PIB), attribute ranges */
/* See IEEE802.15.4-2003 draft, Table 19 */
/******************************************************************************/
#define IEEE80215_PHY_CURRENT_CHANNEL_MIN	0x0
#define IEEE80215_PHY_CURRENT_CHANNEL_MAX	0x1a

#define IEEE80215_PHY_CHANNELS_SUPPORTED_MIN	0x0
#define IEEE80215_PHY_CHANNELS_SUPPORTED_MAX	0x7FFFFFF

#define IEEE80215_PHY_TRANSMIT_POWER_MIN	0x0
#define IEEE80215_PHY_TRANSMIT_POWER_MAX	0xbf

#define IEEE80215_PHY_CCA_MODE_MIN		0x1
#define IEEE80215_PHY_CCA_MODE_MAX		0x3

#ifdef __KERNEL__

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

#endif /* __KERNEL__ */

#endif

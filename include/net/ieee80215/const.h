/*
 * ieee80215_const.h
 *
 * Description: IEEE 802.15.4 Constants and return codes.
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
 */

#ifndef IEEE80215_CONST_H
#define IEEE80215_CONST_H

#define IEEE80215_ACK_LEN	3	/* Size of acknowledge frame */

/* Time related constants, in microseconds.
 *
 * The 1SYM_TIME values are shown how much time is needed to transmit one
 * symbol across media.
 * The callculation is following:
 * For a 2450 MHZ radio freq rate is 62,5 ksym/sec. A byte (8 bit) transfered
 * by low 4 bits in first symbol, high 4 bits in next symbol. So, to transmit
 * 1 byte in 2450Mhz freq 2 symbols are needed. Therefore we have 31,25 kbyte/sec
 * rate. 1 symbol transfered in 16*10^(-6) sec, or 16 microseconds.
 * For a 868Mhz and 915Mhz, 1 symbol is equal to 1 byte. So, we have 20kbyte/sec
 * and 40 kbyte/sec respectively. And 5*10^(-5) sec and 2,5*10(-5) sec,
 * or 50 and 25 microseconds respectively for 868Mhz and 915Mhz freq.
 */
#define IEEE80215_2450MHZ_1SYM_TIME	16
#define IEEE80215_868MHZ_1SYM_TIME	50
#define IEEE80215_915MHZ_1SYM_TIME	25

/******************************************************************************/
/* MAC constants */
/******************************************************************************/
/** The number of symbols forming a superframe slot when the superframe order
 * is equal to 0.
 */
#define IEEE80215_BASE_SD	60

/** The number of slots contained in any superframe. */
#define IEEE80215_NUM_SFS	16

/** The number of symbols forming a superframe when the superframe order is
 * equal to 0.
 */
#define IEEE80215_BASE_SFD	IEEE80215_BASE_SD*IEEE80215_NUM_SFS

/** The 64 bit (IEEE) address assigned to the device. */
#define IEEE80215_EXT_ADDR		0

/** The maximum value of the backoff exponent in the CSMA-CA algorithm. */
#define IEEE80215_MAXBE			5

/** The maximum number of octets added by the MAC sublayer to the payload of
 * its beacon frame.
 */
#define IEEE80215_MAX_BOVERHEAD		75

/** The maximum size, in octets, of a beacon payload. */
#define IEEE80215_MAX_BPAYLOAD	IEEE80215_MAX_PHY_PACKET_SIZE - IEEE80215_MAX_BOVERHEAD

/** The number of superframes in which a GTS descriptor exists in the beacon
 * frame of a PAN coordinator.
 */
#define IEEE80215_GTS_DESC_PERS_TIME	4

/** The maximum number of octets added by the MAC sublayer to its payload
 * without security. If security is required on a frame, its secure processing
 * may inflate the frame length so that it is greater than this value. In
 * this case, an error is generated through the appropriate .confirm or
 * MLME-COMM-STATUS.indication primitives.
 */
#define IEEE80215_MAX_FRAME_OVERHEAD	25

/** The maximum number of CAP symbols in a beaconenabled PAN, or symbols in a
 * nonbeacon-enabled PAN, to wait for a frame intended as a response to a
 * data request frame.
 */
#define IEEE80215_MAX_FRAME_RESP_TIME	1220

/** The maximum number of retries allowed after a transmission failure. */
#define IEEE80215_MAX_FRAME_RETRIES		3

/** The number of consecutive lost beacons that will cause the MAC sublayer of
 * a receiving device to declare a loss of synchronization.
 */
#define IEEE80215_MAX_LOST_BEACONS		4

/** The maximum number of octets that can be transmitted in the MAC frame
 * payload field.
 */
#define IEEE80215_MAX_FRAME_SIZE		IEEE80215_MAX_PHY_PACKET_SIZE - IEEE80215_MAX_FRAME_OVERHEAD

/** The maximum size of an MPDU, in octets, that can be followed by a short
 * interframe spacing (SIFS) period.
 */
#define IEEE80215_MAX_SIFS_FRAME_SIZE	18

/** The minimum number of symbols forming the CAP. This ensures that MAC
 * commands can still be transferred to devices when GTSs are being used.
 * An exception to this minimum shall be allowed for the accommodation of the
 * temporary increase in the beacon frame length needed to perform GTS
 * maintenance (see 802.15.4-2003.pdf, item 7.2.2.1.3). */
#define IEEE80215_MIN_CAP_LEN		440

/** The minimum number of symbols forming a long interframe spacing (LIFS) period. */
#define IEEE80215_MIN_LIFS_PERIOD		40

/** The minimum number of symbols forming a SIFS period. */
#define IEEE80215_MIN_SIFS_PERIOD		12

/** The maximum number of symbols a device shall wait for a response command to
 * be available following a request command.
 */
#define IEEE80215_RESPONSE_WAIT_TIME	32*IEEE80215_BASE_SFD

/** The number of symbols forming the basic time period used by the CSMA-CA
 * algorithm.
 */
#define IEEE80215_UNIT_BACKOFF_PERIOD	20

/******************************************************************************/
/* PAN Information Base (PIB), MAC attribute identifiers */
/* See IEEE802.15.4-2003 draft, Table 71 */
/******************************************************************************/
/** The maximum number of symbols to wait for an acknowledgment frame to arrive
 * following a transmitted data frame. This value is dependent on the currently
 * selected logical channel. For 0 ≤ phyCurrentChannel ≤ 10, this value is equal
 * to 120. For 11 ≤ phyCurrentChannel ≤ 26, this value is equal to 54.
 */
#define IEEE80215_ACK_WAIT_DURATION		0x40

/** Indication of whether a coordinator is currently allowing association.
 * A value of TRUE indicates that association is permitted.
 */
#define IEEE80215_ASSOCIATION_PERMIT	0x41

/** Indication of whether a device automatically sends a data request command
 * if its address is listed in the beacon frame. A value of TRUE indicates that
 * the data request command is automatically sent.
 */
#define IEEE80215_AUTO_REQUEST		0x42

/** Indication of whether battery life extension, by reduction of coordinator
 * receiver operation time during the CAP, is enabled. A value of TRUE indicates
 * that it is enabled.
 */
#define IEEE80215_BAT_LIFE_EXT		0x43

/** The number of backoff periods during which the receiver is enabled following
 * a beacon in battery life extension mode. This value is dependent on the
 * currently selected logical channel. For 0 ≤ phyCurrentChannel ≤ 10, this
 * value is equal to 8. For 11 ≤ phyCurrentChannel ≤ 26, this value is equal
 * to 6.
 */
#define IEEE80215_BAT_LIFE_EXT_PERIOD	0x44

/** The contents of the beacon payload.*/
#define IEEE80215_BEACON_PAYLOAD		0x45

/** The length, in octets, of the beacon payload.*/
#define IEEE80215_BEACON_PAYLOAD_LEN	0x46

/** Specification of how often the coordinator transmits a beacon. The
 * macBeaconOrder, BO, and the beacon interval, BI, are related as follows:
 * for 0 ≤ BO ≤ 14, BI = aBaseSuperframeDuration * 2BO symbols. If BO = 15,
 * the coordinator will not transmit a beacon.
 */
#define IEEE80215_BEACON_ORDER		0x47

/** The time that the device transmitted its last beacon frame, in symbol
 * periods. The measurement shall be taken at the same symbol boundary within
 * every transmitted beacon frame, the location of which is implementation
 * specific. The precision of this value shall be a minimum of 20 bits, with the
 * lowest four bits being the least significant.
 */
#define IEEE80215_BEACON_TX_TIME		0x48

/** The sequence number added to the transmitted beacon frame. */
#define IEEE80215_BSN			0x49

/** The 64 bit address of the coordinator with which the device is associated. */
#define IEEE80215_COORD_EXTENDED_ADDRESS	0x4a

/** The 16 bit short address assigned to the coordinator with which the device
 * is associated. A value of 0xfffe indicates that the coordinator is only
 * using its 64 bit extended address. A value of 0xffff indicates that this
 * value is unknown.
 */
#define IEEE80215_COORD_SHORT_ADDRESS	0x4b

/** The sequence number added to the transmitted data or MAC command frame. */
#define IEEE80215_DSN			0x4c

/** TRUE if the PAN coordinator is to accept GTS requests. FALSE otherwise. */
#define IEEE80215_GTS_PERMIT		0x4d

/** The maximum number of backoffs the CSMA-CA algorithm will attempt before
 * declaring a channel access failure.
 */
#define IEEE80215_MAX_CSMA_BACKOFF		0x4e

/** The minimum value of the backoff exponent in the CSMA-CA algorithm. Note
 * that if this value is set to 0, collision avoidance is disabled during the
 * first iteration of the algorithm. Also note that for the slotted version of
 * the CSMACA algorithm with the battery life extension enabled, the minimum
 * value of the backoff exponent will be the lesser of 2 and the value of
 * macMinBE.
 */
#define IEEE80215_MIN_BE			0x4f

/** The 16 bit identifier of the PAN on which the device is operating. If this
 * value is 0 x ffff, the device is not associated.
 */
#define IEEE80215_PANID			0x50

/** This indicates whether the MAC sublayer is in a promiscuous (receive all)
 * mode. A value of TRUE indicates that the MAC sublayer accepts all frames
 * received from the PHY.
 */
#define IEEE80215_PROMISCOUS_MODE		0x51

/** This indicates whether the MAC sublayer is to enable its receiver during
 * idle periods.
 */
#define IEEE80215_RXON_WHEN_IDLE		0x52

/** The 16 bit address that the device uses to communicate in the PAN. If the
 * device is a PAN coordinator, this value shall be chosen before a PAN is
 * started. Otherwise, the address is allocated by a coordinator during
 * association. A value of 0xfffe indicates that the device has associated but
 * has not been allocated an address. A value of 0xffff indicates that the
 * device does not have a short address.
 */
#define IEEE80215_SHORT_ADDRESS		0x53

/** This specifies the length of the active portion of the superframe, including
 * the beacon frame. The macSuperframeOrder, SO, and the superframe duration,
 * SD, are related as follows: for 0 ≤ SO ≤ BO ≤ 14, SD = aBaseSuperframeDuration * 2SO
 * symbols. If SO = 15, the superframe will not be active following the beacon.
 */
#define IEEE80215_SUPERFRAME_ORDER		0x54

/** The maximum time (in superframe periods) that a transaction is stored by a
 * coordinator and indicated in its beacon.
 */
#define IEEE80215_TRANSACTION_PERSISTENSE_TIME	0x55

/******************************************************************************/
/* PAN Information Base (PIB), MAC attribute ranges */
/* See IEEE802.15.4-2003 draft, Table 71 */
/******************************************************************************/
/**
 * The maximum number of symbols to wait for an acknowledgment frame to arrive
 * following a transmitted data frame. This value is dependent on the currently
 * selected logical channel. For 0 ≤ phyCurrentChannel ≤ 10, this value is equal
 * to 120. For 11 ≤ phyCurrentChannel ≤ 26, this value is equal to 54.
 */
#define IEEE80215_ACK_WAIT_DURATION_DEF	0x36
#define IEEE80215_ACK_WAIT_DURATION_MIN	0x36
#define IEEE80215_ACK_WAIT_DURATION_MAX	0x78

/**
 * Indication of whether a coordinator is currently allowing association. A
 * value of TRUE indicates that association is permitted.
 */
#define IEEE80215_ASSOCIATION_PERMIT_DEF	false

/**
 * Indication of whether a device automatically sends a data request command if
 * its address is listed in the beacon frame. A value of TRUE indicates that the
 * data request command is automatically sent.
 */
#define IEEE80215_AUTO_REQUEST_DEF		true

/**
 * Indication of whether battery life extension, by reduction of coordinator
 * receiver operation time during the CAP, is enabled. A value of TRUE indicates
 * that it is enabled.
 */
#define IEEE80215_BAT_LIFE_EXT_DEF		true

/**
 * The number of backoff periods during which the receiver is enabled following
 * a beacon in battery life extension mode. This value is dependent on the
 * currently selected logical channel. For 0 ≤ phyCurrentChannel ≤ 10, this
 * value is equal to 8. For 11 ≤ phyCurrentChannel ≤ 26, this value is equal
 * to 6.
 */
#define IEEE80215_BAT_LIFE_EXT_PERIOD_DEF	0x6
#define IEEE80215_BAT_LIFE_EXT_PERIOD_MIN	0x6
#define IEEE80215_BAT_LIFE_EXT_PERIOD_MAX	0x8

/**
 * The contents of the beacon payload.
 */
#define IEEE80215_BEACON_PAYLOAD_DEF	NULL

/**
 * The length, in octets, of the beacon payload.
 */
#define IEEE80215_BEACON_PAYLOAD_LEN_DEF	0x0
#define IEEE80215_BEACON_PAYLOAD_LEN_MIN	0x0
#define IEEE80215_BEACON_PAYLOAD_LEN_MAX	IEEE80215_BEACON_PAYLOAD_LEN

/**
 * Specification of how often the coordinator transmits a beacon. The
 * macBeaconOrder, BO, and the beacon interval, BI, are related as follows:
 * for 0 ≤ BO ≤ 14, BI = aBaseSuperframeDuration * 2BO symbols. If BO = 15, the
 * coordinator will not transmit a beacon.
 */
#define IEEE80215_BEACON_ORDER_DEF		0xf
#define IEEE80215_BEACON_ORDER_MIN		0x0
#define IEEE80215_BEACON_ORDER_MAX		0xf

/**
 * The time that the device transmitted its last beacon frame, in symbol periods.
 * The measurement shall be taken at the same symbol boundary within every
 * transmitted beacon frame, the location of which is implementation specific.
 * The precision of this value shall be a minimum of 20 bits, with the lowest
 * four bits being the least significant.
 */
#define IEEE80215_BEACON_TX_TIME_DEF	0x0
#define IEEE80215_BEACON_TX_TIME_MIN	0x0
#define IEEE80215_BEACON_TX_TIME_MAX	0xffffffff

/**
 * The sequence number added to the transmitted beacon frame.
 */
//#define IEEE80215_BSN_DEF			ieee80215_random_range(0, 0xf)
#define IEEE80215_BSN_MIN			0x0
#define IEEE80215_BSN_MAX			0xff

/**
 * The 16 bit short address assigned to the coordinator with which the device is
 * associated. A value of 0xfffe indicates that the coordinator is only using
 * its 64 bit extended address. A value of 0xffff indicates that this value is
 * unknown.
 */
#define IEEE80215_COORD_SHORT_ADDRESS_DEF	0xffff
#define IEEE80215_COORD_SHORT_ADDRESS_MIN	0x0
#define IEEE80215_COORD_SHORT_ADDRESS_MAX	0xffff
#define IEEE80215_COORD_SHORT_ADDRESS_64BIT	0xfffe

#define IEEE80215_COORD_EXT_ADDRESS_DEF		0xffffffff

/**
 * The sequence number added to the transmitted data or MAC command frame.
 */
//#define IEEE80215_DSN_DEF			ieee80215_random_range(0, 0xf)
#define IEEE80215_DSN_MIN			0x0
#define IEEE80215_DSN_MAX			0xff

/**
 * TRUE if the PAN coordinator is to accept GTS requests. FALSE otherwise.
 */
#define IEEE80215_GTS_PERMIT_DEF		true

/**
 * The maximum number of backoffs the CSMA-CA algorithm will attempt before
 * declaring a channel access failure.
 */
#define IEEE80215_MAX_CSMA_BACKOFF_DEF	0x4
#define IEEE80215_MAX_CSMA_BACKOFF_MIN	0x0
#define IEEE80215_MAX_CSMA_BACKOFF_MAX	0x5

/**
 * The minimum value of the backoff exponent in the CSMA-CA algorithm. Note that
 * if this value is set to 0, collision avoidance is disabled during the first
 * iteration of the algorithm. Also note that for the slotted version of the
 * CSMA-CA algorithm with the battery life extension enabled, the minimum value
 * of the backoff exponent will be the lesser of 2 and the value of macMinBE.
 */
#define IEEE80215_MIN_BE_DEF		0x3
#define IEEE80215_MIN_BE_MIN		0x0
#define IEEE80215_MIN_BE_MAX		0x3

/**
 * The 16 bit identifier of the PAN on which the device is operating. If this
 * value is 0xffff, the device is not associated.
 */
#define IEEE80215_PANID_DEF			0xffff
#define IEEE80215_PANID_MIN			0x0
#define IEEE80215_PANID_MAX			0xffff

/**
 * This indicates whether the MAC sublayer is in a promiscuous (receive all)
 * mode. A value of TRUE indicates that the MAC sublayer accepts all frames
 * received from the PHY.
 */
#define IEEE80215_PROMISCOUS_MODE_DEF	false

/**
 * This indicates whether the MAC sublayer is to enable its receiver during idle
 * periods.
 */
#define IEEE80215_RXON_WHEN_IDLE_DEF	false

/**
 * The 16 bit address that the device uses to communicate in the PAN. If the
 * device is a PAN coordinator, this value shall be chosen before a PAN is
 * started. Otherwise, the address is allocated by a coordinator during
 * association. A value of 0xfffe indicates that the device has associated but
 * has not been allocated an address. A value of 0xffff indicates that the
 * device does not have a short address.
 */
#define IEEE80215_SHORT_ADDRESS_DEF		0xffff
#define IEEE80215_SHORT_ADDRESS_MIN		0x0
#define IEEE80215_SHORT_ADDRESS_MAX		0xffff

/**
 * This specifies the length of the active portion of the superframe, including
 * the beacon frame. The macSuperframeOrder, SO, and the superframe duration,
 * SD, are related as follows: for 0 ≤ SO ≤ BO ≤ 14,
 * SD = aBaseSuperframeDuration * 2SO symbols. If SO = 15, the superframe will
 * not be active following the beacon.
 */
#define IEEE80215_SUPERFRAME_ORDER_DEF	0xf
#define IEEE80215_SUPERFRAME_ORDER_MIN	0x0
#define IEEE80215_SUPERFRAME_ORDER_MAX	0xf

/**
 * The maximum time (in superframe periods) that a transaction is stored by a
 * coordinator and indicated in its beacon.
 */
#define IEEE80215_TRANSACTION_PERSISTENSE_TIME_DEF	0x1f4
#define IEEE80215_TRANSACTION_PERSISTENSE_TIME_MIN	0x0
#define IEEE80215_TRANSACTION_PERSISTENSE_TIME_MAX	0xffff

/******************************************************************************/
/* PAN Information Base (PIB), MAC security attribute identifiers */
/* See IEEE802.15.4-2003 draft, Table 71 */
/******************************************************************************/
/** A set of ACL entries, each containing address information, security suite
 * information, and security material to be used to protect frames between the
 * MAC sublayer and the specified device.
 */
#define IEEE80215_ACL_ENTRY_DESCRIPTOR_SET	0x70

/** The number of entries in the ACL descriptor set. */
#define IEEE80215_ACL_ENTRY_DESCRIPTOR_SET_SIZE	0x71

/** Indication of whether the device is able to transmit secure frames to or
 * accept secure frames from devices that are not explicitly listed in the ACL.
 * It is also used to communicate with multiple devices at once. A value of
 * TRUE indicates that such transmissions are permitted.
 */
#define IEEE80215_DEFAULT_SECURITY		0x72

/** The number of octets contained in ACLSecurityMaterial. */
#define IEEE80215_DEFAULT_SECURITY_MLEN	0x73

/** The specific security material to be used to protect frames between the MAC
 * sublayer and devices not in the ACL (see 802.15.4-2003.pdf, item 7.6.1.8).
 */
#define IEEE80215_DEFAULT_SECURITY_MATERIAL	0x74

/** The unique identifier of the security suite to be used to protect
 * communications between the MAC and devices not in the ACL as specified in
 * 802.15.4-2003.pdf, Table 75.
 */
#define IEEE80215_DEFAULT_SECURITY_SUITE	0x75

/** The identifier of the security use as specified in 802.15.4-2003.pdf, item
 * 7.5.8.
 * 0 x 00 = Unsecured mode.
 * 0 x 01 = ACL mode.
 * 0 x 02 = Secured mode.
 */
#define IEEE80215_SECURITY_MODE		0x76

/******************************************************************************/
/* PAN Information Base (PIB), MAC security attribute ranges */
/* See IEEE802.15.4-2003 draft, Table 72 */
/******************************************************************************/
/** A set of ACL entries, each containing address information, security suite
 * information, and security material to be used to protect frames between the
 * MAC sublayer and the specified device.
 */
#define IEEE80215_ACL_ENTRY_DESCRIPTOR_SET_DEF	NULL

/** The number of entries in the ACL descriptor set. */
#define IEEE80215_ACL_ENTRY_DESCRIPTOR_SET_SIZE_DEF	0x0
#define IEEE80215_ACL_ENTRY_DESCRIPTOR_SET_SIZE_MIN	0x0
#define IEEE80215_ACL_ENTRY_DESCRIPTOR_SET_SIZE_MAX	0xff

/** Indication of whether the device is able to transmit secure frames to or
 * accept secure frames from devices that are not explicitly listed in the ACL.
 * It is also used to communicate with multiple devices at once. A value of
 * TRUE indicates that such transmissions are permitted.
 */
#define IEEE80215_DEFAULT_SECURITY_DEF		false

/** The number of octets contained in ACLSecurityMaterial. */
#define IEEE80215_DEFAULT_SECURITY_MLEN_DEF		0x15
#define IEEE80215_DEFAULT_SECURITY_MLEN_MIN		0x0
#define IEEE80215_DEFAULT_SECURITY_MLEN_MAX		0x1a

/** The specific security material to be used to protect frames between the MAC
 * sublayer and devices not in the ACL (see 802.15.4-2003.pdf, item 7.6.1.8).
 */
/*#warning "FIXME: IEEE80215_DEFAULT_SECURITY_MATERIAL_MAX value"*/
#define IEEE80215_DEFAULT_SECURITY_MATERIAL_DEF	NULL
#define IEEE80215_DEFAULT_SECURITY_MATERIAL_MIN	NULL
#define IEEE80215_DEFAULT_SECURITY_MATERIAL_MAX	0x20

/** The unique identifier of the security suite to be used to protect
 * communications between the MAC and devices not in the ACL as specified in
 * 802.15.4-2003.pdf, Table 75.
 */
#define IEEE80215_DEFAULT_SECURITY_SUITE_DEF	0x0
#define IEEE80215_DEFAULT_SECURITY_SUITE_MIN	0x0
#define IEEE80215_DEFAULT_SECURITY_SUITE_MAX	0x7

/** The identifier of the security use as specified in 802.15.4-2003.pdf, item
 * 7.5.8.
 * 0 x 00 = Unsecured mode.
 * 0 x 01 = ACL mode.
 * 0 x 02 = Secured mode.
 */
#define IEEE80215_SECURITY_MODE_DEF			0x0
#define IEEE80215_SECURITY_MODE_MIN			0x0
#define IEEE80215_SECURITY_MODE_MAX			0x2


/****************/
/* Result codes */
/****************/
/**
 * \brief PHY return codes description
 *
 * The return values of PHY operations
 */
enum ieee80215_rcodes {
	/**< The CCA attempt has detected a busy channel */
	IEEE80215_BUSY = 0x0,
	/** The transceiver is asked to change its state while receiving */
	IEEE80215_BUSY_RX = 0x1,
	/** The transceiver is asked to change its state while transmitting */
	IEEE80215_BUSY_TX = 0x2,
	/** The transceiver is to be switched off */
	IEEE80215_FORCE_TRX_OFF = 0x3,
	/** The CCA attempt has detected an idle channel */
	IEEE80215_IDLE = 0x4,
	/**
	 * A SET/GET request was issued with a parameter in the primitive that
	 * is out of the valid range
	 */
	IEEE80215_PHY_INVALID_PARAMETER = 0x5,
	/**
	 * The transceiver is in or is to be configured into the receiver
	 * enabled state
	 */
	IEEE80215_RX_ON = 0x6,
	/**
	 * A SET/GET, an ED operation, or a transceiver state change was
	 * successful
	 */
	IEEE80215_PHY_SUCCESS = 0x7,
	/**
	 * The transceiver is in or is to be configured into the transceiver
	 * disabled state
	 */
	IEEE80215_TRX_OFF = 0x8,
	/**
	 * The transceiver is in or is to be configured into the transmitter
	 * enabled state
	 */
	IEEE80215_TX_ON = 0x9,
	/**
	 * A SET/GET request was issued with the identifier of an attribute that
	 * is not supported
	 */
	IEEE80215_UNSUPPORTED_ATTRIBUTE = 0xa,
};

/**
 * \brief MAC return codes description
 *
 * The return values of MAC operations
 */
enum ieee80215_mac_rcodes {
	/**
	 * The requested operation was completed successfully. For a transmission
	 * request, this value indicates a successful transmission.
	 */
	IEEE80215_SUCCESS = 0x0,
	/**< The disassociation reason code: coordinator kick off device from pan */
	IEEE80215_KICK_DEV = 0x1,
	/**< The disassociation reason code: device wishes to leave the pan */
	IEEE80215_LEAVE_DEV = 0x2,
	/**< The beacon was lost following a synchronization request. */
	IEEE80215_BEACON_LOSS = 0xe0,
	/**
	 * A transmission could not take place due to activity on the
	 * channel, i.e., the CSMA-CA mechanism has failed.
	 */
	IEEE80215_CHNL_ACCESS_FAIL = 0xe1,
	/**< The GTS request has been denied by the PAN coordinator. */
	IEEE80215_DENINED = 0xe2,
	/**< The attempt to disable the transceiver has failed. */
	IEEE80215_DISABLE_TRX_FAIL = 0xe3,
	/**
	 * The received frame induces a failed security check according to
	 * the security suite.
	 */
	IEEE80215_FAILED_SECURITY_CHECK = 0xe4,
	/**
	 * The frame resulting from secure processing has a length that is
	 * greater than aMACMaxFrameSize.
	 */
	IEEE80215_FRAME_TOO_LONG = 0xe5,
	/**
	 * The requested GTS transmission failed because the specified GTS
	 * either did not have a transmit GTS direction or was not defined.
	 */
	IEEE80215_INVALID_GTS = 0xe6,
	/**
	 * A request to purge an MSDU from the transaction queue was made using
	 * an MSDU handle that was not found in the transaction table.
	 */
	IEEE80215_INVALID_HANDLE = 0xe7,
	/**< A parameter in the primitive is out of the valid range.*/
	IEEE80215_INVALID_PARAMETER = 0xe8,
	/**< No acknowledgment was received after aMaxFrameRetries. */
	IEEE80215_NO_ACK = 0xe9,
	/**< A scan operation failed to find any network beacons.*/
	IEEE80215_NO_BEACON = 0xea,
	/**< No response data were available following a request. */
	IEEE80215_NO_DATA = 0xeb,
	/**< The operation failed because a short address was not allocated. */
	IEEE80215_NO_SHORT_ADDRESS = 0xec,
	/**
	 * A receiver enable request was unsuccessful because it could not be
	 * completed within the CAP.
	 */
	IEEE80215_OUT_OF_CAP = 0xed,
	/**
	 * A PAN identifier conflict has been detected and communicated to the
	 * PAN coordinator.
	 */
	IEEE80215_PANID_CONFLICT = 0xee,
	/**< A coordinator realignment command has been received. */
	IEEE80215_REALIGMENT = 0xef,
	/**< The transaction has expired and its information discarded. */
	IEEE80215_TRANSACTION_EXPIRED = 0xf0,
	/**< There is no capacity to store the transaction. */
	IEEE80215_TRANSACTION_OVERFLOW = 0xf1,
	/**
	 * The transceiver was in the transmitter enabled state when the
	 * receiver was requested to be enabled.
	 */
	IEEE80215_TX_ACTIVE = 0xf2,
	/**< The appropriate key is not available in the ACL. */
	IEEE80215_UNAVAILABLE_KEY = 0xf3,
	/**
	 * A SET/GET request was issued with the identifier of a PIB attribute
	 * that is not supported.
	 */
	IEEE80215_UNSUPPORTED_ATTR = 0xf4,
	/*
	 * A request to perform a scan operation failed because the MLME was
	 * in the process of performing a previously initiated scan operation.
	 */
	IEEE80215_SCAN_IN_PROGRESS = 0xfc,
};

/**
 * other errors
 */
#define IEEE80215_ERROR	0xff

#define ZB_ED_MAX	0xff
#define ZB_ED_MIN	0x0
/* #define ZB_ED_EDGE	0x7f */
/* I've got 0xBE on idle channel; let threshold be a little higher */
#define ZB_ED_EDGE	0xc8

/* In an ideal world this should be 1 */
#define IEEE80215_SLOW_SERIAL_FIXUP	75

#endif /* IEEE80215_CONST_H */

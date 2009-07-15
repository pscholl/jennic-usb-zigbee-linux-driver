/****************************************************************************
 *
 * MODULE:             ZED-MAC
 *
 * COMPONENT:          $RCSfile: mac_sap.h,v $
 *
 * VERSION:            $Name: R&D_Release_28thMay08_RP01 $
 *
 * REVISION:           $Revision: 1.2 $
 *
 * DATED:              $Date: 2008/01/09 10:43:06 $
 *
 * STATUS:             $State: Exp $
 *
 * AUTHOR:             rcc
 *
 * DESCRIPTION:
 * ZED 802.15.4 Media Access Controller
 * SAP interface for MLME and MCPS
 *
 * LAST MODIFIED BY:   $Author: dclar $
 *                     $Modtime$
 *
 *
 ****************************************************************************
 *
 *  (c) Copyright 2005, Jennic Limited
 *
 ****************************************************************************/

/* This is a MODIFIED version with explicit padding to allow use 
 * of -fpack-struct together with the code in ROM on jennic
 */
#ifndef _mac_sap_h_
#define _mac_sap_h_

#define packed __attribute__((packed))

/** Maximum PHY packet (PDU) size */
#define MAC_MAX_PHY_PKT_SIZE            127
/** PHY turnaround time */
#define MAC_PHY_TURNAROUND_TIME         12
/** PAN ID field size in octets */
#define MAC_PAN_ID_LEN                  2
/** Short address field size in octets */
#define MAC_SHORT_ADDR_LEN              2
/** Extended address field size in octets */
#define MAC_EXT_ADDR_LEN                8
/** Extended address field size in words (32 bit) */
#define MAC_EXT_ADDR_LEN_WORDS          2
/** Minimum Data Frame overhead */
#define MAC_MIN_DATA_FRM_OVERHEAD       9
/** Maximum Data Frame overhead */
#define MAC_MAX_DATA_FRM_OVERHEAD       25
/** Minimum Beacon Frame overhead */
#define MAC_MIN_BEACON_FRM_OVERHEAD     9
/** Maximum Beacon Frame overhead */
#define MAC_MAX_BEACON_FRM_OVERHEAD     15
/** Maximum Data Frame payload */
#define MAC_MAX_DATA_PAYLOAD_LEN      (MAC_MAX_PHY_PKT_SIZE - MAC_MIN_DATA_FRM_OVERHEAD)
/** Maximum Beacon Frame payload */
#define MAC_MAX_BEACON_PAYLOAD_LEN    (MAC_MAX_PHY_PKT_SIZE - MAC_MIN_BEACON_FRM_OVERHEAD)
/** @a aNumSuperframeSlots: Maximum number of superframe slots */
#define MAC_NUM_SUPERFRAME_SLOTS        16
/** @a aMaxBeaconOverhead: Maximum beacon overhead */
#define MAC_MAX_BEACON_OVERHEAD         75
/** @a aBaseSlotDuration */
#define MAC_BASE_SLOT_DURATION          60
/** @a aBaseSuperframeDuration */
#define MAC_BASE_SUPERFRAME_DURATION    (MAC_BASE_SLOT_DURATION * MAC_NUM_SUPERFRAME_SLOTS)
/** @a aResponseWaitTime */
#define MAC_RESPONSE_WAIT_TIME          (32 * MAC_BASE_SUPERFRAME_DURATION)
/** @a aMinLIFSPeriod: Minimum number of symbols in a LIFS period */
#define MAC_MIN_LIFS_PERIOD             40
/** @a aMinSIFSPeriod: Minimum number of symbols in a SIFS period */
#define MAC_MIN_SIFS_PERIOD             12
/** @a aMinCAPLength: Minimum CAP length */
#define MAC_MIN_CAP_LENGTH              440
/** @a aMaxFrameResponseTime: Maximum frame response time */
#define MAC_MAX_FRAME_RESPONSE_TIME     1220
/** @a aUnitBackoffPeriod: Number of symbols for CSMA/CA backoff */
#define MAC_UNIT_BACKOFF_PERIOD         20
/** @a aMaxFrameRetries: Maximum number of CSMA/CA retries */
#define MAC_MAX_FRAME_RETRIES           3
/** @a aMaxLostBeacons: Maximum number of lost beacons before sync loss */
#define MAC_MAX_LOST_BEACONS            4
/** @a aGTSDescPersistenceTime: How many beacons a GTS descriptor persists for */
#define MAC_GTS_DESC_PERSISTENCE_TIME   4
/** Maximum number of scan channel (2.4GHz) */
#define MAC_MAX_SCAN_CHANNELS           16
/** Maximum number of PAN descriptors in record */
#define MAC_MAX_SCAN_PAN_DESCRS         8
/** Maximum security material length */
#define MAC_MAX_SECURITY_MATERIAL_LEN   26
#define PHY_PIB_CHANNELS_SUPPORTED_DEF 0x07fff800
#define PHY_PIB_CURRENT_CHANNEL_DEF    11
#define PHY_PIB_CURRENT_CHANNEL_MIN    11
#define PHY_PIB_CURRENT_CHANNEL_MAX    26
#define PHY_PIB_TX_POWER_DEF           PHY_PIB_TX_POWER_3DB_TOLERANCE
#define PHY_PIB_TX_POWER_MIN           0
#define PHY_PIB_TX_POWER_MAX           0xbf
#define PHY_PIB_TX_POWER_MASK          0x3f
#define PHY_PIB_TX_POWER_1DB_TOLERANCE 0x00
#define PHY_PIB_TX_POWER_3DB_TOLERANCE 0x40
#define PHY_PIB_TX_POWER_6DB_TOLERANCE 0x80
#define PHY_PIB_CCA_MODE_DEF           1
#define PHY_PIB_CCA_MODE_MIN           1
#define PHY_PIB_CCA_MODE_MAX           3

typedef enum
{
    MAC_ENUM_SUCCESS = 0,             /**< Success (0x00) */
    MAC_ENUM_BEACON_LOSS = 0xE0,      /**< Beacon loss after synchronisation request (0xE0) */
    MAC_ENUM_CHANNEL_ACCESS_FAILURE,  /**< CSMA/CA channel access failure (0xE1) */
    MAC_ENUM_DENIED,                  /**< GTS request denied (0xE2) */
    MAC_ENUM_DISABLE_TRX_FAILURE,     /**< Could not disable transmit or receive (0xE3) */
    MAC_ENUM_FAILED_SECURITY_CHECK,   /**< Incoming frame failed security check (0xE4) */
    MAC_ENUM_FRAME_TOO_LONG,          /**< Frame too long after security processing to be sent (0xE5) */
    MAC_ENUM_INVALID_GTS,             /**< GTS transmission failed (0xE6) */
    MAC_ENUM_INVALID_HANDLE,          /**< Purge request failed to find entry in queue (0xE7) */
    MAC_ENUM_INVALID_PARAMETER,       /**< Out-of-range parameter in primitive (0xE8) */
    MAC_ENUM_NO_ACK,                  /**< No acknowledgement received when expected (0xE9) */
    MAC_ENUM_NO_BEACON,               /**< Scan failed to find any beacons (0xEA) */
    MAC_ENUM_NO_DATA,                 /**< No response data after a data request (0xEB) */
    MAC_ENUM_NO_SHORT_ADDRESS,        /**< No allocated short address for operation (0xEC) */
    MAC_ENUM_OUT_OF_CAP,              /**< Receiver enable request could not be executed as CAP finished (0xED) */
    MAC_ENUM_PAN_ID_CONFLICT,         /**< PAN ID conflict has been detected (0xEE) */
    MAC_ENUM_REALIGNMENT,             /**< Coordinator realignment has been received (0xEF) */
    MAC_ENUM_TRANSACTION_EXPIRED,     /**< Pending transaction has expired and data discarded (0xF0) */
    MAC_ENUM_TRANSACTION_OVERFLOW,    /**< No capacity to store transaction (0xF1) */
    MAC_ENUM_TX_ACTIVE,               /**< Receiver enable request could not be executed as in transmit state (0xF2) */
    MAC_ENUM_UNAVAILABLE_KEY,         /**< Appropriate key is not available in ACL (0xF3) */
    MAC_ENUM_UNSUPPORTED_ATTRIBUTE    /**< PIB Set/Get on unsupported attribute (0xF4) */
} MAC_Enum_e;

typedef enum
{
    MAC_MLME_SCAN_TYPE_ENERGY_DETECT = 0,   /**< Energy detect scan */
    MAC_MLME_SCAN_TYPE_ACTIVE = 1,          /**< Active scan */
    MAC_MLME_SCAN_TYPE_PASSIVE = 2,         /**< Passive scan */
    MAC_MLME_SCAN_TYPE_ORPHAN = 3,          /**< Orphan scan */
    NUM_MAC_MLME_SCAN_TYPE
} MAC_MlmeScanType_e;


typedef enum
{
    MAC_TX_OPTION_ACK      = 1,             /**< Acknowledge required */
    MAC_TX_OPTION_GTS      = 2,             /**< Transmit in GTS */
    MAC_TX_OPTION_INDIRECT = 4,             /**< Transmit indirectly */
    MAC_TX_OPTION_SECURITY = 8              /**< Use security */
} MAC_TransmitOption_e;

typedef enum
{
    MAC_PIB_ATTR_ACK_WAIT_DURATION = 0x40,      /**< macAckWaitDuration */
    MAC_PIB_ATTR_ASSOCIATION_PERMIT,            /**< macAssociationPermit */
    MAC_PIB_ATTR_AUTO_REQUEST,                  /**< macAutoRequest */
    MAC_PIB_ATTR_BATT_LIFE_EXT,                 /**< macBattLifeExt */
    MAC_PIB_ATTR_BATT_LIFE_EXT_PERIODS,         /**< macBattLifeExtPeriods */
    MAC_PIB_ATTR_BEACON_PAYLOAD,                /**< macBeaconPayload */
    MAC_PIB_ATTR_BEACON_PAYLOAD_LENGTH,         /**< macBeaconPayloadLength */
    MAC_PIB_ATTR_BEACON_ORDER,                  /**< macBeaconOrder */
    MAC_PIB_ATTR_BEACON_TX_TIME,                /**< macBeaconTxTime */
    MAC_PIB_ATTR_BSN,                           /**< macBSN */
    MAC_PIB_ATTR_COORD_EXTENDED_ADDRESS,        /**< macCoordExtendedAddress */
    MAC_PIB_ATTR_COORD_SHORT_ADDRESS,           /**< macCoordShortAddress */
    MAC_PIB_ATTR_DSN,                           /**< macDSN */
    MAC_PIB_ATTR_GTS_PERMIT,                    /**< macGTSPermit */
    MAC_PIB_ATTR_MAX_CSMA_BACKOFFS,             /**< macMaxCSMABackoffs */
    MAC_PIB_ATTR_MIN_BE,                        /**< macMinBE */
    MAC_PIB_ATTR_PAN_ID,                        /**< macPANId */
    MAC_PIB_ATTR_PROMISCUOUS_MODE,              /**< macPromiscuousMode */
    MAC_PIB_ATTR_RX_ON_WHEN_IDLE,               /**< macRxOnWhenIdle */
    MAC_PIB_ATTR_SHORT_ADDRESS,                 /**< macShortAddress */
    MAC_PIB_ATTR_SUPERFRAME_ORDER,              /**< macSuperframeOrder */
    MAC_PIB_ATTR_TRANSACTION_PERSISTENCE_TIME,  /**< macTransactionPersistenceTime */
    /* New for TG4b */
    //MAC_PIB_ATTR_MAX_TOTAL_FRAME_TX_TIME = 0x59,/**< macMaxTotalFrameTxTime */
    MAC_PIB_ATTR_MAX_FRAME_RETRIES  = 0x59,     /**< macMaxFrameRetries */
    MAC_PIB_ATTR_RESPONSE_WAIT_TIME = 0x5c,     /**< macResponseWaitTime */
    /* Security attributes */
    MAC_PIB_ATTR_ACL_ENTRY_DESCRIPTOR_SET = 0x70,       /**< macACLEntryDescriptorSet */
    MAC_PIB_ATTR_ACL_ENTRY_DESCRIPTOR_SET_SIZE,         /**< macACLEntryDescriptorSetSize */
    MAC_PIB_ATTR_DEFAULT_SECURITY,                      /**< macDefaultSecurity */
    MAC_PIB_ATTR_ACL_DEFAULT_SECURITY_MATERIAL_LENGTH,  /**< macACLDefaultSecurityMaterialLength */
    MAC_PIB_ATTR_DEFAULT_SECURITY_MATERIAL,             /**< macDefaultSecurityMaterial */
    MAC_PIB_ATTR_DEFAULT_SECURITY_SUITE,                /**< macDefaultSecuritySuite */
    MAC_PIB_ATTR_SECURITY_MODE,                         /**< macSecurityMode */
    NUM_MAC_ATTR_PIB                                    /**< (endstop) */
} MAC_PibAttr_e;

typedef struct
{
    __be32 u32L;  /**< Low word */
    __be32 u32H;  /**< High word */
} packed MAC_ExtAddr_s;

typedef struct
{
    u8         u8AddrMode;  /**< Address mode */
    u8         u8Pad;
    __be16     u16PanId;    /**< PAN ID */
    union {              /** Adress */
        __be16        u16Short;
        MAC_ExtAddr_s sExt;
    };
} packed MAC_Addr_s;

typedef struct
{
    MAC_ExtAddr_s sAclExtAddr;                                              /**< Extended address */
    __be16        u16AclShortAddr;                                          /**< Short address */
    __be16        u16AclPanId;                                              /**< PAN ID */
    u8            u8AclSecuritySuite;                                       /**< Security suite */
    u8            u8AclSecurityMaterialLen;                                 /**< Length of security material */
    u8            au8AclSecurityMaterial[MAC_MAX_SECURITY_MATERIAL_LEN];    /**< Security material */
} packed MAC_SapAclEntry_s;

typedef struct
{
    MAC_Addr_s sCoord;              /**< Coordinator address */
    u8         u8LogicalChan;       /**< Logical channel */
    u8         u8GtsPermit;         /**< True if beacon is from PAN coordinator which accepts GTS requests */
    u8         u8LinkQuality;       /**< Link quality of the received beacon */
    u8         u8SecurityUse;       /**< True if beacon received was secure */
    u8         u8AclEntry;          /**< Security mode used in ACL entry */
    u8         u8SecurityFailure;   /**< True if there was an error in security processing */
    __be16     u16SuperframeSpec;   /**< Superframe specification */
    __be32     u32TimeStamp;        /**< Timestamp of the received beacon */
} packed MAC_PanDescr_s;

typedef struct
{
    MAC_Addr_s sCoord;              /**< Coordinator to associate with */
    u8         u8LogicalChan;       /**< Logical channel to associate on */
    u8         u8Capability;        /**< Device's capability */
    u8         u8SecurityEnable;    /**< True if security is to be used on command frames */
    u8         pad;
} packed MAC_MlmeReqAssociate_s;

typedef struct
{
    MAC_Addr_s sAddr;               /**< Disassociating address of other end */
    u8         u8Reason;            /**< Disassociation reason */
    u8         u8SecurityEnable;    /**< True if security is to be used on command frames */
    u8         pad[2];
} packed MAC_MlmeReqDisassociate_s;

typedef struct
{
    u8    u8PibAttribute;       /**< Attribute @sa MAC_PibAttr_e */
    u8    u8PibAttributeIndex;  /**< Index value used to specify which ACL entry to set. <b>Not part of 802.15.4</b> */
    u8    pad[2];
} packed MAC_MlmeReqGet_s;

typedef struct tagMAC_MlmeReqGts_s
{
    u8    u8Characteristics;    /**< GTS characteristics */
    u8    u8SecurityEnable;     /**< True if security is to be used on command frames */
    u8    pad[2];
} packed MAC_MlmeReqGts_s;

typedef struct
{
    u8    u8SetDefaultPib;  /**< True if PIB is to be reset to default values */
    u8    pad[3];
} packed MAC_MlmeReqReset_s;

typedef struct
{
    __be32 u32RxOnTime;     /**< Number of symbol periods from the start of the superframe before the receiver is enabled (beacon networks only) */
    __be32 u32RxOnDuration; /**< Number of symbol periods the receiver should be enabled for */
    u8     u8DeferPermit;   /**< True if receiver enable can be deferred to the next superframe (beacon networks only) */
    u8     pad[3]; 
} packed MAC_MlmeReqRxEnable_s;

typedef struct MAC_MlmeReqScan_s
{
    __be32 u32ScanChannels; /**< Scan channels bitmap */
    u8     u8ScanType;      /**< Scan type @sa MAC_MlmeScanType_e */
    u8     u8ScanDuration;  /**< Scan duration */
    u8     pad[2];
} packed MAC_MlmeReqScan_s;

typedef struct
{
    u8        u8PibAttribute;       /**< Attribute @sa MAC_PibAttr_e */
    u8        u8PibAttributeIndex;  /**< Index value used to specify which ACL entry to set. <b>Not part of 802.15.4</b> */
    __be16    u16Pad;               /**< Padding to show alignment */
    union {
      u8            u8AckWaitDuration;                            /**< macAckWaitDuration */
      u8            u8AssociationPermit;                          /**< macAssociationPermit */
      u8            u8AutoRequest;                                /**< macAutoRequest */
      u8            u8BattLifeExt;                                /**< macBattLifeExt */
      u8            u8BattLifeExtPeriods;                         /**< macBattLifeExtPeriods */
      u8            au8BeaconPayload[MAC_MAX_BEACON_PAYLOAD_LEN]; /**< macBeaconPayload */
      u8            u8BeaconPayloadLength;                        /**< macBeaconPayloadLength */
      u8            u8BeaconOrder;                                /**< macBeaconOrder */
      __be32        u32BeaconTxTime;                              /**< macBeaconTxTime */
      u8            u8Bsn;                                        /**< macBSN */
      MAC_ExtAddr_s sCoordExtAddr;                                /**< macCoordExtendedAddress */
      __be16        u16CoordShortAddr;                            /**< macCoordShortAddress */
      u8            u8Dsn;                                        /**< macDSN */
      u8            u8GtsPermit;                                  /**< macGTSPermit */
      u8            u8MaxCsmaBackoffs;                            /**< macMaxCSMABackoffs */
      u8            u8MinBe;                                      /**< macMinBE */
      __be16        u16PanId;                                     /**< macPANId */
      u8            u8PromiscuousMode;                            /**< macPromiscuousMode */
      u8            u8RxOnWhenIdle;                               /**< macRxOnWhenIdle */
      __be16        u16ShortAddr;                                 /**< macShortAddress */
      u8            u8SuperframeOrder;                            /**< macSuperframeOrder */
      __be16        u16TransactionPersistenceTime;                /**< macTransactionPersistenceTime */
      /* Security attributes, as defined in table 72 (d18) */
      MAC_SapAclEntry_s sAclEntry;                                                    /**< ACL Entry table */
      u8                u8AclEntryDescriptorSetSize;                                  /**< macACLEntryDescriptorSetSize */
      u8                u8DefaultSecurity;                                            /**< macDefaultSecurity */
      u8                u8AclDefaultSecurityMaterialLength;                           /**< macACLDefaultSecurityMaterialLength */
      u8                au8DefaultSecurityMaterial[MAC_MAX_SECURITY_MATERIAL_LEN];    /**< macDefaultSecurityMaterial */
      u8                u8DefaultSecuritySuite;                                       /**< macDefaultSecuritySuite */
      u8                u8SecurityMode;                                               /**< macSecurityMode */
      /* New for TG4b */
      __be16 u16MaxTotalFrameTxTime;  /**< macMaxTotalFrameTxTime */
      u8     u8ResponseWaitTime;      /**< macResponseWaitTime */
      u8     u8MaxFrameRetries;       /**< macMaxFrameRetries */
      u8     pad[MAC_MAX_BEACON_PAYLOAD_LEN+2];
    };
} packed MAC_MlmeReqSet_s;

typedef struct
{
    __be16 u16PanId;            /**< The PAN ID indicated in the beacon */
    u8     u8Channel;           /**< Channel to send beacon out on */
    u8     u8BeaconOrder;       /**< Beacon order */
    u8     u8SuperframeOrder;   /**< Superframe order */
    u8     u8PanCoordinator;    /**< True if the Coordinator is a PAN Coordinator */
    u8     u8BatteryLifeExt;    /**< True if battery life extension timings are to be used */
    u8     u8Realignment;       /**< True if Coordinator realignment is sent when superframe parameters change */
    u8     u8SecurityEnable;    /**< True if security is to be used on command frames */
    u8     pad[3];
} packed MAC_MlmeReqStart_s;

typedef struct
{
    u8     u8Channel;       /**< Channel to listen for beacon on */
    u8     u8TrackBeacon;   /**< True if beacon is to be tracked */
    u8     pad[2]; 
} packed MAC_MlmeReqSync_s;

typedef struct
{
    MAC_Addr_s sCoord;              /**< Coordinator to poll for data */
    u8         u8SecurityEnable;    /**< True if security is to be used on command frames */
    u8         pad[3];
} packed MAC_MlmeReqPoll_s;

typedef struct
{
    MAC_ExtAddr_s sExtAddr; /**< Extended address to set */
} packed MAC_MlmeReqVsExtAddr_s;

typedef struct
{
    u8     u8Status;            /**< Status of association @sa MAC_Enum_e */
    u8     u8Pad;               /**< Padding to show alignment */
    __be16 u16AssocShortAddr;   /**< Associated Short Address */
} packed MAC_MlmeCfmAssociate_s;

typedef struct
{
    u8    u8Status; /**< Status of disassociation @sa MAC_Enum_e */
    u8    pad[3];
} packed MAC_MlmeCfmDisassociate_s;

typedef struct
{
    u8        u8Status;             /**< Status of PIB get @sa MAC_Enum_e */
    u8        u8PibAttribute;       /**< PIB attribute requested */
    __be16    u16Pad;               /**< Padding to show alignment */
    union {
      u8            u8AckWaitDuration;                            /**< macAckWaitDuration */
      u8            u8AssociationPermit;                          /**< macAssociationPermit */
      u8            u8AutoRequest;                                /**< macAutoRequest */
      u8            u8BattLifeExt;                                /**< macBattLifeExt */
      u8            u8BattLifeExtPeriods;                         /**< macBattLifeExtPeriods */
      u8            au8BeaconPayload[MAC_MAX_BEACON_PAYLOAD_LEN]; /**< macBeaconPayload */
      u8            u8BeaconPayloadLength;                        /**< macBeaconPayloadLength */
      u8            u8BeaconOrder;                                /**< macBeaconOrder */
      __be32        u32BeaconTxTime;                              /**< macBeaconTxTime */
      u8            u8Bsn;                                        /**< macBSN */
      MAC_ExtAddr_s sCoordExtAddr;                                /**< macCoordExtendedAddress */
      __be16        u16CoordShortAddr;                            /**< macCoordShortAddress */
      u8            u8Dsn;                                        /**< macDSN */
      u8            u8GtsPermit;                                  /**< macGTSPermit */
      u8            u8MaxCsmaBackoffs;                            /**< macMaxCSMABackoffs */
      u8            u8MinBe;                                      /**< macMinBE */
      __be16        u16PanId;                                     /**< macPANId */
      u8            u8PromiscuousMode;                            /**< macPromiscuousMode */
      u8            u8RxOnWhenIdle;                               /**< macRxOnWhenIdle */
      __be16        u16ShortAddr;                                 /**< macShortAddress */
      u8            u8SuperframeOrder;                            /**< macSuperframeOrder */
      __be16        u16TransactionPersistenceTime;                /**< macTransactionPersistenceTime */
      /* Security attributes, as defined in table 72 (d18) */
      MAC_SapAclEntry_s sAclEntry;                                                    /**< ACL Entry table */
      u8                u8AclEntryDescriptorSetSize;                                  /**< macACLEntryDescriptorSetSize */
      u8                u8DefaultSecurity;                                            /**< macDefaultSecurity */
      u8                u8AclDefaultSecurityMaterialLength;                           /**< macACLDefaultSecurityMaterialLength */
      u8                au8DefaultSecurityMaterial[MAC_MAX_SECURITY_MATERIAL_LEN];    /**< macDefaultSecurityMaterial */
      u8                u8DefaultSecuritySuite;                                       /**< macDefaultSecuritySuite */
      u8                u8SecurityMode;                                               /**< macSecurityMode */
      /* New for TG4b */
      __be16 u16MaxTotalFrameTxTime;  /**< macMaxTotalFrameTxTime */
      u8     u8ResponseWaitTime;      /**< macResponseWaitTime */
      u8     u8MaxFrameRetries;       /**< macMaxFrameRetries */
      u8     pad[MAC_MAX_BEACON_PAYLOAD_LEN+2];
    };
} packed MAC_MlmeCfmGet_s;

typedef struct
{
    u8    u8Status;             /**< Status of GTS request @sa MAC_Enum_e */
    u8    u8Characteristics;    /**< GTS characteristics */
    u8    pad[2]; 
} packed MAC_MlmeCfmGts_s;

typedef struct
{
    u8    u8Status; /**< Status of receiver enable request @sa MAC_Enum_e */
    u8    pad[3]; 
} packed MAC_MlmeCfmReset_s;

typedef struct
{
    u8    u8Status; /**< Status of receiver enable request @sa MAC_Enum_e */
    u8    pad[3]; 
} packed MAC_MlmeCfmRxEnable_s;


typedef struct
{
    u8             u8Status;                /**< Status of scan request @sa MAC_Enum_e */
    u8             u8ScanType;              /**< Scan type */
    u8             u8ResultListSize;        /**< Size of scan results list */
    u8             u8Pad;                   /**< Padding to show alignment */
    __be32         u32UnscannedChannels;    /**< Bitmap of unscanned channels */
    union {
        u8             au8EnergyDetect[MAC_MAX_SCAN_CHANNELS];
        MAC_PanDescr_s asPanDescr[MAC_MAX_SCAN_PAN_DESCRS];
    };
} packed MAC_MlmeCfmScan_s;

typedef struct
{
    u8    u8Status;         /**< Status of PIB set request @sa MAC_Enum_e */
    u8    u8PibAttribute;   /**< PIB attribute set */
    u8    pad[2];
} packed MAC_MlmeCfmSet_s;

typedef struct
{
    u8    u8Status; /**< Status of superframe start request @sa MAC_Enum_e */
    u8    pad[3];
} packed MAC_MlmeCfmStart_s;

typedef struct
{
    u8    u8Status; /**< Status of data poll request @sa MAC_Enum_e */
    u8    pad[3];
} packed MAC_MlmeCfmPoll_s;

typedef struct
{
    MAC_ExtAddr_s sDeviceAddr;      /**< Extended address of device wishing to associate */
    u8            u8Capability;     /**< Device capabilities */
    u8            u8SecurityUse;    /**< True if security was used on command frames */
    u8            u8AclEntry;       /**< Security suite used */
    u8            pad;
} packed MAC_MlmeIndAssociate_s;

typedef struct
{
    MAC_ExtAddr_s sDeviceAddr;      /**< Extended address of device which has sent disassociation notification */
    u8            u8Reason;         /**< Reason for disassociating */
    u8            u8SecurityUse;    /**< True if security was used on command frames */
    u8            u8AclEntry;       /**< Security suite used */
    u8            pad;
} packed MAC_MlmeIndDisassociate_s;

typedef struct
{
    u8    u8Reason; /**< Synchronisation loss reason @sa MAC_Enum_e */
    u8    pad[3];
} packed MAC_MlmeIndSyncLoss_s;

typedef struct
{
    __be16 u16ShortAddr;        /**< Short address of device to which GTS has been allocated or deallocated */
    u8     u8Characteristics;   /**< Characteristics of the GTS */
    u8     u8Security;          /**< True if security was used on command frames */
    u8     u8AclEntry;          /**< Security suite used */
    u8     pad[3];
} packed MAC_MlmeIndGts_s;

typedef struct
{
    MAC_PanDescr_s   sPANdescriptor;                    /**< PAN descriptor */
    u8               u8BSN;                             /**< Beacon sequence number */
    u8               u8PendAddrSpec;                    /**< Pending address specification */
    u8               u8SDUlength;                       /**< Length of following payload */
    u8               pad;
    union {
      __be16 u16Short;        /**< Short address */
      MAC_ExtAddr_s sExt;  /**< Extended address */
    } uAddrList[7];
    u8               u8SDU[MAC_MAX_BEACON_PAYLOAD_LEN]; /**< Beacon payload */
    u8               pad2[2];
} packed MAC_MlmeIndBeacon_s;

typedef struct
{
    MAC_Addr_s sSrcAddr;    /**< Source address of frame */
    MAC_Addr_s sDstAddr;    /**< Destination address of frame */
    u8         u8Status;    /**< Status of communication @sa MAC_Enum_e */
    u8         pad[3];
} packed MAC_MlmeIndCommStatus_s;

typedef struct
{
    MAC_ExtAddr_s sDeviceAddr;      /**< Extended address of orphaned device */
    u8            u8SecurityUse;    /**< True if security was used on command frames */
    u8            u8AclEntry;       /**< Security suite used */
    u8            pad[2];
} packed MAC_MlmeIndOrphan_s;

typedef struct
{
    MAC_ExtAddr_s sDeviceAddr;          /**< Device's extended address */
    __be16        u16AssocShortAddr;    /**< Short address allocated to Device */
    u8            u8Status;             /**< Status of association */
    u8            u8SecurityEnable;     /**< True if security is to be used on command frames */
} packed MAC_MlmeRspAssociate_s;

typedef struct
{
    MAC_ExtAddr_s sOrphanAddr;          /**< Orphaned Device's extended address */
    __be16        u16OrphanShortAddr;   /**< Short address Orphaned Device should use */
    u8            u8Associated;         /**< True if Device was previously associated */
    u8            u8SecurityEnable;     /**< True if security is to be used on command frames */
} packed MAC_MlmeRspOrphan_s;

typedef enum
{
    MAC_MLME_REQ_ASSOCIATE = 0,     /**< Use with tagMAC_MlmeReqAssociate_s */
    MAC_MLME_REQ_DISASSOCIATE,      /**< Use with MAC_MlmeReqDisassociate_s */
    MAC_MLME_REQ_GET,       /**< Use with MAC_MlmeReqGet_s */
    MAC_MLME_REQ_GTS,               /**< Use with tagMAC_MlmeReqGts_s */
    MAC_MLME_REQ_RESET,             /**< Use with tagMAC_MlmeReqReset_s */
    MAC_MLME_REQ_RX_ENABLE,         /**< Use with tagMAC_MlmeReqRxEnable_s */
    MAC_MLME_REQ_SCAN,              /**< Use with tagMAC_MlmeReqScan_s */
    MAC_MLME_REQ_SET,       /**< Use with tagMAC_MlmeReqSet_s */
    MAC_MLME_REQ_START,             /**< Use with tagMAC_MlmeReqStart_s */
    MAC_MLME_REQ_SYNC,              /**< Use with tagMAC_MlmeReqSync_s */
    MAC_MLME_REQ_POLL,              /**< Use with tagMAC_MlmeReqPoll_s */
    MAC_MLME_RSP_ASSOCIATE,         /**< Use with tagMAC_MlmeRspAssociate_s */
    MAC_MLME_RSP_ORPHAN,            /**< Use with tagMAC_MlmeRspOrphan_s */
    MAC_MLME_REQ_VS_EXTADDR_removed,/**< Use with tagMAC_MlmeReqVsExtAddr_s */
    NUM_MAC_MLME_REQ                /**< (endstop) */
} MAC_MlmeReqRspType_e;

typedef struct
{
    u8                    u8Type;           /**< Request type (@sa MAC_MlmeReqRspType_e) */
    u8                    u8ParamLength;    /**< Parameter length in following union */
    __be16                u16Pad;           /**< Padding to force alignment */
    union {
      /* MLME Requests */
      MAC_MlmeReqAssociate_s    sReqAssociate;        /**< Association request */
      MAC_MlmeReqDisassociate_s sReqDisassociate;     /**< Disassociation request */
      MAC_MlmeReqGet_s          sReqGet;              /**< PIB get request */
      MAC_MlmeReqGts_s          sReqGts;              /**< GTS request */
      MAC_MlmeReqReset_s        sReqReset;            /**< MAC reset request */
      MAC_MlmeReqRxEnable_s     sReqRxEnable;         /**< Receiver enable request */
      MAC_MlmeReqScan_s         sReqScan;             /**< Scan request */
      MAC_MlmeReqSet_s          sReqSet;              /**< PIB set request */
      MAC_MlmeReqStart_s        sReqStart;            /**< Superframe start request */
      MAC_MlmeReqSync_s         sReqSync;             /**< Superframe sync request */
      MAC_MlmeReqPoll_s         sReqPoll;             /**< Data poll request */
      MAC_MlmeReqVsExtAddr_s    sReqVsExtAddr;        /**< VS set external address */
      MAC_MlmeRspAssociate_s    sRspAssociate;        /**< Association response */
      MAC_MlmeRspOrphan_s       sRspOrphan;           /**< Orphan response */
    };
} packed MAC_MlmeReqRsp_s;

typedef enum
{
    MAC_MLME_CFM_OK,                /**< Synchronous confirm without error */
    MAC_MLME_CFM_ERROR,             /**< Synchronous confirm with error; see u8Status field */
    MAC_MLME_CFM_DEFERRED,          /**< Asynchronous deferred confirm will occur */
    MAC_MLME_CFM_NOT_APPLICABLE,    /**< Dummy synchronous confirm for MLME responses */
    NUM_MAC_MLME_CFM                /**< (endstop) */
} MAC_MlmeSyncCfmStatus_e;

typedef struct
{
    u8                     u8Status;        /**< Confirm status (@sa MAC_MlmeSyncCfmStatus_e ) */
    u8                     u8ParamLength;   /**< Parameter length in following union */
    __be16                 u16Pad;          /**< Padding to force alignment */
    union {
      MAC_MlmeCfmAssociate_s    sCfmAssociate;        /**< Association confirm */
      MAC_MlmeCfmDisassociate_s sCfmDisassociate;     /**< Disassociation confirm */
      MAC_MlmeCfmGet_s          sCfmGet;              /**< PIB get confirm */
      MAC_MlmeCfmGts_s          sCfmGts;              /**< GTS confirm */
      MAC_MlmeCfmScan_s         sCfmScan;             /**< Scan confirm */
      MAC_MlmeCfmSet_s          sCfmSet;              /**< PIB set confirm */
      MAC_MlmeCfmStart_s        sCfmStart;            /**< Superframe start confirm */
      MAC_MlmeCfmPoll_s         sCfmPoll;             /**< Data poll confirm */
      MAC_MlmeCfmReset_s        sCfmReset;            /**< Reset confirm */
      MAC_MlmeCfmRxEnable_s     sCfmRxEnable;         /**< Receiver enable confirm */
    };
} packed MAC_MlmeSyncCfm_s;

typedef enum
{
    MAC_MLME_DCFM_SCAN,                 /**< Use with tagMAC_MlmeCfmScan_s */
    MAC_MLME_DCFM_GTS,                  /**< Use with tagMAC_MlmeCfmGts_s */
    MAC_MLME_DCFM_ASSOCIATE,            /**< Use with tagMAC_MlmeCfmAssociate_s */
    MAC_MLME_DCFM_DISASSOCIATE,         /**< Use with tagMAC_MlmeCfmDisassociate_s */
    MAC_MLME_DCFM_POLL,                 /**< Use with tagMAC_MlmeCfmPoll_s */
    MAC_MLME_DCFM_RX_ENABLE,            /**< Use with tagMAC_MlmeCfmRxEnable_s */
    MAC_MLME_IND_ASSOCIATE,             /**< Use with tag MAC_MlmeIndAssociate_s */
    MAC_MLME_IND_DISASSOCIATE,          /**< Use with tagMAC_MlmeIndDisassociate_s */
    MAC_MLME_IND_SYNC_LOSS,             /**< Use with tagMAC_MlmeIndSyncLoss_s */
    MAC_MLME_IND_GTS,                   /**< Use with tagMAC_MlmeIndGts_s */
    MAC_MLME_IND_BEACON_NOTIFY,         /**< Use with tagMAC_MlmeIndBeacon_s */
    MAC_MLME_IND_COMM_STATUS,           /**< Use with tagMAC_MlmeIndCommStatus_s */
    MAC_MLME_IND_ORPHAN,                /**< Use with tagMAC_MlmeIndOrphan_s */
    NUM_MAC_MLME_IND
} MAC_MlmeDcfmIndType_e;

typedef struct
{
    u8                     u8Type;          /**< Deferred Confirm/Indication type @sa MAC_MlmeDcfmIndType_e */
    u8                     u8ParamLength;   /**< Parameter length in following union */
    __be16                 u16Pad;          /**< Padding to force alignment */
    union {
      MAC_MlmeCfmScan_s         sDcfmScan;
      MAC_MlmeCfmGts_s          sDcfmGts;
      MAC_MlmeCfmAssociate_s    sDcfmAssociate;
      MAC_MlmeCfmDisassociate_s sDcfmDisassociate;
      MAC_MlmeCfmPoll_s         sDcfmPoll;
      MAC_MlmeCfmRxEnable_s     sDcfmRxEnable;
      MAC_MlmeIndAssociate_s    sIndAssociate;
      MAC_MlmeIndDisassociate_s sIndDisassociate;
      MAC_MlmeIndGts_s          sIndGts;
      MAC_MlmeIndBeacon_s       sIndBeacon;
      MAC_MlmeIndSyncLoss_s     sIndSyncLoss;
      MAC_MlmeIndCommStatus_s   sIndCommStatus;
      MAC_MlmeIndOrphan_s       sIndOrphan;
    };
} packed MAC_MlmeDcfmInd_s;

typedef struct
{
    MAC_Addr_s sSrcAddr;                            /**< Source address */
    MAC_Addr_s sDstAddr;                            /**< Destination address */
    u8         u8TxOptions;                         /**< Transmit options */
    u8         u8SduLength;                         /**< Length of payload (MSDU) */
    u8         au8Sdu[MAC_MAX_DATA_PAYLOAD_LEN];    /**< Payload (MSDU) */
} packed MAC_TxFrameData_s;

typedef struct
{
    u8                u8Handle; /**< Handle of frame in queue */
    u8                pad[3];
    MAC_TxFrameData_s sFrame;   /**< Frame to send */
} packed MAC_McpsReqData_s;

typedef struct
{
    u8             u8Handle;    /**< Handle of request to purge from queue */
    u8    pad[3]; 
} packed MAC_McpsReqPurge_s;

typedef struct
{
    u8    u8Handle; /**< Handle matching associated request */
    u8    u8Status; /**< Status of request @sa MAC_Enum_e */
    u8    pad[2]; 
} packed MAC_McpsCfmData_s;

typedef struct
{
    u8    u8Handle; /**< Handle matching associated request */
    u8    u8Status; /**< Status of request @sa MAC_Enum_e */
    u8    pad[2]; 
} packed MAC_McpsCfmPurge_s;

typedef struct
{
    MAC_Addr_s sSrcAddr;                                /**< Source address */
    MAC_Addr_s sDstAddr;                                /**< Destination address */
    u8         u8LinkQuality;                           /**< Link quality of received frame */
    u8         u8SecurityUse;                           /**< True if security was used */
    u8         u8AclEntry;                              /**< Security suite used */
    u8         u8SduLength;                         /**< Length of payload (MSDU) */
    u8         au8Sdu[MAC_MAX_DATA_PAYLOAD_LEN];    /**< Payload (MSDU) */
    u8         pad[2]; 
} packed MAC_RxFrameData_s;

typedef struct
{
    MAC_RxFrameData_s sFrame;   /**< Frame received */
} packed MAC_McpsIndData_s;

typedef enum
{
    MAC_MCPS_REQ_DATA = 0,  /**< Use with tagMAC_McpsReqData_s */
    MAC_MCPS_REQ_PURGE,     /**< Use with tagMAC_McpsReqPurge_s */
    NUM_MAC_MCPS_REQ        /**> (endstop) */
} MAC_McpsReqRspType_e;

typedef struct
{
    u8                    u8Type;          /**< Request type (@sa MAC_McpsReqRspType_e) */
    u8                    u8ParamLength;   /**< Parameter length in following union */
    __be16                u16Pad;          /**< Padding to force alignment */
    union {
      MAC_McpsReqData_s  sReqData;   /**< Data request */
      MAC_McpsReqPurge_s sReqPurge;  /**< Purge request */
    };
} packed MAC_McpsReqRsp_s;

typedef enum
{
    MAC_MCPS_CFM_OK,        /**< Synchronous confirm without error */
    MAC_MCPS_CFM_ERROR,     /**< Synchronous confirm with error; see u8Status field */
    MAC_MCPS_CFM_DEFERRED,  /**< Asynchronous deferred confirm will occur */
    NUM_MAC_MCPS_CFM        /**< (endstop) */
} MAC_McpsSyncCfmStatus_e;

typedef struct
{
    u8                     u8Status;        /**< Confirm status (@sa MAC_McpsSyncCfmStatus_e) */
    u8                     u8ParamLength;   /**< Parameter length in following union */
    __be16                 u16Pad;          /**< Padding to force alignment */
    union {
      MAC_McpsCfmData_s  sCfmData;
      MAC_McpsCfmPurge_s sCfmPurge;
    };
} packed MAC_McpsSyncCfm_s;

typedef enum
{
    MAC_MCPS_DCFM_DATA,
    MAC_MCPS_DCFM_PURGE,
    MAC_MCPS_IND_DATA,
    NUM_MAC_MCPS_IND
} MAC_McpsDcfmIndType_e;

typedef struct
{
    u8                     u8Type;          /**< Indication type (@sa MAC_McpsDcfmIndType_e) */
    u8                     u8ParamLength;   /**< Parameter length in following union */
    __be16                 u16Pad;          /**< Padding to force alignment */
    union {
      MAC_McpsCfmData_s  sDcfmData;   /**< Deferred transmit data confirm */
      MAC_McpsCfmPurge_s sDcfmPurge;  /**< Deferred purge confirm */
      MAC_McpsIndData_s  sIndData;    /**< Received data indication */
    };
} packed MAC_McpsDcfmInd_s;

typedef struct
{
    u8     u8Type;          /**< Request/Response type */
    u8     u8ParamLength;   /**< Parameter length */
    __be16 u16Pad;          /**< Padding to force alignment */
} packed MAC_ReqRspHdr_s;

typedef struct
{
    u8     u8Status;        /**< Confirm status */
    u8     u8ParamLength;   /**< Parameter length */
    __be16 u16Pad;          /**< Padding to force alignment */
} packed MAC_SyncCfmHdr_s;

typedef struct
{
    u8     u8Type;          /**< Deferred confirm/Indication type */
    u8     u8ParamLength;   /**< Parameter length */
    __be16 u16Pad;          /**< Padding to force alignment */
} packed MAC_DcfmIndHdr_s;

typedef enum
{
    PHY_PIB_ATTR_CURRENT_CHANNEL    = 0,  /**<  */
    PHY_PIB_ATTR_CHANNELS_SUPPORTED = 1,  /**<  */
    PHY_PIB_ATTR_TX_POWER           = 2,  /**<  */
    PHY_PIB_ATTR_CCA_MODE           = 3   /**<  */
} PHY_PibAttr_e;

typedef enum
{
    PHY_ENUM_INVALID_PARAMETER     = 0x05,
    PHY_ENUM_SUCCESS               = 0x07,
    PHY_ENUM_UNSUPPORTED_ATTRIBUTE = 0x0a
} PHY_Enum_e;

typedef enum
{
    MAC_SAP_MLME = 0,   /**< SAP Type is MLME */
    MAC_SAP_MCPS = 1,   /**< SAP Type is MCPS */
    NUM_MAC_SAP
} MAC_Sap_e;

typedef struct jenusb_req {
    u8 type; /* use MAC_SAP_e */
    u8 pad[3];
    union {
      MAC_McpsReqRsp_s mcps;
      MAC_MlmeReqRsp_s mlme;
    };
} packed jenusb_req;

typedef struct jenusb_ind {
    u8 type;
    u8 pad[3];
    union {
      MAC_McpsDcfmInd_s mcps;
      MAC_MlmeDcfmInd_s mlme;
    };
} packed jenusb_ind;

typedef struct jenusb_cfm {
    u8 type;
    u8 pad[3];
    union {
      MAC_McpsSyncCfm_s mcps;
      MAC_MlmeSyncCfm_s mlme;
    };
} packed jenusb_cfm;

#endif /* _mac_sap_h_ */

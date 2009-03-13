obj-$(CONFIG_IEEE802154) +=	ieee80215.o af_80215.o
ieee80215-objs		:= main.o mdev.o dev.o netlink.o mac_cmd.o scan.o \
			crc.o beacon.o beacon_hash.o
af_80215-objs		:= af_ieee80215.o raw.o dgram.o mac_ioctl.o

#
#obj-y	+= 	ieee80215_phy.o ieee80215_mac_lib.o ieee80215_mac.o \
#	ieee80215_mac_scan.o ieee80215_mac_ed.o ieee80215_mac_passive.o \
#	ieee80215_mac_orphan.o ieee80215_mac_active.o ieee80215_mac_beacon.o \
#	ieee80215_mac_set.o ieee80215_mac_cmd.o ieee80215_secure.o \
#	ieee80215_assoc.o ieee80215_disassoc.o ieee80215_gts.o \
#	ieee80215_sync.o ieee80215_poll.o ieee80215_mac_start.o \
#	ieee80215_purge.o ieee80215_mac_data.o ieee80215_core.o \
#	ieee80215_rxenable.o ieee80215_lib.o
EXTRA_CFLAGS += -Wall -DEXPORT_SYMTAB -DCONFIG_FFD -DCONFIG_ZIGBEE_DEBUG -DIEEE80215_DEBUG -DDEBUG

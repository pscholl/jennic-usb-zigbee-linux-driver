obj-$(CONFIG_IEEE802154) +=	ieee80215.o af_80215.o
ieee80215-objs		:= main.o mdev.o dev.o netlink.o mac_cmd.o scan.o \
			crc.o beacon.o beacon_hash.o
af_80215-objs		:= af_ieee80215.o raw.o dgram.o mac_ioctl.o

EXTRA_CFLAGS += -Wall -DDEBUG

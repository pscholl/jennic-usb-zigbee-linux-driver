obj-$(CONFIG_IEEE802154) +=	ieee802154.o af_802154.o
ieee802154-objs		:= main.o mdev.o dev.o netlink.o mac_cmd.o scan.o \
			crc.o beacon.o beacon_hash.o
af_802154-objs		:= af_ieee802154.o raw.o dgram.o

EXTRA_CFLAGS += -Wall -DDEBUG

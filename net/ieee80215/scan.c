/*
 * scan.c
 *
 * Description: MAC scan helper functions.
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
#include <linux/net.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/if_arp.h>
#include <linux/termios.h>	/* For TIOCOUTQ/INQ */
#include <linux/crc-itu-t.h>
#include <net/datalink.h>
#include <net/psnap.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/route.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/mac_struct.h>
#include <net/ieee80215/mac_def.h>

static int scan_ed(struct net_device *dev, u32 channels, u8 duration)
{
	int i, ret;
	struct ieee80215_priv *priv = netdev_priv(dev);
	BUG_ON(dev->master);
	pr_debug("ed scan channels %d duration %d\n", channels, duration);
	for(i = 1; i < 28; i++) {
		u8 e;
		if(priv->hw.channel_mask & (1 << (i - 1)))
			return -EINVAL; /* FIXME */
		ret = priv->ops->set_channel(&priv->hw,  i);
		if(ret == PHY_ERROR)
			goto exit_error;
		ret = priv->ops->ed(&priv->hw, &e);
		if(ret == PHY_ERROR)
			goto exit_error;
		pr_debug("ed scan channel %d value %d\n", i, e);
	}
	return 0;
exit_error:
	pr_debug("PHY fault during ED scan\n")'
	return -EINVAL;
}
static int scan_active(struct net_device *dev, u32 channels, u8 duration)
{
	pr_debug("active scan channels %d duration %d\n", channels, duration);
	return 0;
}
static int scan_passive(struct net_device *dev, u32 channels, u8 duration)
{
	pr_debug("passive scan channels %d duration %d\n", channels, duration);
	return 0;
}
static int scan_orphan(struct net_device *dev, u32 channels, u8 duration)
{
	pr_debug("orphan scan channels %d duration %d\n", channels, duration);
	return 0;
}

/**
 * @brief MLME-SAP.Scan request
 *
 * Alloc ed_detect list for ED scan.
 *
 * @param mac current mac pointer
 * @param type type of the scan to be performed
 * @param channels 32-bit mask of requested to scan channels
 * @param duration scan duration, see ieee802.15.4-2003.pdf, page 145.
 * @return 0 if request is ok, errno otherwise.
 */
int ieee80215_mlme_scan_req(struct net_device *dev, u8 type, u32 channels, u8 duration)
{
	/* TODO: locking, workqueue */
	if(duration > 14)
		return -EINVAL;

	switch(type) {
	case IEEE80215_MAC_SCAN_ED:
		return scan_ed(dev, channels, duration);
	case IEEE80215_MAC_SCAN_ACTIVE:
		return scan_active(dev, channels, duration);
	case IEEE80215_MAC_SCAN_PASSIVE:
		return scan_passive(dev, channels, duration);
	case IEEE80215_MAC_SCAN_ORPHAN:
		return scan_orphan(dev, channels, duration);
	default:
		pr_debug("%s(): incalid type %d\n", __FUNCTION__, type);
		break;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(ieee80215_mlme_scan_req)

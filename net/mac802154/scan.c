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
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/netdevice.h>

#include <net/af_ieee802154.h>
#include <net/mac802154.h>
#include <net/nl802154.h>
#include <net/ieee802154.h>
#include <net/ieee802154_netdev.h>

#include "mac802154.h"
#include "beacon.h"

/*
 * ED scan is periodic issuing of ed device function
 * on evry permitted channel, so it is virtually PHY-only scan */

struct scan_work {
	struct work_struct work;

	int (*scan_ch)(struct scan_work *work, int channel, u8 duration);
	struct net_device *dev;

	u8 edl[27];

	u8 type;
	u32 channels;
	u8 page;
	u8 duration;
};

static int scan_ed(struct scan_work *work, int channel, u8 duration)
{
	int ret;
	struct ieee802154_priv *hw = ieee802154_slave_get_priv(work->dev);
	pr_debug("ed scan channel %d duration %d\n", channel, duration);
	ret = hw->ops->ed(&hw->hw, &work->edl[channel]);
	pr_debug("ed scan channel %d value %d\n", channel, work->edl[channel]);
	return ret;
}

static int scan_passive(struct scan_work *work, int channel, u8 duration)
{
	unsigned long j;
	pr_debug("passive scan channel %d duration %d\n", channel, duration);

	/* Hope 2 msecs will be enough for scan */
	j = msecs_to_jiffies(2);
	while (j > 0)
		j = schedule_timeout(j);

	return 0;
}

/* Active scan is periodic submission of beacon request
 * and waiting for beacons which is useful for collecting LWPAN information */
static int scan_active(struct scan_work *work, int channel, u8 duration)
{
	int ret;
	pr_debug("active scan channel %d duration %d\n", channel, duration);
	ret = ieee802154_send_beacon_req(work->dev);
	if (ret)
		return ret;
	return scan_passive(work, channel, duration);
}

static int scan_orphan(struct scan_work *work, int channel, u8 duration)
{
	pr_debug("orphan scan channel %d duration %d\n", channel, duration);
	return 0;
}

static void scanner(struct work_struct *work)
{
	struct scan_work *sw = container_of(work, struct scan_work, work);
	struct ieee802154_priv *hw = ieee802154_slave_get_priv(sw->dev);
	int i;
	int ret;

	for (i = 0; i < 27; i++) {
		if (!(sw->channels & (1 << i)))
			continue;

		ret = hw->ops->set_channel(&hw->hw,  i);
		if (ret)
			goto exit_error;

		ret = sw->scan_ch(sw, i, sw->duration);
		if (ret)
			goto exit_error;

		sw->channels &= ~(1 << i);
	}

	ieee802154_nl_scan_confirm(sw->dev, IEEE802154_SUCCESS, sw->type,
			sw->channels, sw->page, sw->edl/*, NULL */);

	kfree(sw);

	return;

exit_error:
	ieee802154_nl_scan_confirm(sw->dev, IEEE802154_INVALID_PARAMETER,
			sw->type, sw->channels, sw->page, NULL/*, NULL */);
	kfree(sw);
	return;
}

/*
 * Alloc ed_detect list for ED scan.
 *
 * @param mac current mac pointer
 * @param type type of the scan to be performed
 * @param channels 32-bit mask of requested to scan channels
 * @param duration scan duration, see ieee802.15.4-2003.pdf, page 145.
 * @return 0 if request is ok, errno otherwise.
 */
int ieee802154_mlme_scan_req(struct net_device *dev,
		u8 type, u32 channels, u8 page, u8 duration)
{
	struct ieee802154_priv *hw = ieee802154_slave_get_priv(dev);
	struct scan_work *work;

	pr_debug("%s()\n", __func__);

	if (duration > 14)
		goto inval;
	if (channels & hw->hw.channel_mask)
		goto inval;

	work = kzalloc(sizeof(struct scan_work), GFP_KERNEL);
	if (!work)
		goto inval;

	work->dev = dev;
	work->channels = channels;
	work->page = page;
	work->duration = duration;
	work->type = type;

	switch (type) {
	case IEEE802154_MAC_SCAN_ED:
		work->scan_ch = scan_ed;
		break;
	case IEEE802154_MAC_SCAN_ACTIVE:
		work->scan_ch = scan_active;
		break;
	case IEEE802154_MAC_SCAN_PASSIVE:
		work->scan_ch = scan_passive;
		break;
	case IEEE802154_MAC_SCAN_ORPHAN:
		work->scan_ch = scan_orphan;
		break;
	default:
		pr_debug("%s(): invalid type %d\n", __func__, type);
		goto inval;
	}

	INIT_WORK(&work->work, scanner);
	queue_work(hw->dev_workqueue, &work->work);

	return 0;

inval:
	ieee802154_nl_scan_confirm(dev, IEEE802154_INVALID_PARAMETER, type,
			channels, page, NULL/*, NULL */);
	return -EINVAL;
}


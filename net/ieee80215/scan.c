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

#include <net/ieee80215/beacon.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/mac_def.h>
#include <net/ieee80215/nl.h>
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
	u8 duration;
};

static int scan_ed(struct scan_work *work, int channel, u8 duration)
{
	int ret;
	struct ieee80215_priv *hw = ieee80215_slave_get_hw(work->dev);
	pr_debug("ed scan channel %d duration %d\n", channel, duration);
	ret = hw->ops->ed(&hw->hw, &work->edl[channel]);
	pr_debug("ed scan channel %d value %d\n", channel, work->edl[channel]);
	return ret;
}

struct scan_data {
	struct notifier_block nb;
	struct list_head scan_head;
};

static int beacon_notifier(struct notifier_block *p,
                                unsigned long event, void *data)
{
	struct ieee80215_pandsc * pd = data;
	struct scan_data * sd = container_of(p, struct scan_data, nb);
	switch(event) {
	case IEEE80215_NOTIFIER_BEACON:
		/* TODO: add item to list here */
		pr_debug("got a beacon frame addr_type %d pan_id %d\n",
				pd->addr.addr_type, pd->addr.pan_id);
		break;
	}
	return 0;
}


static int scan_passive(struct scan_work *work, int channel, u8 duration)
{
	unsigned long j;
	struct scan_data * data = kzalloc(sizeof(struct scan_data), GFP_KERNEL);
	pr_debug("passive scan channel %d duration %d\n", channel, duration);
	data->nb.notifier_call = beacon_notifier;
	ieee80215_slave_register_notifier(work->dev, &data->nb);
	/* Hope 2 msecs will be enough for scan */
	j = msecs_to_jiffies(2);
	while (j > 0) {
		j = schedule_timeout(j);
	}
	ieee80215_slave_unregister_notifier(work->dev, &data->nb);
	kfree(data);
	return PHY_SUCCESS;
}
/* Active scan is periodic submission of beacon request
 * and waiting for beacons which is useful for collecting LWPAN information */
static int scan_active(struct scan_work *work, int channel, u8 duration)
{
	int ret;
	pr_debug("active scan channel %d duration %d\n", channel, duration);
	ret = ieee80215_send_beacon_req(work->dev);
	if (ret < 0)
		return PHY_ERROR;
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
	struct ieee80215_priv *hw = ieee80215_slave_get_hw(sw->dev);
	int i;
	phy_status_t ret;

	for (i = 0; i < 27; i++) {
		if (!(sw->channels & (1 << i)))
			continue;

		ret = hw->ops->set_channel(&hw->hw,  i);
		if (ret != PHY_SUCCESS)
			goto exit_error;

		ret = sw->scan_ch(sw, i, sw->duration);
		if (ret != PHY_SUCCESS)
			goto exit_error;

		sw->channels &= ~(1 << i);
	}

	ieee80215_nl_scan_confirm(sw->dev, IEEE80215_SUCCESS, sw->type, sw->channels,
			sw->edl/*, NULL */);

	kfree(sw);

	return;

exit_error:
	ieee80215_nl_scan_confirm(sw->dev, IEEE80215_INVALID_PARAMETER, sw->type, sw->channels,
			NULL/*, NULL */);
	kfree(sw);
	return;
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
	struct ieee80215_priv *hw = ieee80215_slave_get_hw(dev);
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
	work->duration = duration;
	work->type = type;

	switch (type) {
	case IEEE80215_MAC_SCAN_ED:
		work->scan_ch = scan_ed;
		break;
	case IEEE80215_MAC_SCAN_ACTIVE:
		work->scan_ch = scan_active;
		break;
	case IEEE80215_MAC_SCAN_PASSIVE:
		work->scan_ch = scan_passive;
		break;
	case IEEE80215_MAC_SCAN_ORPHAN:
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
	ieee80215_nl_scan_confirm(dev, IEEE80215_INVALID_PARAMETER, type, channels,
			NULL/*, NULL */);
	return -EINVAL;
}
EXPORT_SYMBOL(ieee80215_mlme_scan_req);


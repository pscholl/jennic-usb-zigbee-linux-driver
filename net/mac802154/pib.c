/*
 * Copyright 2008 Siemens AG
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
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <net/ieee802154/mac802154.h>

#include "mac802154.h"
#include "pib.h"

int ieee802154_pib_set(struct ieee802154_dev *hw, struct ieee802154_pib *pib)
{
	int ret;
	struct ieee802154_priv *priv = ieee802154_to_priv(hw);
	BUG_ON(!hw);
	BUG_ON(!pib);
	switch (pib->type) {
	case IEEE802154_PIB_CURCHAN:
#warning this should go via usual workqueue!!!
		/* Our internal mask is inverted
		 * 0 = channel is available
		 * 1 = channel is unavailable
		 * this saves initialization */
		if (hw->channel_mask & (1 << (pib->val - 1)))
			return -EINVAL;
		ret = priv->ops->set_channel(hw, pib->val);
		if (ret == PHY_ERROR)
			return -EINVAL; /* FIXME */
		hw->current_channel =  pib->val;
		break;
	case IEEE802154_PIB_CHANSUPP:
		hw->channel_mask = ~(pib->val);
		break;
	case IEEE802154_PIB_TRPWR:
		/* TODO */
		break;
	case IEEE802154_PIB_CCAMODE:
		/* TODO */
		break;
	default:
		pr_debug("Unknown PIB type value\n");
		return -ENOTSUPP;
	}
	return 0;
}

int ieee802154_pib_get(struct ieee802154_dev *hw, struct ieee802154_pib *pib)
{
	BUG_ON(!hw);
	BUG_ON(!pib);
	switch (pib->type) {
	case IEEE802154_PIB_CURCHAN:
		pib->val = hw->current_channel;
		break;
	case IEEE802154_PIB_CHANSUPP:
		pib->val = ~(hw->channel_mask);
		break;
	case IEEE802154_PIB_TRPWR:
		pib->val = 0;
		break;
	case IEEE802154_PIB_CCAMODE:
		pib->val = 0;
		break;
	default:
		pr_debug("Unknown PIB type value\n");
		return -ENOTSUPP;
	}
	return 0;
}


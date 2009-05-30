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

#ifndef PIB802154_H
#define PIB802154_H

struct ieee802154_pib {
	int type;
	u32 val;
};

#define IEEE802154_PIB_CURCHAN	0 /* Current channel, u8 6.1.2 */
#define IEEE802154_PIB_CHANSUPP	1 /* Channel mask, u32 6.1.2 */
#define IEEE802154_PIB_TRPWR	2 /* Transmit power, u8 6.4.2  */
#define IEEE802154_PIB_CCAMODE	3 /* CCA mode, u8 6.7.9 */

int ieee802154_pib_set(struct ieee802154_dev *hw, struct ieee802154_pib *pib);
int ieee802154_pib_get(struct ieee802154_dev *hw, struct ieee802154_pib *pib);

#endif

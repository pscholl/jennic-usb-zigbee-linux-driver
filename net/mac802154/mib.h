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

#ifndef MIB802154_H
#define MIB802154_H

/* FIXME: should be dropped in favour of generic MIB API */
u8 ieee802154_dev_get_dsn(const struct net_device *dev);
u8 ieee802154_dev_get_bsn(const struct net_device *dev);
u16 ieee802154_dev_get_pan_id(const struct net_device *dev);
u16 ieee802154_dev_get_short_addr(const struct net_device *dev);
void ieee802154_dev_set_pan_id(struct net_device *dev, u16 val);
void ieee802154_dev_set_short_addr(struct net_device *dev, u16 val);
void ieee802154_dev_set_channel(struct net_device *dev, u8 chan);
void ieee802154_dev_set_page(struct net_device *dev, u8 page);
struct wpan_phy *ieee802154_get_phy(const struct net_device *dev);


#endif

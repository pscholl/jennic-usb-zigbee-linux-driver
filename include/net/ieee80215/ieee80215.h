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

#ifndef IEEE80215_H
#define IEEE80215_H
#include <net/ieee80215/phy.h>

#define IEEE80215_ADDR_LEN	8
#define IEEE80215_DEV_SINGLE	1
#define IEEE80215_DEV_MULTI	2

int ieee80215_register_device(struct ieee80215_dev_ops *hw);
int ieee80215_unregister_device(struct ieee80215_dev_ops *hw);

#endif

/*
 * ieee80215_info.h
 *
 * Description: IEEE 802.15.4 Modules information.
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
 */

#ifndef IEEE80215_INFO_H
#define IEEE80215_INFO_H

enum ieee80215_modules {
	CORE = 0,
	CSMA = 1,
	DATA = 2,
	SET_GET = 3,
	SCAN = 4,
	SCAN_ED = 5,
	SCAN_ACTIVE = 6,
	SCAN_PASSIVE = 7,
	SCAN_ORPHAN = 8,
	START = 9,
	ASSOC = 10,
	DISASSOC = 11,
	BEACON = 12,
	GTS = 13,
	POLL = 14,
	PURGE = 15,
	RXEN = 16,
	SYNC = 17,
	TX = 18,
	CMD = 19,
	TIMER = 20,
	PHY_CORE = 21,
	PHY_SET_GET = 22,
	PHY_CCA = 23,
	PHY_ED = 24,
	PHY_RECV = 25,
	PHY_TRX = 26,
	SECURE = 27,
	DATA_FILTER = 28,
	NMODS
};

#endif /* IEEE80215_INFO_H */

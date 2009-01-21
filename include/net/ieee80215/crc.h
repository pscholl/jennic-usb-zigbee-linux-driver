/*
 * based on crc-itu-t.c.
 * Basically it's CRC-ITU-T but with inverted bit numbering
 *
 * Copyright 2007, 2008 Siemens AG
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
 * 	Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 */

extern const u16 ieee80215_crc_table[256];

static inline u16 ieee80215_crc_byte(u16 crc, const u8 data)
{
	return (crc >> 8) ^ ieee80215_crc_table[(crc ^ data) & 0xff];
}

static inline u16 ieee80215_crc(u16 crc, const u8 *buffer, size_t len)
{
	while (len--)
		crc = ieee80215_crc_byte(crc, *buffer++);
	return crc;
}



/*
 * ieee80215_secure.c
 *
 * Description: Security module
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

#include <linux/list.h>
#include <net/ieee80215/mac_lib.h>

ieee80215_acl_pib_t*
ieee80215_find_acl(ieee80215_mac_t *mac, ieee80215_addr_t *addr)
{
	struct list_head *it;
	ieee80215_acl_pib_t *acl;
	ieee80215_dev_addr_t da;

	memset(&da, 0, sizeof(da));
	da._16bit = addr->_16bit;
	if (0xfffe == addr->_16bit) {
		da._64bit = addr->_64bit;
	}

	spin_lock(&mac->pib.acl_entries.lock);
	list_for_each(it, &mac->pib.acl_entries.pib.list) {
		acl = container_of(it, ieee80215_acl_pib_t, list);
		if (ieee80215_cmp_addr(&da, &acl->addr)) {
			break;
		}
		acl = NULL;
	}
	spin_unlock(&mac->pib.acl_entries.lock);
	return acl;
}

int ieee80215_add_acl(ieee80215_mac_t *mac, ieee80215_acl_pib_t *nacl)
{
	ieee80215_acl_pib_t *acl;
	ieee80215_addr_t addr;

	if (nacl->addr._16bit == 0xfffe) {
		addr._64bit = nacl->addr._64bit;
	} else
		addr._16bit = nacl->addr._16bit;

	acl = ieee80215_find_acl(mac, &addr);
	if (acl) {
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
		dbg_print(mac, SECURE, DBG_INFO,
			  "Acl for such address is alredy exists\n");
		return -1;
	}
	spin_lock(&mac->pib.acl_entries.lock);
	list_add(&mac->pib.acl_entries.pib.list, &nacl->list);
	mac->pib.acl_entries.count++;
	spin_unlock(&mac->pib.acl_entries.lock);
	return 0;
}

int ieee80215_del_acl(ieee80215_mac_t *mac, ieee80215_addr_t *addr)
{
	ieee80215_acl_pib_t *acl = NULL;

	acl = ieee80215_find_acl(mac, addr);
	if (!acl) {
		dbg_print(mac, SECURE, DBG_INFO,
			  "Unable to find appropriate acl entry\n");
		return 0;
	}
	spin_lock(&mac->pib.acl_entries.lock);
	list_del(&acl->list);
	mac->pib.acl_entries.count--;
	spin_unlock(&mac->pib.acl_entries.lock);
	if (acl->sec_mlen)
		kfree(acl->sec_material);
	kfree(acl);
	return 0;
}


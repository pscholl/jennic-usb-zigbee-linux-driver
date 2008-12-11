/*
 * ieee80215_core.c
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

#include <net/ieee80215/ieee80215.h>
#include <net/ieee80215/mac.h>
#include <net/ieee80215/netdev.h>

static int s_leveles[NMODS];

int *levels = NULL;

bool timestamps = false;

static char *debug_opts;
static int ts;

module_param(ts, int, 0);
MODULE_PARM_DESC(ts, "1 - print timestamps in debug info, 0 - do not print\n");

module_param(debug_opts, charp, 0);
MODULE_PARM_DESC(debug_opts, "A debugging options, debug_opts=0.20,1.30 mean 20 \n"
		"verbosity level for CORE module, 30 for set_get, etc.\n"
		"debug_opts=30 mean verbosity level 30 for all modules\n");

char *s_modules[] = {
	"CORE",
	"CSMA",
	"DATA",
	"SET_GET",
	"SCAN",
	"SCAN_ED",
	"SCAN_ACTIVE",
	"SCAN_PASSIVE",
	"SCAN_ORPHAN",
	"START",
	"ASSOC",
	"DISASSOC",
	"BEACON",
	"GTS",
	"POLL",
	"PURGE",
	"RXEN",
	"SYNC",
	"TX",
	"CMD",
	"TIMER",
	"PHY_CORE",
	"PHY_SET_GET",
	"PHY_CCA",
	"PHY_ED",
	"PHY_RECV",
	"PHY_TRX",
	"SECURE",
	"FILTER"
};

int ieee80215_register_device(ieee80215_dev_op_t *dev)
{
	ieee80215_phy_t *phy;
	int ret;

	if (!dev || !dev->name || !dev->set_channel || !dev->ed
		|| !dev->set_state || !dev->xmit || !dev->cca) {
		printk(KERN_ERR "device is not valid\n");
		return -EINVAL;
	}
#if 0
	if (0 == dev->_64bit || 0xffffffff == dev->_64bit) {
		printk(KERN_WARNING "64bit device address is not valid\n");
		return -EINVAL;
	}
#endif
	phy = ieee80215_phy_alloc(dev->name);
	if (!phy) {
		printk(KERN_WARNING "Cannot allocate phy\n" );
		return -ENOMEM;
	}

	phy->dev_op = dev;
	phy->dev_op->priv = phy;

	ret = ieee80215_phy_init ( phy );
	if (ret) {
		printk(KERN_WARNING "Cannot init phy\n" );
		ieee80215_phy_free ( phy );
		dev->priv = NULL;
		return ret;
	}

	ret = ieee80215_register_phy ( phy );
	if (ret) {
#warning FIXME debug
#define dbg_print(c, ...)
#define dbg_dump8(c, ...)
		dbg_print(phy, 0, DBG_ERR_CRIT,
			"Cannot register phy: %d\n", ret);
		ieee80215_phy_free ( phy );
		dev->priv = NULL;
	}
	ret = ieee80215_register_netdev_master(phy, dev);
	if(ret) {
		pr_debug("Cannot register phy\n");
		ieee80215_phy_free ( phy );
		dev->priv = NULL;
	}

	return ret;
}
EXPORT_SYMBOL(ieee80215_register_device);

int ieee80215_unregister_device(ieee80215_dev_op_t *dev)
{
	ieee80215_phy_t *phy;
	int ret;

	if (!dev || !dev->priv)
		return -EINVAL;

	phy = (ieee80215_phy_t*)dev->priv;

	if(phy->dev) {
		unregister_netdev(phy->dev);
		free_netdev(phy->dev);
		phy->dev = NULL;
	}

	ret = ieee80215_unregister_phy(phy);
	if (ret) {
		dbg_print(phy, CORE, DBG_ERR, "Could not unregister phy\n" );
		return ret;
	}

	ret = ieee80215_phy_close(phy);
	if (ret) {
		dbg_print(phy, CORE, DBG_ERR, "Could not close phy\n" );
		return ret;
	}

	ieee80215_phy_free(phy);
	dev->priv = NULL;
	return 0;
}
EXPORT_SYMBOL(ieee80215_unregister_device);

static int __init ieee80215_core_init ( void )
{
	printk(KERN_INFO "%s()\n", __FUNCTION__);
#ifdef IEEE80215_DEBUG
	printk(KERN_INFO"Debug enabled\n");
	// dbg_init(&ieee80215_debug_opts, s_leveles, NMODS, s_modules, ts);
	printk(KERN_INFO "debug_opts: %s\n", debug_opts);
#if 0
	if (parse_debug_opts(&ieee80215_debug_opts, debug_opts)) {
		return -EINVAL;
	}
#endif
#endif
	return 0;
}

static void __exit ieee80215_core_exit ( void )
{
	printk(KERN_INFO "%s()\n", __FUNCTION__);
}

module_init ( ieee80215_core_init );
module_exit ( ieee80215_core_exit );

MODULE_LICENSE ( "GPL" );


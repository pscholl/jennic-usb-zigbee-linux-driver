/*
 * ZigBee TTY line discipline.
 *
 * Provides interface between ZigBee stack and IEEE 802.15.4 compatible
 * firmware over serial line. Communication protocol is described below.
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
 * Maxim Gorbachyov <maxim.gorbachev@siemens.com>
 * Maxim Osipov <maxim.osipov@siemens.com>
 * Sergey Lapin <sergey.lapin@siemens.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/tty.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/skbuff.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <asm/string.h>
#include <linux/if.h>
#include <linux/netdevice.h>
/*
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
*/
#include <net/ieee80215/ieee80215.h>
#include <net/ieee80215/const.h>
#include <net/ieee80215/mac.h>
#include <net/ieee80215/phy.h>
#if 0
#include <net/zb_aps.h>
#include <net/zb_phy_serial.h>
#include <net/zb_debug.h>
#endif


/* NOTE: be sure to use here the same values as in the firmware */
#define START_BYTE1	'z'
#define START_BYTE2	'b'
#define MAX_DATA_SIZE	127

#define IDLE_MODE	0x00
#define RX_MODE		0x02
#define TX_MODE		0x03
#define FORCE_TRX_OFF	0xF0

#define STATUS_SUCCESS	0
#define STATUS_RX_ON	1
#define STATUS_TX_ON	2
#define STATUS_TRX_OFF	3
#define STATUS_IDLE	4
#define STATUS_BUSY	5
#define STATUS_BUSY_RX	6
#define STATUS_BUSY_TX	7
#define STATUS_ERR	8

/*
 * The following messages are used to control ZigBee firmware.
 * All communication has request/response format,
 * except of asynchronous incoming data stream (DATA_RECV_* messages).
 */
typedef enum {
	NO_ID			= 0, /* means no pending id */

	/* Driver to Firmware */
	CMD_OPEN		= 0x01, /* u8 id */
	CMD_CLOSE		= 0x02, /* u8 id */
	CMD_SET_CHANNEL		= 0x04, /* u8 id, u8 channel */
	CMD_ED			= 0x05, /* u8 id */
	CMD_CCA			= 0x06, /* u8 id */
	CMD_SET_STATE		= 0x07, /* u8 id, u8 flag */
	DATA_XMIT_BLOCK		= 0x09, /* u8 id, u8 len, u8 data[len] */
	DATA_XMIT_STREAM	= 0x0a, /* u8 id, u8 c */
	RESP_RECV_BLOCK		= 0x0b, /* u8 id, u8 status */
	RESP_RECV_STREAM	= 0x0c, /* u8 id, u8 status */

	/* Firmware to Driver */
	RESP_OPEN		= 0x81, /* u8 id, u8 status */
	RESP_CLOSE		= 0x82, /* u8 id, u8 status */
	RESP_SET_CHANNEL 	= 0x84, /* u8 id, u8 status */
	RESP_ED			= 0x85, /* u8 id, u8 status, u8 level */
	RESP_CCA		= 0x86, /* u8 id, u8 status */
	RESP_SET_STATE		= 0x87, /* u8 id, u8 status */
	RESP_XMIT_BLOCK		= 0x89, /* u8 id, u8 status */
	RESP_XMIT_STREAM	= 0x8a, /* u8 id, u8 status */
	DATA_RECV_BLOCK		= 0x8b, /* u8 id, u8 lq, u8 len, u8 data[len] */
	DATA_RECV_STREAM	= 0x8c  /* u8 id, u8 c */
} zb_pkt_t;

typedef enum {
	STATE_WAIT_START1,
	STATE_WAIT_START2,
	STATE_WAIT_COMMAND,
	STATE_WAIT_PARAM1,
	STATE_WAIT_PARAM2,
	STATE_WAIT_DATA
} state_t;

struct zb_device {
	/* Relative devices */
	struct tty_struct	*tty;
	/*struct net_device	*netdev;*/
	ieee80215_phy_t 	*phy;

	/* Internal state */
	struct list_head	list;
	struct completion	open_done;
	unsigned char		opened;
	struct delayed_work	resp_timeout;
	volatile u8		pending_id;
	volatile unsigned int	pending_size;
	u8			*pending_data;

	/* Command (rx) processing */
	state_t			state;
	unsigned char		id;
	unsigned char		param1;
	unsigned char		param2;
	unsigned char		index;
	unsigned char		data[MAX_DATA_SIZE];
};

static char	*name;
/*static u64	addr64;*/
module_param_named(dev_name, name, charp, 0);
/*module_param_named(mac_addr, addr64, ulong, 0);*/

static struct list_head zbd_list_head;

/*****************************************************************************
 * Helper functions for ZigBee device structure identification
 *****************************************************************************/

static struct zb_device*
get_zbd_by_phy(struct ieee80215_phy *phy)
{
	struct list_head *itr;
	struct zb_device *p, *ret = NULL;

	list_for_each(itr, &zbd_list_head) {
		p = list_entry(itr, struct zb_device, list);
		if (phy == p->phy) {
			ret = p;
			break;
		}
	}
	return ret;
}

static struct zb_device*
get_zbd_by_tty(struct tty_struct *tty)
{
	struct list_head *itr;
	struct zb_device *p, *ret = NULL;

	list_for_each(itr, &zbd_list_head) {
		p = list_entry(itr, struct zb_device, list);
		if (tty == p->tty) {
			ret = p;
			break;
		}
	}
	return ret;
}


/*****************************************************************************
 * ZigBee serial device protocol handling
 *****************************************************************************/

static void 
_send_pending_data(struct zb_device *zbdev)
{
	unsigned int j;
	struct tty_struct *tty;
	
	BUG_ON(!zbdev);
	tty = zbdev->tty;
	BUG_ON(!tty);

	/* Debug info */
	printk(KERN_INFO "%lu %s, %d bytes:", jiffies, __FUNCTION__, zbdev->pending_size);
	for (j = 0; j < zbdev->pending_size; ++j) {
		printk(" 0x%02X", zbdev->pending_data[j]);
	}
	printk("\n");

	if (tty->driver->ops->write(tty, zbdev->pending_data, zbdev->pending_size) == zbdev->pending_size) {
		/*
		zbdev->netdev->stats.tx_packets++;
		zbdev->netdev->stats.tx_bytes += zbdev->pending_size;
		*/
	} else {
		/*zbdev->netdev->stats.tx_errors++;*/
		printk(KERN_ERR "%s: device write failed\n", __FUNCTION__);
	}
	return;
}

static int
_prepare_cmd(struct zb_device *zbdev, u8 id, u8 extra)
{
	u8 len = 0, buf[4];	/* 4 because of 2 start bytes, id and optional extra */

	/* Check arguments */
	BUG_ON(!zbdev);

	printk("%s(): id = %u\n", __FUNCTION__, id);
	if (zbdev->pending_size) {
		printk(KERN_ERR "%s(): cmd is already pending, id = %u\n",
			__FUNCTION__, zbdev->pending_id);
		BUG();
	}

	/* Prepare a message */
	buf[len++] = START_BYTE1;
	buf[len++] = START_BYTE2;
	buf[len++] = id;

	switch (id) {
	case CMD_SET_CHANNEL:
	case CMD_SET_STATE:
	case DATA_XMIT_STREAM:
	case RESP_RECV_BLOCK:
	case RESP_RECV_STREAM:
		buf[len++] = extra;
	}

	zbdev->pending_id = id;
	zbdev->pending_size = len;
	zbdev->pending_data = kzalloc(zbdev->pending_size, GFP_KERNEL);
	if (!zbdev->pending_data) {
		printk(KERN_ERR "%s(): unable to allocate memory\n", __FUNCTION__);
		zbdev->pending_id = 0;
		zbdev->pending_size = 0;
		return -ENOMEM;
	}
	memcpy(zbdev->pending_data, buf, len);
	return 0;
}

static int
_prepare_block(struct zb_device *zbdev, u8 len, u8 *data)
{
	u8 i = 0, buf[4];	/* 4 because of 2 start bytes, id and len */

	/* Check arguments */
	BUG_ON(!zbdev);

	printk("%s(): id = %u\n", __FUNCTION__, DATA_XMIT_BLOCK);
	if (zbdev->pending_size) {
		printk(KERN_ERR "%s(): cmd is already pending, id = %u\n",
			__FUNCTION__, zbdev->pending_id);
		BUG();
	}

	/* Prepare a message */
	buf[i++] = START_BYTE1;
	buf[i++] = START_BYTE2;
	buf[i++] = DATA_XMIT_BLOCK;
	buf[i++] = len;

	zbdev->pending_id = DATA_XMIT_BLOCK;
	zbdev->pending_size = i + len;
	zbdev->pending_data = kzalloc(zbdev->pending_size, GFP_KERNEL);
	if (!zbdev->pending_data) {
		printk(KERN_ERR "%s(): unable to allocate memory\n", __FUNCTION__);
		zbdev->pending_id = 0;
		zbdev->pending_size = 0;
		return -ENOMEM;
	}
	memcpy(zbdev->pending_data, buf, i);
	memcpy(zbdev->pending_data + i, data, len);
	return 0;
}

static void
cleanup(struct zb_device *zbdev)
{
	zbdev->state = STATE_WAIT_START1;
	zbdev->id = 0;
	zbdev->param1 = 0;
	zbdev->param2 = 0;
	zbdev->index = 0;
}

static int
is_command(unsigned char c)
{
	switch (c) {
	/* ids we can get here: */
	case RESP_OPEN:
	case RESP_CLOSE:
	case RESP_SET_CHANNEL:
	case RESP_ED:
	case RESP_CCA:
	case RESP_SET_STATE:
	case RESP_XMIT_BLOCK:
	case RESP_XMIT_STREAM:
	case DATA_RECV_BLOCK:
	case DATA_RECV_STREAM:
		return 1;
	}
	return 0;
}

static int
_match_pending_id(struct zb_device *zbdev)
{
	if ((CMD_OPEN == zbdev->pending_id && RESP_OPEN == zbdev->id)
		|| (CMD_CLOSE == zbdev->pending_id && RESP_CLOSE == zbdev->id)
		|| (CMD_SET_CHANNEL == zbdev->pending_id && RESP_SET_CHANNEL == zbdev->id)
		|| (CMD_ED == zbdev->pending_id && RESP_ED == zbdev->id)
		|| (CMD_CCA == zbdev->pending_id && RESP_CCA == zbdev->id)
		|| (CMD_SET_STATE == zbdev->pending_id && RESP_SET_STATE == zbdev->id)
		|| (DATA_XMIT_BLOCK == zbdev->pending_id && RESP_XMIT_BLOCK == zbdev->id)
		|| (DATA_XMIT_STREAM == zbdev->pending_id && RESP_XMIT_STREAM == zbdev->id)
		|| DATA_RECV_BLOCK == zbdev->id
		|| DATA_RECV_STREAM == zbdev->id) {
		return 1;
	}
	return 0;
}

static void
process_command(struct zb_device *zbdev)
{
	u8 status;

	/* Command processing */
	if (!_match_pending_id(zbdev)) {
		return;
	}

	if (RESP_OPEN == zbdev->id && STATUS_SUCCESS == zbdev->param1) {
		zbdev->opened = 1;
		complete(&zbdev->open_done);
		return;
	}

	if (!zbdev->opened) {
		return;
	}

	/* Update statistics
	zbdev->netdev->stats.rx_packets++;
	*/

	cancel_delayed_work(&zbdev->resp_timeout);
	zbdev->pending_id = 0;
	kfree(zbdev->pending_data);
	zbdev->pending_data = NULL;
	zbdev->pending_size = 0;

	if (STATUS_SUCCESS == zbdev->param1) {
		status = IEEE80215_PHY_SUCCESS;
	} else {
		status = IEEE80215_ERROR;
	}
	switch (zbdev->id) {
	case RESP_SET_CHANNEL:
		zbdev->phy->set_channel_confirm(zbdev->phy, status);
		break;
	case RESP_ED:
		zbdev->phy->ed_confirm(zbdev->phy, status, zbdev->param2 /* level */);
		break;
	case RESP_CCA:
		/* zbdev->param1 is STATUS_ERR or STATUS_BUSY or STATUS_IDLE */
		if (STATUS_IDLE == zbdev->param1) {
			status = IEEE80215_IDLE;
		} else {
			status = IEEE80215_BUSY;
		}
		zbdev->phy->cca_confirm(zbdev->phy, status);
		break;
	case RESP_SET_STATE:
		if (STATUS_SUCCESS == zbdev->param1) {
			status = IEEE80215_PHY_SUCCESS;
		} else if (STATUS_TRX_OFF == zbdev->param1) {
			status = IEEE80215_TRX_OFF;
		} else if (STATUS_RX_ON == zbdev->param1) {
			status = IEEE80215_RX_ON;
		} else if (STATUS_TX_ON == zbdev->param1) {
			status = IEEE80215_TX_ON;
		} else if (STATUS_BUSY_RX == zbdev->param1) {
			status = IEEE80215_BUSY_RX;
		} else if (STATUS_BUSY_TX == zbdev->param1) {
			status = IEEE80215_BUSY_TX;
		} else if (STATUS_BUSY == zbdev->param1) {
			status = IEEE80215_BUSY;
		} else {
			printk(KERN_ERR "%s: bad status received from firmware: %u\n",
				__FUNCTION__, zbdev->param1);
			status = IEEE80215_ERROR;
		}
		zbdev->phy->set_state_confirm(zbdev->phy, status);
		break;
	case RESP_XMIT_BLOCK:
		zbdev->phy->xmit_confirm(zbdev->phy, status);
		break;
	case RESP_XMIT_STREAM:
		zbdev->phy->xmit_confirm(zbdev->phy, status);
		break;
	case DATA_RECV_BLOCK:
		/* zbdev->param1 is LQ, zbdev->param2 is length */
		zbdev->phy->receive_block(zbdev->phy, zbdev->param2, zbdev->data, zbdev->param1);
		break;
	case DATA_RECV_STREAM:
		/* TODO: update firmware to use this */
		zbdev->phy->receive_stream(zbdev->phy, zbdev->param2, zbdev->param1);
		break;
	}
}

static void
process_char(struct zb_device *zbdev, unsigned char c)
{
	/* Update statistics
	zbdev->netdev->stats.rx_bytes++;
	*/

	/* Data processing */
	switch (zbdev->state) {
	case STATE_WAIT_START1:
		if (START_BYTE1 == c) {
			zbdev->state = STATE_WAIT_START2;
		}
		break;

	case STATE_WAIT_START2:
		if (START_BYTE2 == c) {
			zbdev->state = STATE_WAIT_COMMAND;
		} else {
			cleanup(zbdev);
		}
		break;

	case STATE_WAIT_COMMAND:
		if (is_command(c)) {
			zbdev->id = c;
			zbdev->state = STATE_WAIT_PARAM1;
		} else {
			cleanup(zbdev);
			printk(KERN_ERR "%s, unexpected command id: %x\n", __FUNCTION__, c);
		}
		break;

	case STATE_WAIT_PARAM1:
		zbdev->param1 = c;
		if ((RESP_ED == zbdev->id) || (DATA_RECV_BLOCK == zbdev->id)) {
			zbdev->state = STATE_WAIT_PARAM2;
		} else {
			process_command(zbdev);
			cleanup(zbdev);
		}
		break;

	case STATE_WAIT_PARAM2:
		zbdev->param2 = c;
		if (RESP_ED == zbdev->id) {
			process_command(zbdev);
			cleanup(zbdev);
		} else if (DATA_RECV_BLOCK == zbdev->id) {
			zbdev->state = STATE_WAIT_DATA;
		} else {
			cleanup(zbdev);
		}
		break;

	case STATE_WAIT_DATA:
		if (zbdev->index < sizeof(zbdev->data)) {
			zbdev->data[zbdev->index] = c;
			zbdev->index++;
			/* Pending data is received, param2 is length for DATA_RECV_BLOCK */
			if (zbdev->index == zbdev->param2) {
				process_command(zbdev);
				cleanup(zbdev);
			}
		} else {
			printk(KERN_ERR "%s(): data size is greater "
				"than buffer available\n", __FUNCTION__);
			cleanup(zbdev);
		}
		break;

	default:
		cleanup(zbdev);
	}
}

/*****************************************************************************
 * Device operations for IEEE 802.15.4 PHY side interface ZigBee stack
 *****************************************************************************/

static int _open_dev(struct zb_device *zbdev) {
	int retries;

	if (_prepare_cmd(zbdev, CMD_OPEN, 0) != 0) {
		return 0;
	}

	retries = 5;
	while (!zbdev->opened && retries) {
		_send_pending_data(zbdev);
		/* 1 second before retransmission */
		wait_for_completion_interruptible_timeout(&zbdev->open_done, HZ);
		--retries;
	}

	zbdev->pending_id = 0;
	kfree(zbdev->pending_data);
	zbdev->pending_data = NULL;
	zbdev->pending_size = 0;

	if (zbdev->opened) {
		return 1;
	}
	return 0;
}

/* Valid channels: 1-16 */
static void
zb_serial_set_channel(ieee80215_phy_t *phy, u8 channel)
{
	struct zb_device *zbdev;

	zbdev = get_zbd_by_phy(phy);
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return;
	}

	if (!zbdev->opened) {
		if (!_open_dev(zbdev)) {
			phy->set_channel_confirm(phy, IEEE80215_ERROR);
			return;
		}
	}

	if (_prepare_cmd(zbdev, CMD_SET_CHANNEL, channel) != 0) {
		phy->set_channel_confirm(phy, IEEE80215_ERROR);
		return;
	}
	/* schedule retransmission in 1 second */
	schedule_delayed_work(&zbdev->resp_timeout, HZ);
	_send_pending_data(zbdev);
}

static void
zb_serial_ed(ieee80215_phy_t *phy)
{
	struct zb_device *zbdev;

	zbdev = get_zbd_by_phy(phy);
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return;
	}

	if (!zbdev->opened) {
		if (!_open_dev(zbdev)) {
			phy->ed_confirm(phy, IEEE80215_ERROR, 0);
			return;
		}
	}

	if (_prepare_cmd(zbdev, CMD_ED, 0) != 0) {
		phy->ed_confirm(phy, IEEE80215_ERROR, 0);
		return;
	}
	/* schedule retransmission in 1 second */
	schedule_delayed_work(&zbdev->resp_timeout, HZ);
	_send_pending_data(zbdev);
}

static void
zb_serial_cca(ieee80215_phy_t *phy, u8 mode)
{
	struct zb_device *zbdev;

	zbdev = get_zbd_by_phy(phy);
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return;
	}

	if (!zbdev->opened) {
		if (!_open_dev(zbdev)) {
			phy->cca_confirm(phy, IEEE80215_ERROR);
			return;
		}
	}

	if (_prepare_cmd(zbdev, CMD_CCA, 0) != 0) {
		phy->cca_confirm(phy, IEEE80215_ERROR);
		return;
	}
	/* schedule retransmission in 1 second */
	schedule_delayed_work(&zbdev->resp_timeout, HZ);
	_send_pending_data(zbdev);
}

static void
zb_serial_set_state(ieee80215_phy_t *phy, u8 state)
{
	struct zb_device *zbdev;
	unsigned char flag;

	zbdev = get_zbd_by_phy(phy);
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return;
	}

	if (IEEE80215_RX_ON == state) {
		flag = RX_MODE;
	} else if (IEEE80215_TX_ON == state) {
		flag = TX_MODE;
	} else if (IEEE80215_TRX_OFF == state) {
		flag = IDLE_MODE;
	} else if (IEEE80215_FORCE_TRX_OFF == state) {
		flag = FORCE_TRX_OFF;
	} else {
		phy->set_state_confirm(phy, IEEE80215_INVALID_PARAMETER);
		return;
	}

	if (!zbdev->opened) {
		if (!_open_dev(zbdev)) {
			phy->set_state_confirm(phy, IEEE80215_ERROR);
			return;
		}
	}

	if (_prepare_cmd(zbdev, CMD_SET_STATE, flag) != 0) {
		phy->set_state_confirm(phy, IEEE80215_ERROR);
		return;
	}
	/* schedule retransmission in 1 second */
	schedule_delayed_work(&zbdev->resp_timeout, HZ);
	_send_pending_data(zbdev);
}

static void
zb_serial_xmit(ieee80215_phy_t *phy, u8 *ppdu, size_t len)
{
	struct zb_device *zbdev;

	zbdev = get_zbd_by_phy(phy);
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return;
	}

	if (!zbdev->opened) {
		if (!_open_dev(zbdev)) {
			phy->xmit_confirm(phy, IEEE80215_ERROR);
			return;
		}
	}

	if (_prepare_block(zbdev, len, ppdu) != 0) {
		phy->xmit_confirm(phy, IEEE80215_ERROR);
		return;
	}
	/* schedule retransmission in 1 second */
	schedule_delayed_work(&zbdev->resp_timeout, HZ);
	_send_pending_data(zbdev);
}

static ieee80215_dev_op_t *_alloc_dev_op(void)
{
	ieee80215_dev_op_t *dev_op;

	dev_op = kzalloc(sizeof(*dev_op), GFP_KERNEL);
	if (!dev_op) {
		printk(KERN_ERR "%s: unable to allocate memory\n", __FUNCTION__);
		return NULL;
	}
	dev_op->name 		= name;		/* module param */
	dev_op->set_channel	= zb_serial_set_channel;
	dev_op->ed		= zb_serial_ed;
	dev_op->cca		= zb_serial_cca;
	dev_op->set_state	= zb_serial_set_state;
	dev_op->xmit		= zb_serial_xmit;

	return dev_op;
}

/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/

static void _on_resp_timeout(struct work_struct *work)
{
	struct zb_device *zbdev = container_of(work, struct zb_device, resp_timeout.work);

	if (zbdev->pending_size) {
		printk(KERN_INFO "%lu %s(): device response timeout, retry\n",
			jiffies, __FUNCTION__);
		/* schedule retransmission in 1 second */
		schedule_delayed_work(&zbdev->resp_timeout, HZ);
		_send_pending_data(zbdev);
	}
	/* TODO: count retries;
	 * call appropriate phy->(...)_confirm with error code
	 * if retries count exceeds limit */
}

/*
 * Called when a tty is put into ZB line discipline. Called in process context.
 * Returns 0 on success.
 */
static int
zb_tty_open(struct tty_struct *tty)
{
	struct zb_device *zbdev;
	int err;
	ieee80215_dev_op_t *dev_op;
	ieee80215_phy_t *phy;
	/*
	ieee80215_mac_t *mac;
	zb_nwk_t *nwk;
	*/

	if(!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Allocate device structure */
	zbdev = kzalloc(sizeof(struct zb_device), GFP_KERNEL);
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: can't allocate zb_device structure.\n", __FUNCTION__);
		return -ENOMEM;
	}
	init_completion(&zbdev->open_done);
	INIT_DELAYED_WORK(&zbdev->resp_timeout, _on_resp_timeout);

	dev_op = _alloc_dev_op();
	if (!dev_op) {
		kfree(zbdev);
		return -ENOMEM;
	}

	err = ieee80215_register_device(dev_op);
	if (err) {
		printk(KERN_ERR "%s: device register failed\n", __FUNCTION__);
		kfree(dev_op);
		kfree(zbdev);
		return err;
	}

	phy = (ieee80215_phy_t*)dev_op->priv;
	zbdev->phy = phy;
	zbdev->tty = tty;
	cleanup(zbdev);

	tty->disc_data = zbdev;
	tty->receive_room = MAX_DATA_SIZE;

	list_add(&zbdev->list, &zbd_list_head);
	return 0;
}

/*
 * Called when the tty is put into another line discipline or it hangs up. We
 * have to wait for any cpu currently executing in any of the other zb_tty_*
 * routines to finish before we can call zb_tty_close and free the
 * zb_serial_dev struct. This routine must be called from process context, not
 * interrupt or softirq context.
 */
static void
zb_tty_close(struct tty_struct *tty)
{
	struct zb_device *zbdev;
	ieee80215_dev_op_t *dev_op;

	zbdev = get_zbd_by_tty(tty);
	if (NULL == zbdev) {
		printk(KERN_WARNING "%s: match is not found\n", __FUNCTION__);
		return;
	}

	list_del(&zbdev->list);
	tty->disc_data = NULL;

	dev_op = zbdev->phy->dev_op;
	ieee80215_unregister_device(dev_op);
	kfree(dev_op);
	kfree(zbdev);
}

/*
 * Called on tty hangup in process context.
 */
static int
zb_tty_hangup(struct tty_struct *tty)
{
	zb_tty_close(tty);
	return 0;
}

/*
 * Called in process context only. May be re-entered by multiple ioctl calling threads.
 */
static int
zb_tty_ioctl(struct tty_struct *tty, struct file *file, unsigned int cmd, unsigned long arg)
{
	struct zb_device *zbdev;
//	struct ieee80215_mac *mac;
//	zb_nwk_t *nwk;
//	zb_aps_t *aps;
//	struct net_device *dev;
	struct ifreq ifr;

	pr_debug("cmd = 0x%x\n", cmd);
	memset(&ifr, 0, sizeof(ifr));

	zbdev = get_zbd_by_tty(tty);
	if (NULL == zbdev) {
		pr_debug("match is not found\n");
		return -EINVAL;
	}

//	mac = _mac(zbdev->phy);
//	nwk = _nhle(mac);
//	aps = _apsme(nwk);
//	dev = (struct net_device*)aps->priv;
	switch (cmd) {
#if 0
	case ZIGBEE_GET_NETDEV_NAME:
		strncpy(ifr.ifr_name, dev->name, min(strlen(dev->name), sizeof(ifr.ifr_name) - 1));
		if (copy_to_user((void __user *)arg, &ifr, sizeof(ifr))) {
			zb_err("copy_to_user() failed\n");
			return -EINVAL;
		}
		return 0;
#endif	
	default:
		pr_debug("Unknown ioctl cmd: %u\n", cmd);
		return IEEE80215_ERROR;
	}
	return 0;
}


/*
 * This can now be called from hard interrupt level as well
 * as soft interrupt level or mainline.
 */
static void
zb_tty_receive(struct tty_struct *tty, const unsigned char *buf, char *cflags, int count)
{
	struct zb_device *p_zbd;
	int i;

	/* Debug info */
	printk(KERN_INFO "%lu %s, received %d bytes:", jiffies, __FUNCTION__, count);
	for (i = 0; i < count; ++i) {
		printk(" 0x%02X", buf[i]);
	}
	printk("\n");

	/* Actual processing */
	p_zbd = get_zbd_by_tty(tty);
	if (NULL == p_zbd) {
		printk(KERN_ERR "%s(): record for tty is not found\n", __FUNCTION__);
		return;
	}
	for (i = 0; i < count; ++i) {
		process_char(p_zbd, buf[i]);
	}
#if 0
	if (tty->driver->flush_chars) {
		tty->driver->flush_chars(tty);
	}
#endif
	if (test_and_clear_bit(TTY_THROTTLED, &tty->flags) &&
		tty->driver->ops->unthrottle) {
		tty->driver->ops->unthrottle(tty);
	}
}

/*
 * Line discipline device structure
 */
static struct tty_ldisc_ops zb_ldisc = {
	.owner  = THIS_MODULE,
	.magic	= TTY_LDISC_MAGIC,
	.name	= "zb-ldisc",
	.open	= zb_tty_open,
	.close	= zb_tty_close,
	.hangup	= zb_tty_hangup,
	.receive_buf = zb_tty_receive,
	.ioctl	= zb_tty_ioctl,
};

/*****************************************************************************
 * Module service routinues
 *****************************************************************************/

static int __init zb_serial_init(void)
{
	printk(KERN_INFO "Initializing ZigBee TTY interface. Device name = %s\n", name);

	INIT_LIST_HEAD(&zbd_list_head);
	/*init_completion(&ready);*/

	if (tty_register_ldisc(N_IEEE80215, &zb_ldisc) != 0) {
		printk(KERN_ERR "%s: line discipline register failed\n", __FUNCTION__);
		return -EINVAL;
	}
#if 0
	int i;

	printk(KERN_INFO "mac_addr =");
	for (i = 0; i < sizeof(addr64); ++i) {
		printk(" %02X", (unsigned char)*((unsigned char*)&addr64 + i));
	}
	printk("\n");
#endif
	return 0;
}

static void __exit zb_serial_cleanup(void)
{
	if (tty_unregister_ldisc(N_IEEE80215) != 0)
		printk(KERN_CRIT "failed to unregister ZigBee line discipline.\n");
}

module_init(zb_serial_init);
module_exit(zb_serial_cleanup);

MODULE_LICENSE("GPL");
MODULE_ALIAS_LDISC(N_ZB);


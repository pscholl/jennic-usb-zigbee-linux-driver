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
#include <linux/skbuff.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/af_ieee80215.h>
#include <net/ieee80215/dev.h>
#include <net/ieee80215/netdev.h>


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
	struct ieee80215_dev	*dev;

	/* locks the ldisc for the command */
	struct mutex		mutex;

	/* command completition */
	wait_queue_head_t	wq;
	phy_status_t		status;
	u8			ed;

	/* Internal state */
	struct completion	open_done;
	struct completion	work_done;
	unsigned char		opened;
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

	/* simple TX queue implementation */
	struct sk_buff_head	tx_queue;
	struct work_struct	work;
};

static char	*name;
/*static u64	addr64;*/
module_param_named(dev_name, name, charp, 0);
/*module_param_named(mac_addr, addr64, ulong, 0);*/

/*****************************************************************************
 * ZigBee serial device protocol handling
 *****************************************************************************/
static int
send_block(struct zb_device *zbdev, u8 len, u8 *data);

static void serial_tx_worker(struct work_struct *work)
{
	int ret;
	struct sk_buff *skb;
	struct zb_device *zbdev =
		container_of(work, struct zb_device, work);
	if (mutex_lock_interruptible(&zbdev->mutex))
		return; /* FIXME */
	while(skb_queue_len(&zbdev->tx_queue) > 0) {
		struct net_device *dev;
		skb = skb_dequeue_tail(&zbdev->tx_queue);
		BUG_ON(!skb);
		dev = skb->dev;

		if (send_block(zbdev, skb->len, skb->data) != 0) {
			ret = PHY_ERROR;
			goto out;
		}
		kfree_skb(skb);
		if (wait_event_interruptible(zbdev->wq, zbdev->status != PHY_INVAL))
			zbdev->status = PHY_ERROR;
		/* FIXME */
		complete(&zbdev->work_done);
		netif_start_queue(dev);
		/* Here we're ready to receive frames */
	}
out:
	mutex_unlock(&zbdev->mutex);
}

static int _open_dev(struct zb_device *zbdev);

static int 
_send_pending_data(struct zb_device *zbdev)
{
	unsigned int j;
	struct tty_struct *tty;

	BUG_ON(!zbdev);
	tty = zbdev->tty;
	BUG_ON(!tty);

	zbdev->status = PHY_INVAL;

	/* Debug info */
	printk(KERN_INFO "%lu %s, %d bytes:", jiffies, __FUNCTION__, zbdev->pending_size);
	for (j = 0; j < zbdev->pending_size; ++j) {
		printk(" 0x%02X", zbdev->pending_data[j]);
	}
	printk("\n");

	if (tty->driver->ops->write(tty, zbdev->pending_data, zbdev->pending_size) != zbdev->pending_size) {
		printk(KERN_ERR "%s: device write failed\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

static int
send_cmd(struct zb_device *zbdev, u8 id)
{
	u8 len = 0, buf[4];	/* 4 because of 2 start bytes, id and optional extra */

	/* Check arguments */
	BUG_ON(!zbdev);

	if (!zbdev->opened) {
		if (!_open_dev(zbdev))
			return -EAGAIN;
	}

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

	return _send_pending_data(zbdev);
}

static int
send_cmd2(struct zb_device *zbdev, u8 id, u8 extra)
{
	u8 len = 0, buf[4];	/* 4 because of 2 start bytes, id and optional extra */

	/* Check arguments */
	BUG_ON(!zbdev);

	if (!zbdev->opened) {
		if (!_open_dev(zbdev))
			return -EAGAIN;
	}

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
	buf[len++] = extra;

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

	return _send_pending_data(zbdev);
}

static int
send_block(struct zb_device *zbdev, u8 len, u8 *data)
{
	u8 i = 0, buf[4];	/* 4 because of 2 start bytes, id and len */

	/* Check arguments */
	BUG_ON(!zbdev);

	if (!zbdev->opened) {
		if (!_open_dev(zbdev))
			return -EAGAIN;
	}

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

	return _send_pending_data(zbdev);
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

static void serial_net_rx(struct zb_device *zbdev)
{
	/* zbdev->param1 is LQI
	 * zbdev->param2 is length of data
	 * zbdev->data is data itself
	 */
	struct sk_buff *skb;
	skb = alloc_skb(zbdev->param2, GFP_ATOMIC);
	skb_put(skb, zbdev->param2);
	skb_copy_to_linear_data(skb, zbdev->data, zbdev->param2);
	ieee80215_rx(zbdev->dev, skb, zbdev->param1);
}

static void
process_command(struct zb_device *zbdev)
{
//	phy_status_t status;
//	u8 data = 0;
//	struct ieee80215_dev * dev = zbdev->dev;

	/* Command processing */
	if (!_match_pending_id(zbdev)) {
		return;
	}

	if (RESP_OPEN == zbdev->id && STATUS_SUCCESS == zbdev->param1) {
		zbdev->opened = 1;
		pr_debug("Opened device\n");
		complete(&zbdev->open_done);
		/* Input is not processed during output, so
		 * using completion is not possible during output.
		 * so we need to handle open as any other command
		 * and hope for best
		 */
		return;
	}

	if (!zbdev->opened) {
		return;
	}

	zbdev->pending_id = 0;
	kfree(zbdev->pending_data);
	zbdev->pending_data = NULL;
	zbdev->pending_size = 0;
	if (zbdev->id != DATA_RECV_BLOCK)
		switch(zbdev->param1) {
		case STATUS_SUCCESS:
			zbdev->status = PHY_SUCCESS;
			break;
		case STATUS_RX_ON:
			zbdev->status = PHY_RX_ON;
			break;
		case STATUS_TX_ON:
			zbdev->status = PHY_TX_ON;
			break;
		case STATUS_TRX_OFF:
			zbdev->status = PHY_TRX_OFF;
			break;
		case STATUS_BUSY:
			zbdev->status = PHY_BUSY;
			break;
		case STATUS_IDLE:
			zbdev->status = PHY_IDLE;
			break;
		case STATUS_BUSY_RX:
			zbdev->status = PHY_BUSY_RX;
			break;
		case STATUS_BUSY_TX:
			zbdev->status = PHY_BUSY_TX;
			break;
		default:
			printk(KERN_ERR "%s: bad status received from firmware: %u\n",
				__FUNCTION__, zbdev->param1);
			zbdev->status = PHY_ERROR;
			break;
		}

	switch (zbdev->id) {
	case RESP_ED:
		zbdev->ed = zbdev->param2;
		break;
	case DATA_RECV_BLOCK:
		printk("Received block, lqi %02x, len %02x\n", zbdev->param1, zbdev->param2);
		/* zbdev->param1 is LQ, zbdev->param2 is length */
		serial_net_rx(zbdev);
		break;
	case DATA_RECV_STREAM:
		/* TODO: update firmware to use this */
		break;
	}

	wake_up(&zbdev->wq);
}

static void
process_char(struct zb_device *zbdev, unsigned char c)
{
	/* Data processing */
	pr_debug("Char: %d (0x%02x)\n", c, c);
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
	u8 len = 0, buf[4];	/* 4 because of 2 start bytes, id and optional extra */

	/* Check arguments */
	BUG_ON(!zbdev);
	if(zbdev->opened)
		return 1;

	printk("%s()\n", __FUNCTION__);
	if (zbdev->pending_size) {
		printk(KERN_ERR "%s(): cmd is already pending, id = %u\n",
			__FUNCTION__, zbdev->pending_id);
		BUG();
	}

	/* Prepare a message */
	buf[len++] = START_BYTE1;
	buf[len++] = START_BYTE2;
	buf[len++] = CMD_OPEN;

	zbdev->pending_id = CMD_OPEN;
	zbdev->pending_size = len;
	zbdev->pending_data = kzalloc(zbdev->pending_size, GFP_KERNEL);
	if (!zbdev->pending_data) {
		printk(KERN_ERR "%s(): unable to allocate memory\n", __FUNCTION__);
		zbdev->pending_id = 0;
		zbdev->pending_size = 0;
		return -ENOMEM;
	}
	memcpy(zbdev->pending_data, buf, len);

	retries = 5;
	while (!zbdev->opened && retries) {
		if(_send_pending_data(zbdev) != 0)
			return 0;

		/* 3 second before retransmission */
		wait_for_completion_interruptible_timeout(&zbdev->open_done, msecs_to_jiffies(1000));
		--retries;
	}

	zbdev->pending_id = 0;
	kfree(zbdev->pending_data);
	zbdev->pending_data = NULL;
	zbdev->pending_size = 0;

	if (zbdev->opened) {
		return 1;
	}
	/* We always fail here, hoping commands will retry their stuff
	 * as soon as device is open
	 */

	zbdev->pending_id = 0;
	kfree(zbdev->pending_data);
	zbdev->pending_data = NULL;
	zbdev->pending_size = 0;
	return 0;
}

/* Valid channels: 1-16 */
static phy_status_t
ieee80215_serial_set_channel(struct ieee80215_dev *dev, int channel)
{
	struct zb_device *zbdev;
	phy_status_t ret;

	pr_debug("%s\n",__FUNCTION__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return PHY_INVAL;
	}

	if (mutex_lock_interruptible(&zbdev->mutex))
		return PHY_ERROR;

	if (send_cmd2(zbdev, CMD_SET_CHANNEL, channel) != 0) {
		ret = PHY_ERROR;
		goto out;
	}

	if (!wait_event_interruptible(zbdev->wq, zbdev->status != PHY_INVAL))
		ret = zbdev->status;
	else
		ret = PHY_ERROR;
out:
	mutex_unlock(&zbdev->mutex);
	pr_debug("%s end\n",__FUNCTION__);
	return ret;
}

static phy_status_t
ieee80215_serial_ed(struct ieee80215_dev *dev, u8 *level)
{
	struct zb_device *zbdev;
	phy_status_t ret;

	pr_debug("%s\n",__FUNCTION__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return PHY_INVAL;
	}

	if (mutex_lock_interruptible(&zbdev->mutex))
		return PHY_ERROR;

	if (send_cmd(zbdev, CMD_ED) != 0) {
		ret = PHY_ERROR;
		goto out;
	}

	if (!wait_event_interruptible(zbdev->wq, zbdev->status != PHY_INVAL)) {
		*level = zbdev->ed;
		ret = zbdev->status;
	} else
		ret = PHY_ERROR;
out:
	mutex_unlock(&zbdev->mutex);
	pr_debug("%s end\n",__FUNCTION__);
	return ret;
}

static phy_status_t
ieee80215_serial_cca(struct ieee80215_dev *dev)
{
	struct zb_device *zbdev;
	phy_status_t ret;

	pr_debug("%s\n",__FUNCTION__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return PHY_INVAL;
	}

	if (mutex_lock_interruptible(&zbdev->mutex))
		return PHY_ERROR;

	if (send_cmd(zbdev, CMD_CCA) != 0) {
		ret = PHY_ERROR;
		goto out;
	}

	if (!wait_event_interruptible(zbdev->wq, zbdev->status != PHY_INVAL))
		ret = zbdev->status;
	else
		ret = PHY_ERROR;
out:
	mutex_unlock(&zbdev->mutex);
	pr_debug("%s end\n",__FUNCTION__);
	return ret;
}

static phy_status_t
ieee80215_serial_set_state(struct ieee80215_dev *dev, phy_status_t state)
{
	struct zb_device *zbdev;
	unsigned char flag;
	phy_status_t ret;

	pr_debug("%s %d\n",__FUNCTION__, state);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return PHY_INVAL;
	}

	if (mutex_lock_interruptible(&zbdev->mutex))
		return PHY_ERROR;
	switch(state) {
	case PHY_RX_ON:
		flag = RX_MODE;
		break;
	case PHY_TX_ON:
		flag = TX_MODE;
		break;
	case PHY_TRX_OFF:
		flag = IDLE_MODE;
		break;
	case PHY_FORCE_TRX_OFF:
		flag = FORCE_TRX_OFF;
		break;
	default:
		ret = PHY_INVAL;
		goto out;
	}

	if (send_cmd2(zbdev, CMD_SET_STATE, flag) != 0) {
		ret = PHY_ERROR;
		goto out;
	}

	if (!wait_event_interruptible(zbdev->wq, zbdev->status != PHY_INVAL))
		ret = zbdev->status;
	else
		ret = PHY_ERROR;
out:
	mutex_unlock(&zbdev->mutex);
	pr_debug("%s end\n",__FUNCTION__);
	return ret;
}

static phy_status_t
ieee80215_serial_xmit(struct ieee80215_dev *dev, struct sk_buff *skb)
{
	struct zb_device *zbdev;
//	phy_status_t ret;
	struct sk_buff *dev_skb;

	pr_debug("%s\n",__FUNCTION__);

	zbdev = dev->priv;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: wrong phy\n", __FUNCTION__);
		return PHY_INVAL;
	}

	if (mutex_lock_interruptible(&zbdev->mutex))
		return PHY_ERROR;
	init_completion(&zbdev->work_done);
	netif_stop_queue(skb->dev);
	dev_skb = skb_clone(skb, GFP_ATOMIC);
	if(!dev_skb)
		return PHY_ERROR;
	/* Check if that is needed */
	dev_skb->dev = skb->dev;
	/* WARNING: dev_skb is not owned by socket anymore, so it is not possible
	 * to play around socket in device work function
	 */
	skb_queue_tail(&zbdev->tx_queue, dev_skb);
	schedule_work(&zbdev->work);
#if 0
	if (send_block(zbdev, skb->len, skb->data) != 0) {
		ret = PHY_ERROR;
		goto out;
	}

	if (!wait_event_interruptible(zbdev->wq, zbdev->status != PHY_INVAL))
		ret = zbdev->status;
	else
		ret = PHY_ERROR;
out:
#endif
	mutex_unlock(&zbdev->mutex);
	pr_debug("%s end\n",__FUNCTION__);
	return zbdev->status;
}

/*****************************************************************************
 * Line discipline interface for IEEE 802.15.4 serial device
 *****************************************************************************/

static struct ieee80215_ops serial_ops = {
	.owner = THIS_MODULE,
	.tx = ieee80215_serial_xmit,
	.ed = ieee80215_serial_ed,
	.cca = ieee80215_serial_cca,
	.set_trx_state = ieee80215_serial_set_state,
	.set_channel	= ieee80215_serial_set_channel,
	.flags = IEEE80215_OPS_OMIT_CKSUM,
};


/*
 * Called when a tty is put into ZB line discipline. Called in process context.
 * Returns 0 on success.
 */
static int
ieee80215_tty_open(struct tty_struct *tty)
{
	struct zb_device *zbdev = tty->disc_data;
	int err;

	pr_debug("Openning ldisc\n");
	if(!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (zbdev)
		return -EBUSY;

	/* Allocate device structure */
	zbdev = kzalloc(sizeof(struct zb_device), GFP_KERNEL);
	if (NULL == zbdev) {
		printk(KERN_ERR "%s: can't allocate zb_device structure.\n", __FUNCTION__);
		return -ENOMEM;
	}
	mutex_init(&zbdev->mutex);
	init_completion(&zbdev->open_done);
	init_waitqueue_head(&zbdev->wq);
	skb_queue_head_init(&zbdev->tx_queue);
	INIT_WORK(&zbdev->work, serial_tx_worker);

	zbdev->dev = ieee80215_alloc_device();
	if (!zbdev->dev) {
		err = -ENOMEM;
		goto out_free_zb;
	}

	zbdev->dev->name		= "serialdev";
	zbdev->dev->priv		= zbdev;
	zbdev->dev->extra_tx_headroom	= 0;

	zbdev->tty = tty;
	cleanup(zbdev);

	tty->disc_data = zbdev;
	tty->receive_room = MAX_DATA_SIZE;
	tty->low_latency = 1;

	err = ieee80215_register_device(zbdev->dev, &serial_ops);
	if (err) {
		printk(KERN_ERR "%s: device register failed\n", __FUNCTION__);
		goto out_free;
	}

	return 0;

	ieee80215_unregister_device(zbdev->dev);

out_free:
	tty->disc_data = NULL;

	ieee80215_free_device(zbdev->dev);
out_free_zb:
	kfree(zbdev);

	return err;
}

/*
 * Called when the tty is put into another line discipline or it hangs up. We
 * have to wait for any cpu currently executing in any of the other zb_tty_*
 * routines to finish before we can call zb_tty_close and free the
 * zb_serial_dev struct. This routine must be called from process context, not
 * interrupt or softirq context.
 */
static void
ieee80215_tty_close(struct tty_struct *tty)
{
	struct zb_device *zbdev;

	zbdev = tty->disc_data;
	if (NULL == zbdev) {
		printk(KERN_WARNING "%s: match is not found\n", __FUNCTION__);
		return;
	}
	/* FIXME !!! */
	flush_scheduled_work();

	ieee80215_unregister_device(zbdev->dev);

	tty->disc_data = NULL;

	ieee80215_free_device(zbdev->dev);
	kfree(zbdev);
}

/*
 * Called on tty hangup in process context.
 */
static int
ieee80215_tty_hangup(struct tty_struct *tty)
{
	ieee80215_tty_close(tty);
	return 0;
}

/*
 * Called in process context only. May be re-entered by multiple ioctl calling threads.
 */
static int
ieee80215_tty_ioctl(struct tty_struct *tty, struct file *file, unsigned int cmd, unsigned long arg)
{
	struct zb_device *zbdev;
	struct ifreq ifr;

	pr_debug("cmd = 0x%x\n", cmd);
	memset(&ifr, 0, sizeof(ifr));

	zbdev = tty->disc_data;
	if (NULL == zbdev) {
		pr_debug("match is not found\n");
		return -EINVAL;
	}

	switch (cmd) {
	default:
		pr_debug("Unknown ioctl cmd: %u\n", cmd);
		return -EINVAL;
	}
	return 0;
}


/*
 * This can now be called from hard interrupt level as well
 * as soft interrupt level or mainline.
 */
static void
ieee80215_tty_receive(struct tty_struct *tty, const unsigned char *buf, char *cflags, int count)
{
	struct zb_device *zbdev;
	int i;

	/* Debug info */
	printk(KERN_INFO "%lu %s, received %d bytes:", jiffies, __FUNCTION__, count);
	for (i = 0; i < count; ++i) {
		printk(" 0x%02X", buf[i]);
	}
	printk("\n");

	/* Actual processing */
	zbdev = tty->disc_data;
	if (NULL == zbdev) {
		printk(KERN_ERR "%s(): record for tty is not found\n", __FUNCTION__);
		return;
	}
	for (i = 0; i < count; ++i) {
		process_char(zbdev, buf[i]);
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
static struct tty_ldisc_ops ieee80215_ldisc = {
	.owner  = THIS_MODULE,
	.magic	= TTY_LDISC_MAGIC,
	.name	= "ieee80215-ldisc",
	.open	= ieee80215_tty_open,
	.close	= ieee80215_tty_close,
	.hangup	= ieee80215_tty_hangup,
	.receive_buf = ieee80215_tty_receive,
	.ioctl	= ieee80215_tty_ioctl,
};

/*****************************************************************************
 * Module service routinues
 *****************************************************************************/

static int __init ieee80215_serial_init(void)
{
	printk(KERN_INFO "Initializing ZigBee TTY interface");

	/*init_completion(&ready);*/

	if (tty_register_ldisc(N_IEEE80215, &ieee80215_ldisc) != 0) {
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

static void __exit ieee80215_serial_cleanup(void)
{
	if (tty_unregister_ldisc(N_IEEE80215) != 0)
		printk(KERN_CRIT "failed to unregister ZigBee line discipline.\n");
}

module_init(ieee80215_serial_init);
module_exit(ieee80215_serial_cleanup);

MODULE_LICENSE("GPL");
MODULE_ALIAS_LDISC(N_IEEE80215);


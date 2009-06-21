#undef AT86RF230_OLDFW_HACK
/*
 * AT86RF230/RF231 driver
 *
 * Copyright (C) 2009 Siemens AG
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
 * Dmitry Eremin-Solenikov <dmitry.baryshkov@siemens.com>
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/spi/spi.h>
#include <linux/spi/at86rf230.h>
#include <linux/rtnetlink.h> /* FIXME: hack for slave instantiation */

#include <net/ieee802154/mac802154.h>

struct at86rf230_local {
	struct spi_device *spi;
	int rstn, slp_tr, dig2;

	u8 part;
	u8 vers;

	u8 buf[2];
	struct mutex bmux;

	struct work_struct irqwork;
	struct completion tx_complete;

	struct ieee802154_dev *dev;

	spinlock_t lock;
	unsigned irq_disabled:1; /* P: lock */
	unsigned is_tx:1; /* P: lock */
};

#define	RG_TRX_STATUS	(0x01)
#define	SR_TRX_STATUS		0x01, 0x1f, 0
#define	SR_RESERVED_01_3	0x01, 0x20, 5
#define	SR_CCA_STATUS		0x01, 0x40, 6
#define	SR_CCA_DONE		0x01, 0x80, 7
#define	RG_TRX_STATE	(0x02)
#define	SR_TRX_CMD		0x02, 0x1f, 0
#define	SR_TRAC_STATUS		0x02, 0xe0, 5
#define	RG_TRX_CTRL_0	(0x03)
#define	SR_CLKM_CTRL		0x03, 0x07, 0
#define	SR_CLKM_SHA_SEL		0x03, 0x08, 3
#define	SR_PAD_IO_CLKM		0x03, 0x30, 4
#define	SR_PAD_IO		0x03, 0xc0, 6
#define	RG_TRX_CTRL_1	(0x04)
#define	SR_IRQ_POLARITY		0x04, 0x01, 0
#define	SR_IRQ_MASK_MODE	0x04, 0x02, 1
#define	SR_SPI_CMD_MODE		0x04, 0x0c, 2
#define	SR_RX_BL_CTRL		0x04, 0x10, 4
#define	SR_TX_AUTO_CRC_ON	0x04, 0x20, 5
#define	SR_IRQ_2_EXT_EN		0x04, 0x40, 6
#define	SR_PA_EXT_EN		0x04, 0x80, 7
#define	RG_PHY_TX_PWR	(0x05)
#define	SR_TX_PWR		0x05, 0x0f, 0
#define	SR_PA_LT		0x05, 0x30, 4
#define	SR_PA_BUF_LT		0x05, 0xc0, 6
#define	RG_PHY_RSSI	(0x06)
#define	SR_RSSI			0x06, 0x1f, 0
#define	SR_RND_VALUE		0x06, 0x60, 5
#define	SR_RX_CRC_VALID		0x06, 0x80, 7
#define	RG_PHY_ED_LEVEL	(0x07)
#define	SR_ED_LEVEL		0x07, 0xff, 0
#define	RG_PHY_CC_CCA	(0x08)
#define	SR_CHANNEL		0x08, 0x1f, 0
#define	SR_CCA_MODE		0x08, 0x60, 5
#define	SR_CCA_REQUEST		0x08, 0x80, 7
#define	RG_CCA_THRES	(0x09)
#define	SR_CCA_ED_THRES		0x09, 0x0f, 0
#define	SR_RESERVED_09_1	0x09, 0xf0, 4
#define	RG_RX_CTRL	(0x0a)
#define	SR_PDT_THRES		0x0a, 0x0f, 0
#define	SR_RESERVED_0a_1	0x0a, 0xf0, 4
#define	RG_SFD_VALUE	(0x0b)
#define	SR_SFD_VALUE		0x0b, 0xff, 0
#define	RG_TRX_CTRL_2	(0x0c)
#define	SR_OQPSK_DATA_RATE	0x0c, 0x03, 0
#define	SR_RESERVED_0c_2	0x0c, 0x7c, 2
#define	SR_RX_SAFE_MODE		0x0c, 0x80, 7
#define	RG_ANT_DIV	(0x0d)
#define	SR_ANT_CTRL		0x0d, 0x03, 0
#define	SR_ANT_EXT_SW_EN	0x0d, 0x04, 2
#define	SR_ANT_DIV_EN		0x0d, 0x08, 3
#define	SR_RESERVED_0d_2	0x0d, 0x70, 4
#define	SR_ANT_SEL		0x0d, 0x80, 7
#define	RG_IRQ_MASK	(0x0e)
#define	SR_IRQ_MASK		0x0e, 0xff, 0
#define	RG_IRQ_STATUS	(0x0f)
#define	SR_IRQ_0_PLL_LOCK	0x0f, 0x01, 0
#define	SR_IRQ_1_PLL_UNLOCK	0x0f, 0x02, 1
#define	SR_IRQ_2_RX_START	0x0f, 0x04, 2
#define	SR_IRQ_3_TRX_END	0x0f, 0x08, 3
#define	SR_IRQ_4_CCA_ED_DONE	0x0f, 0x10, 4
#define	SR_IRQ_5_AMI		0x0f, 0x20, 5
#define	SR_IRQ_6_TRX_UR		0x0f, 0x40, 6
#define	SR_IRQ_7_BAT_LOW	0x0f, 0x80, 7
#define	RG_VREG_CTRL	(0x10)
#define	SR_RESERVED_10_6	0x10, 0x03, 0
#define	SR_DVDD_OK		0x10, 0x04, 2
#define	SR_DVREG_EXT		0x10, 0x08, 3
#define	SR_RESERVED_10_3	0x10, 0x30, 4
#define	SR_AVDD_OK		0x10, 0x40, 6
#define	SR_AVREG_EXT		0x10, 0x80, 7
#define	RG_BATMON	(0x11)
#define	SR_BATMON_VTH		0x11, 0x0f, 0
#define	SR_BATMON_HR		0x11, 0x10, 4
#define	SR_BATMON_OK		0x11, 0x20, 5
#define	SR_RESERVED_11_1	0x11, 0xc0, 6
#define	RG_XOSC_CTRL	(0x12)
#define	SR_XTAL_TRIM		0x12, 0x0f, 0
#define	SR_XTAL_MODE		0x12, 0xf0, 4
#define	RG_RX_SYN	(0x15)
#define	SR_RX_PDT_LEVEL		0x15, 0x0f, 0
#define	SR_RESERVED_15_2	0x15, 0x70, 4
#define	SR_RX_PDT_DIS		0x15, 0x80, 7
#define	RG_XAH_CTRL_1	(0x17)
#define	SR_RESERVED_17_8	0x17, 0x01, 0
#define	SR_AACK_PROM_MODE	0x17, 0x02, 1
#define	SR_AACK_ACK_TIME	0x17, 0x04, 2
#define	SR_RESERVED_17_5	0x17, 0x08, 3
#define	SR_AACK_UPLD_RES_FT	0x17, 0x10, 4
#define	SR_AACK_FLTR_RES_FT	0x17, 0x20, 5
#define	SR_RESERVED_17_2	0x17, 0x40, 6
#define	SR_RESERVED_17_1	0x17, 0x80, 7
#define	RG_FTN_CTRL	(0x18)
#define	SR_RESERVED_18_2	0x18, 0x7f, 0
#define	SR_FTN_START		0x18, 0x80, 7
#define	RG_PLL_CF	(0x1a)
#define	SR_RESERVED_1a_2	0x1a, 0x7f, 0
#define	SR_PLL_CF_START		0x1a, 0x80, 7
#define	RG_PLL_DCU	(0x1b)
#define	SR_RESERVED_1b_3	0x1b, 0x3f, 0
#define	SR_RESERVED_1b_2	0x1b, 0x40, 6
#define	SR_PLL_DCU_START	0x1b, 0x80, 7
#define	RG_PART_NUM	(0x1c)
#define	SR_PART_NUM		0x1c, 0xff, 0
#define	RG_VERSION_NUM	(0x1d)
#define	SR_VERSION_NUM		0x1d, 0xff, 0
#define	RG_MAN_ID_0	(0x1e)
#define	SR_MAN_ID_0		0x1e, 0xff, 0
#define	RG_MAN_ID_1	(0x1f)
#define	SR_MAN_ID_1		0x1f, 0xff, 0
#define	RG_SHORT_ADDR_0	(0x20)
#define	SR_SHORT_ADDR_0		0x20, 0xff, 0
#define	RG_SHORT_ADDR_1	(0x21)
#define	SR_SHORT_ADDR_1		0x21, 0xff, 0
#define	RG_PAN_ID_0	(0x22)
#define	SR_PAN_ID_0		0x22, 0xff, 0
#define	RG_PAN_ID_1	(0x23)
#define	SR_PAN_ID_1		0x23, 0xff, 0
#define	RG_IEEE_ADDR_0	(0x24)
#define	SR_IEEE_ADDR_0		0x24, 0xff, 0
#define	RG_IEEE_ADDR_1	(0x25)
#define	SR_IEEE_ADDR_1		0x25, 0xff, 0
#define	RG_IEEE_ADDR_2	(0x26)
#define	SR_IEEE_ADDR_2		0x26, 0xff, 0
#define	RG_IEEE_ADDR_3	(0x27)
#define	SR_IEEE_ADDR_3		0x27, 0xff, 0
#define	RG_IEEE_ADDR_4	(0x28)
#define	SR_IEEE_ADDR_4		0x28, 0xff, 0
#define	RG_IEEE_ADDR_5	(0x29)
#define	SR_IEEE_ADDR_5		0x29, 0xff, 0
#define	RG_IEEE_ADDR_6	(0x2a)
#define	SR_IEEE_ADDR_6		0x2a, 0xff, 0
#define	RG_IEEE_ADDR_7	(0x2b)
#define	SR_IEEE_ADDR_7		0x2b, 0xff, 0
#define	RG_XAH_CTRL_0	(0x2c)
#define	SR_SLOTTED_OPERATION	0x2c, 0x01, 0
#define	SR_MAX_CSMA_RETRIES	0x2c, 0x0e, 1
#define	SR_MAX_FRAME_RETRIES	0x2c, 0xf0, 4
#define	RG_CSMA_SEED_0	(0x2d)
#define	SR_CSMA_SEED_0		0x2d, 0xff, 0
#define	RG_CSMA_SEED_1	(0x2e)
#define	SR_CSMA_SEED_1		0x2e, 0x07, 0
#define	SR_AACK_I_AM_COORD	0x2e, 0x08, 3
#define	SR_AACK_DIS_ACK		0x2e, 0x10, 4
#define	SR_AACK_SET_PD		0x2e, 0x20, 5
#define	SR_AACK_FVN_MODE	0x2e, 0xc0, 6
#define	RG_CSMA_BE	(0x2f)
#define	SR_MIN_BE		0x2f, 0x0f, 0
#define	SR_MAX_BE		0x2f, 0xf0, 4

#define CMD_REG		0x80
#define CMD_REG_MASK	0x3f
#define CMD_WRITE	0x40
#define CMD_FB		0x20

#define IRQ_BAT_LOW	(1 << 7)
#define IRQ_TRX_UR	(1 << 6)
#define IRQ_AMI		(1 << 5)
#define IRQ_CCA_ED	(1 << 4)
#define IRQ_TRX_END	(1 << 3)
#define IRQ_RX_START	(1 << 2)
#define IRQ_PLL_UNL	(1 << 1)
#define IRQ_PLL_LOCK	(1 << 0)

#define STATE_P_ON		0x00	/* BUSY */
#define STATE_BUSY_RX		0x01
#define STATE_BUSY_TX		0x02
#define STATE_FORCE_TRX_OFF	0x03
#define STATE_FORCE_TX_ON	0x04	/* IDLE */
/* 0x05 */				/* INVALID_PARAMETER */
#define STATE_RX_ON		0x06
/* 0x07 */				/* SUCCESS */
#define STATE_TRX_OFF		0x08
#define STATE_TX_ON		0x09
/* 0x0a - 0x0e */			/* 0x0a - UNSUPPORTED_ATTRIBUTE */
#define STATE_SLEEP		0x0F
#define STATE_BUSY_RX_AACK	0x11
#define STATE_BUSY_TX_ARET	0x12
#define STATE_BUSY_RX_AACK_ON	0x16
#define STATE_BUSY_TX_ARET_ON	0x19
#define STATE_RX_ON_NOCLK	0x1C
#define STATE_RX_AACK_ON_NOCLK	0x1D
#define STATE_BUSY_RX_AACK_NOCLK 0x1E
#define STATE_TRANSITION_IN_PROGRESS 0x1F

static int
__at86rf230_write(struct at86rf230_local *lp, u8 addr, u8 data)
{
	u8 *buf = lp->buf;
	int status;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len		= 2,
		.tx_buf		= buf,
	};

	buf[0] = (addr & CMD_REG_MASK) | CMD_REG | CMD_WRITE;
	buf[1] = data;
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", buf[1]);
	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);

	status = spi_sync(lp->spi, &msg);
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	if (msg.status)
		status = msg.status;
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", buf[1]);

	return status;
}

static int
__at86rf230_read_subreg(struct at86rf230_local *lp,
		u8 addr, u8 mask, int shift, u8 *data)
{
	u8 *buf = lp->buf;
	int status;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len		= 2,
		.tx_buf		= buf,
		.rx_buf		= buf,
	};

	buf[0] = (addr & CMD_REG_MASK) | CMD_REG;
	buf[1] = 0xff;
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);

	status = spi_sync(lp->spi, &msg);
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	if (msg.status)
		status = msg.status;
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", buf[1]);

	if (status == 0)
		*data = buf[1];

	return status;
}

static int
at86rf230_read_subreg(struct at86rf230_local *lp,
		u8 addr, u8 mask, int shift, u8 *data)
{
	int status;

	mutex_lock(&lp->bmux);
	status = __at86rf230_read_subreg(lp, addr, mask, shift, data);
	mutex_unlock(&lp->bmux);

	return status;
}

static int
at86rf230_write_subreg(struct at86rf230_local *lp,
		u8 addr, u8 mask, int shift, u8 data)
{
	int status;
	u8 val;

	mutex_lock(&lp->bmux);
	status = __at86rf230_read_subreg(lp, addr, 0xff, 0, &val);
	if (status)
		goto out;

	val &= ~mask;
	val |= (data << shift) & mask;

	status = __at86rf230_write(lp, addr, val);
out:
	mutex_unlock(&lp->bmux);

	return status;
}

static int
at86rf230_write_fbuf(struct at86rf230_local *lp, u8 *data, u8 len)
{
	u8 *buf = lp->buf;
	int status;
	struct spi_message msg;
	struct spi_transfer xfer_head = {
		.len		= 2,
		.tx_buf		= buf,

	};
	struct spi_transfer xfer_buf = {
		.len		= len,
		.tx_buf		= data,
	};

	mutex_lock(&lp->bmux);
	buf[0] = CMD_WRITE | CMD_FB;
	buf[1] = len;

	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", buf[1]);

	spi_message_init(&msg);
	spi_message_add_tail(&xfer_head, &msg);
	spi_message_add_tail(&xfer_buf, &msg);

	status = spi_sync(lp->spi, &msg);
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	if (msg.status)
		status = msg.status;
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", buf[1]);

	mutex_unlock(&lp->bmux);
	return status;
}

static int
at86rf230_read_fbuf(struct at86rf230_local *lp, u8 *data, u8 *len, u8 *lqi)
{
	u8 *buf = lp->buf;
	int status;
	struct spi_message msg;
	struct spi_transfer xfer_head = {
		.len		= 2,
		.tx_buf		= buf,
		.rx_buf		= buf,

	};
	struct spi_transfer xfer_buf = {
		.len		= *len,
		.rx_buf		= data,
	};

	mutex_lock(&lp->bmux);
	buf[0] = CMD_FB;
	buf[1] = 0x00;

	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", buf[1]);

	spi_message_init(&msg);
	spi_message_add_tail(&xfer_head, &msg);
	spi_message_add_tail(&xfer_buf, &msg);

	status = spi_sync(lp->spi, &msg);
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	if (msg.status)
		status = msg.status;
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", buf[1]);

	if (!status) {
		if (lqi && *len > lp->buf[1])
			*lqi = data[lp->buf[1]];

		*len = lp->buf[1];
	}

	mutex_unlock(&lp->bmux);

	return status;
}

static phy_status_t
at86rf230_ed(struct ieee802154_dev *dev, u8 *level)
{
	pr_debug("%s\n", __func__);
	might_sleep();
	BUG_ON(!level);
	*level = 0xbe;
	return PHY_SUCCESS;
}

static phy_status_t
at86rf230_cca(struct ieee802154_dev *dev)
{
	pr_debug("%s\n", __func__);
	might_sleep();
	return PHY_IDLE;
}

static phy_status_t
at86rf230_state(struct ieee802154_dev *dev, phy_status_t state)
{
	struct at86rf230_local *lp = dev->priv;
	int rc;
	u8 val;

	pr_debug("%s %d\n", __func__/*, priv->cur_state*/, state);
	might_sleep();

	if (state != PHY_TRX_OFF &&
	    state != PHY_RX_ON &&
	    state != PHY_TX_ON &&
	    state != PHY_FORCE_TRX_OFF)
		return PHY_INVAL;

	do {
		rc = at86rf230_read_subreg(lp, SR_TRX_STATUS, &val);
		if (rc)
			goto err;
		pr_debug("%s val1 = %x\n", __func__, val);
	} while (val == STATE_TRANSITION_IN_PROGRESS);

	if (val == state)
		goto out;

	/* FIXME: handle all non-standard states here!!! */

	/* state is equal to phy states */
	rc = at86rf230_write_subreg(lp, SR_TRX_CMD, state);
	if (rc)
		goto err;

	do {
		rc = at86rf230_read_subreg(lp, SR_TRX_STATUS, &val);
		if (rc)
			goto err;
		pr_debug("%s val2 = %x\n", __func__, val);
	} while (val == STATE_TRANSITION_IN_PROGRESS);

	if (val == state)
		val = PHY_SUCCESS;

out:
	return val;

err:
	pr_err("%s error: %d\n", __func__, rc);
	return PHY_ERROR;
}

static phy_status_t
at86rf230_channel(struct ieee802154_dev *dev, int channel)
{
	struct at86rf230_local *lp = dev->priv;
	int rc;

	pr_debug("%s %d\n", __func__, channel);
	might_sleep();

	BUG_ON(channel < 11);
	BUG_ON(channel > 26);

	rc = at86rf230_write_subreg(lp, SR_CHANNEL, channel);
	msleep(1); /* Wait for PLL */
	dev->current_channel = channel;

	return PHY_SUCCESS;
}

static int
at86rf230_tx(struct ieee802154_dev *dev, struct sk_buff *skb)
{
	char *data;
	struct at86rf230_local *lp = dev->priv;
	int rc;
	unsigned long flags;

	pr_debug("%s\n", __func__);

	might_sleep();

#ifdef AT86RF230_OLDFW_HACK
	data = skb_push(skb, 2);
	data[0] = 0x7e;
	data[1] = 0xff;
#else
	data = skb_push(skb, 0); /* FIXME: find a better way */
#endif

	spin_lock_irqsave(&lp->lock, flags);
	BUG_ON(lp->is_tx);
	lp->is_tx = 1;
	INIT_COMPLETION(lp->tx_complete);
	spin_unlock_irqrestore(&lp->lock, flags);

	rc = at86rf230_write_fbuf(lp, data, skb->len);
	if (rc)
		goto err;

	if (gpio_is_valid(lp->slp_tr)) {
		gpio_set_value(lp->slp_tr, 1);
	} else {
		rc = at86rf230_write_subreg(lp, SR_TRX_CMD, STATE_BUSY_TX);
		if (rc)
			goto err;
	}

	rc = wait_for_completion_interruptible(&lp->tx_complete);

	gpio_set_value(lp->slp_tr, 0);

	if (rc < 0)
		goto err;

	return PHY_SUCCESS;
err:
	spin_lock_irqsave(&lp->lock, flags);
	lp->is_tx = 0;
	spin_unlock_irqrestore(&lp->lock, flags);

	return PHY_ERROR;
}

static int at86rf230_rx(struct at86rf230_local *lp)
{
	u8 len = 128;
	u8 lqi = 0;
	int rc;
	struct sk_buff *skb;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	rc = at86rf230_read_fbuf(lp, skb_put(skb, len), &len, &lqi);
	if (len < 2) {
		kfree_skb(skb);
		return -EINVAL;
	}

	skb_trim(skb, len-2); /* We do not put CRC into the frame */

	if (len < 2) {
		kfree_skb(skb);
		return -EINVAL;
	}

#ifdef AT86RF230_OLDFW_HACK
	skb_pull(skb, 2);
#endif
	ieee802154_rx_irqsafe(lp->dev, skb, lqi);

	dev_dbg(&lp->spi->dev, "READ_FBUF: %d %d %x\n", rc, len, lqi);

	return 0;
}

static struct ieee802154_ops at86rf230_ops = {
	.owner = THIS_MODULE,
	.tx = at86rf230_tx,
	.ed = at86rf230_ed,
	.cca = at86rf230_cca,
	.set_trx_state = at86rf230_state,
	.set_channel = at86rf230_channel,
};

static int at86rf230_register(struct at86rf230_local *lp)
{
	int rc = -ENOMEM;

	lp->dev = ieee802154_alloc_device();
	if (!lp->dev)
		goto err_alloc;

	lp->dev->name = dev_name(&lp->spi->dev);
	lp->dev->priv = lp;
	lp->dev->parent = &lp->spi->dev;
#ifdef AT86RF230_OLDFW_HACK
	lp->dev->extra_tx_headroom = 2;
#else
	lp->dev->extra_tx_headroom = 0;
#endif
	lp->dev->channel_mask = 0x7ff; /* We do support only 2.4 Ghz */
	lp->dev->flags = IEEE802154_FLAGS_OMIT_CKSUM;

	rc = ieee802154_register_device(lp->dev, &at86rf230_ops);
	if (rc)
		goto err_register;

	return 0;

err_register:
	ieee802154_free_device(lp->dev);
err_alloc:
	return rc;
}

static void at86rf230_unregister(struct at86rf230_local *lp)
{
	ieee802154_unregister_device(lp->dev);
	ieee802154_free_device(lp->dev);
}

static void at86rf230_irqwork(struct work_struct *work)
{
	struct at86rf230_local *lp =
		container_of(work, struct at86rf230_local, irqwork);
	u8 status = 0, val;
	int rc;
	unsigned long flags;

	dev_dbg(&lp->spi->dev, "IRQ Worker\n");

	do {
		rc = at86rf230_read_subreg(lp, RG_IRQ_STATUS, 0xff, 0, &val);
		status |= val;
		dev_dbg(&lp->spi->dev, "IRQ Status: %02x\n", status);

		status &= ~IRQ_PLL_LOCK; /* ignore */
		status &= ~IRQ_RX_START; /* ignore */
		status &= ~IRQ_AMI; /* ignore */
		status &= ~IRQ_TRX_UR; /* FIXME: possibly handle ???*/

		if (status & IRQ_TRX_END) {
			status &= ~IRQ_TRX_END;
			spin_lock_irqsave(&lp->lock, flags);
			if (lp->is_tx) {
				lp->is_tx = 0;
				spin_unlock_irqrestore(&lp->lock, flags);
				complete(&lp->tx_complete);
			} else {
				spin_unlock_irqrestore(&lp->lock, flags);
				at86rf230_rx(lp);
			}
		}

	} while (status != 0);

	spin_lock_irqsave(&lp->lock, flags);
	if (lp->irq_disabled) {
		lp->irq_disabled = 0;
		enable_irq(lp->spi->irq);
	}
	spin_unlock_irqrestore(&lp->lock, flags);
}

static irqreturn_t at86rf230_isr(int irq, void *data)
{
	struct at86rf230_local *lp = data;

	dev_dbg(&lp->spi->dev, "IRQ!\n");

	spin_lock(&lp->lock);
	if (!lp->irq_disabled) {
		disable_irq_nosync(irq);
		lp->irq_disabled = 1;
	}
	spin_unlock(&lp->lock);

	schedule_work(&lp->irqwork);

	return IRQ_HANDLED;
}


static int at86rf230_hw_init(struct at86rf230_local *lp)
{
	u8 status;
	int rc;

	rc = at86rf230_read_subreg(lp, SR_TRX_STATUS, &status);
	if (rc)
		return rc;

	dev_info(&lp->spi->dev, "Status: %02x\n", status);
	if (status == STATE_P_ON) {
		rc = at86rf230_write_subreg(lp, SR_TRX_CMD, STATE_TRX_OFF);
		if (rc)
			return rc;
		msleep(1);
		rc = at86rf230_read_subreg(lp, SR_TRX_STATUS, &status);
		if (rc)
			return rc;
		dev_info(&lp->spi->dev, "Status: %02x\n", status);
	}

	rc = at86rf230_write_subreg(lp, SR_IRQ_MASK,
			/*IRQ_TRX_UR | IRQ_CCA_ED | IRQ_TRX_END | IRQ_PLL_UNL | IRQ_PLL_LOCK*/ 0xff);
	if (rc)
		return rc;

	/* CLKM changes are applied immediately */
	rc = at86rf230_write_subreg(lp, SR_CLKM_SHA_SEL, 0x00);
	if (rc)
		return rc;

	/* Turn CLKM Off */
	rc = at86rf230_write_subreg(lp, SR_CLKM_CTRL, 0x00);
	if (rc)
		return rc;

	msleep(100);

	rc = at86rf230_write_subreg(lp, SR_TRX_CMD, STATE_TX_ON);
	if (rc)
		return rc;
	msleep(1);

	rc = at86rf230_read_subreg(lp, SR_TRX_STATUS, &status);
	if (rc)
		return rc;
	dev_info(&lp->spi->dev, "Status: %02x\n", status);

	rc = at86rf230_read_subreg(lp, SR_DVDD_OK, &status);
	if (rc)
		return rc;
	if (!status) {
		dev_err(&lp->spi->dev, "DVDD error\n");
		return -EINVAL;
	}

	rc = at86rf230_read_subreg(lp, SR_AVDD_OK, &status);
	if (rc)
		return rc;
	if (!status) {
		dev_err(&lp->spi->dev, "AVDD error\n");
		return -EINVAL;
	}

	return 0;
}

static int at86rf230_suspend(struct spi_device *spi, pm_message_t message)
{
	return 0;
}

static int at86rf230_resume(struct spi_device *spi)
{
	return 0;
}

static int __devinit at86rf230_probe(struct spi_device *spi)
{
	struct at86rf230_local *lp = kzalloc(sizeof *lp, GFP_KERNEL);
	u8 man_id_0, man_id_1;
	int rc;
	const char *chip;
	int supported = 0;
	struct at86rf230_platform_data *pdata = spi->dev.platform_data;

	if (!lp)
		return -ENOMEM;

	if (!pdata) {
		dev_err(&spi->dev, "no platform_data\n");
		rc = -EINVAL;
		goto err;
	}

	if (!spi->irq) {
		dev_err(&spi->dev, "no IRQ specified\n");
		rc = -EINVAL;
		goto err;
	}

	lp->spi = spi;

	lp->rstn = pdata->rstn;
	lp->slp_tr = pdata->slp_tr;
	lp->dig2 = pdata->dig2;

	mutex_init(&lp->bmux);
	INIT_WORK(&lp->irqwork, at86rf230_irqwork);
	spin_lock_init(&lp->lock);
	init_completion(&lp->tx_complete);

	spi_set_drvdata(spi, lp);

	rc = gpio_request(lp->rstn, "rstn");
	if (rc)
		goto err_rstn;

	if (gpio_is_valid(lp->slp_tr)) {
		rc = gpio_request(lp->slp_tr, "slp_tr");
		if (rc)
			goto err_slp_tr;
	}

	rc = gpio_direction_output(lp->rstn, 1);
	if (rc)
		goto err_gpio_dir;

	if (gpio_is_valid(lp->slp_tr)) {
		rc = gpio_direction_output(lp->slp_tr, 0);
		if (rc)
			goto err_gpio_dir;
	}

	/* Reset */
	msleep(1);
	gpio_set_value(lp->rstn, 0);
	msleep(1);
	gpio_set_value(lp->rstn, 1);
	msleep(1);

	rc = at86rf230_read_subreg(lp, SR_MAN_ID_0, &man_id_0);
	if (rc)
		goto err_gpio_dir;
	rc = at86rf230_read_subreg(lp, SR_MAN_ID_1, &man_id_1);
	if (rc)
		goto err_gpio_dir;

	if (man_id_1 != 0x00 || man_id_0 != 0x1f) {
		dev_err(&spi->dev, "Non-Atmel device found (MAN_ID"
				"%02x %02x)\n", man_id_1, man_id_0);
		rc = -EINVAL;
		goto err_gpio_dir;
	}

	rc = at86rf230_read_subreg(lp, SR_PART_NUM, &lp->part);
	if (rc)
		goto err_gpio_dir;

	rc = at86rf230_read_subreg(lp, SR_VERSION_NUM, &lp->vers);
	if (rc)
		goto err_gpio_dir;

	switch (lp->part) {
	case 2:
		chip = "at86rf230";
		/* supported = 1;  FIXME: should be easy to support; */
		break;
	case 3:
		chip = "at86rf231";
		supported = 1;
		break;
	default:
		chip = "UNKNOWN";
		break;
	}

	dev_info(&spi->dev, "Detected %s chip version %d\n", chip, lp->vers);
	if (!supported) {
		rc = -ENOTSUPP;
		goto err_gpio_dir;
	}

	rc = at86rf230_hw_init(lp);
	if (rc)
		goto err_gpio_dir;

	rc = request_irq(spi->irq, at86rf230_isr, IRQF_SHARED,
			dev_name(&spi->dev), lp);
	if (rc)
		goto err_gpio_dir;

	dev_dbg(&spi->dev, "registered at86rf230\n");

	rc = at86rf230_register(lp);
	if (rc)
		goto err_irq;

	return rc;

	at86rf230_unregister(lp);
err_irq:
	free_irq(spi->irq, lp);
	flush_work(&lp->irqwork);
err_gpio_dir:
	if (gpio_is_valid(lp->slp_tr))
		gpio_free(lp->slp_tr);
err_slp_tr:
	gpio_free(lp->rstn);
err_rstn:
err:
	spi_set_drvdata(spi, NULL);
	mutex_destroy(&lp->bmux);
	kfree(lp);
	return rc;
}

static int __devexit at86rf230_remove(struct spi_device *spi)
{
	struct at86rf230_local *lp = spi_get_drvdata(spi);

	at86rf230_unregister(lp);

	free_irq(spi->irq, lp);
	flush_work(&lp->irqwork);

	if (gpio_is_valid(lp->slp_tr))
		gpio_free(lp->slp_tr);
	gpio_free(lp->rstn);

	spi_set_drvdata(spi, NULL);
	mutex_destroy(&lp->bmux);
	kfree(lp);

	dev_dbg(&spi->dev, "unregistered at86rf230\n");
	return 0;
}

static struct spi_driver at86rf230_driver = {
	.driver = {
		.name	= "at86rf230",
		.owner	= THIS_MODULE,
	},
	.probe      = at86rf230_probe,
	.remove     = __devexit_p(at86rf230_remove),
	.suspend    = at86rf230_suspend,
	.resume     = at86rf230_resume,
};

static int __init at86rf230_init(void)
{
	return spi_register_driver(&at86rf230_driver);
}
module_init(at86rf230_init);

static void __exit at86rf230_exit(void)
{
	spi_unregister_driver(&at86rf230_driver);
}
module_exit(at86rf230_exit);

MODULE_DESCRIPTION("AT86RF230 Transceiver Driver");
MODULE_LICENSE("GPL v2");


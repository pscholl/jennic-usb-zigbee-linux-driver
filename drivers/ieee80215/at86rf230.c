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
#include <linux/spi/spi.h>
#include <linux/spi/at86rf230.h>

struct at86rf230_local {
	struct spi_device *spi;
	int rstn, slp_tr, dig2;

	u8 part;
	u8 vers;

	u8 buf[2];
	struct mutex bmux;
};

#define	RG_TRX_STATUS	(0x01)
#define	RG_TRX_STATE	(0x02)
#define	RG_TRX_CTRL_0	(0x03)
#define	RG_TRX_CTRL_1	(0x04)
#define	RG_PHY_TX_PWR	(0x05)
#define	RG_PHY_RSSI	(0x06)
#define	RG_PHY_ED_LEVEL	(0x07)
#define	RG_PHY_CC_CCA	(0x08)
#define	RG_CCA_THRES	(0x09)
#define	RG_RX_CTRL	(0x0a)
#define	RG_SFD_VALUE	(0x0b)
#define	RG_TRX_CTRL_2	(0x0c)
#define	RG_ANT_DIV	(0x0d)
#define	RG_IRQ_MASK	(0x0e)
#define	RG_IRQ_STATUS	(0x0f)
#define	RG_VREG_CTRL	(0x10)
#define	RG_BATMON	(0x11)
#define	RG_XOSC_CTRL	(0x12)
#define	RG_RX_SYN	(0x15)
#define	RG_XAH_CTRL_1	(0x17)
#define	RG_FTN_CTRL	(0x18)
#define	RG_PLL_CF	(0x1a)
#define	RG_PLL_DCU	(0x1b)
#define	RG_PART_NUM	(0x1c)
#define	RG_VERSION_NUM	(0x1d)
#define	RG_MAN_ID_0	(0x1e)
#define	RG_MAN_ID_1	(0x1f)
#define	RG_SHORT_ADDR_0	(0x20)
#define	RG_SHORT_ADDR_1	(0x21)
#define	RG_PAN_ID_0	(0x22)
#define	RG_PAN_ID_1	(0x23)
#define	RG_IEEE_ADDR_0	(0x24)
#define	RG_IEEE_ADDR_1	(0x25)
#define	RG_IEEE_ADDR_2	(0x26)
#define	RG_IEEE_ADDR_3	(0x27)
#define	RG_IEEE_ADDR_4	(0x28)
#define	RG_IEEE_ADDR_5	(0x29)
#define	RG_IEEE_ADDR_6	(0x2a)
#define	RG_IEEE_ADDR_7	(0x2b)
#define	RG_XAH_CTRL_0	(0x2c)
#define	RG_CSMA_SEED_0	(0x2d)
#define	RG_CSMA_SEED_1	(0x2e)
#define	RG_CSMA_BE	(0x2f)

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

#define STATE_P_ON		0x00
#define STATE_BUSY_RX		0x01
#define STATE_BUSY_TX		0x02
#define STATE_FORCE_TRX_OFF	0x03
#define STATE_FORCE_PLL_ON	0x04
/* 0x05 */
#define STATE_RX_ON		0x06
/* 0x07 */
#define STATE_TRX_OFF		0x08
#define STATE_PLL_ON		0x09
/* 0x0a - 0x0e */
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
at86rf230_write_single(struct at86rf230_local *lp, u8 addr, u8 data)
{
	u8 *buf = lp->buf;
	int status;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len		= 2,
		.tx_buf		= buf,
	};

	mutex_lock(&lp->bmux);
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

	mutex_unlock(&lp->bmux);
	return status;
}

static int
at86rf230_read_single(struct at86rf230_local *lp, u8 addr, u8* data)
{
	u8 *buf = lp->buf;
	int status;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len		= 2,
		.tx_buf		= buf,
		.rx_buf		= buf,
	};

	mutex_lock(&lp->bmux);
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
		.tx_buf		= data,
	};

	mutex_lock(&lp->bmux);
	buf[0] = CMD_FB;
	buf[1] = *len + 1;

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
		if (lqi && *len >= lp->buf[1])
			*lqi = buf[lp->buf[1]];

		*len = lp->buf[1] - 1;
	}

	mutex_unlock(&lp->bmux);

	return status;
}


static irqreturn_t at86rf230_isr(int irq, void *data)
{
	struct at86rf230_local *lp = data;

	dev_dbg(&lp->spi->dev, "IRQ!\n");

	return IRQ_HANDLED;
}


static int at86rf230_hw_init(struct at86rf230_local *lp)
{
	u8 status;
	int rc;

	rc = at86rf230_read_single(lp, RG_TRX_STATUS, &status);
	if (rc)
		return rc;

	dev_info(&lp->spi->dev, "Status: %02x\n", status);
	if (status == STATE_P_ON) {
		rc = at86rf230_write_single(lp, RG_TRX_STATE, STATE_TRX_OFF);
		if (rc)
			return rc;
		msleep(1);
		rc = at86rf230_read_single(lp, RG_TRX_STATUS, &status);
		if (rc)
			return rc;
		dev_info(&lp->spi->dev, "Status: %02x\n", status);
	}

	rc = at86rf230_write_single(lp, RG_IRQ_MASK,
			IRQ_TRX_UR | IRQ_CCA_ED | IRQ_TRX_END | IRQ_PLL_UNL | IRQ_PLL_LOCK);
	if (rc)
		return rc;

	rc = at86rf230_read_single(lp, RG_IRQ_STATUS, &status); /* clear irq */
	dev_dbg(&lp->spi->dev, "IRQ Status: %02x\n", status);

	/* rc = at86rf230_write_single(lp, RG_TRX_CTRL_0, 0x19); */
	rc = at86rf230_write_single(lp, RG_TRX_CTRL_0, 0x00); /* PAD_IO = 2mA, turn CLKM off */
	if (rc)
		return rc;

	msleep(100);

	rc = at86rf230_write_single(lp, RG_TRX_STATE, STATE_PLL_ON);
	if (rc)
		return rc;
	msleep(1);
#if 0
	msleep(10);
	at86rf230_read_single(lp, RG_PLL_CF, &status);
	status |= 0x80;
	at86rf230_write_single(lp, RG_PLL_CF, status);
	msleep(10);
#endif
	rc = at86rf230_read_single(lp, RG_TRX_STATUS, &status);
	if (rc)
		return rc;
	dev_info(&lp->spi->dev, "Status: %02x\n", status);

	rc = at86rf230_read_single(lp, RG_VREG_CTRL, &status);
	if (rc)
		return rc;
	if ((status & 0x44) != 0x44) { /* AVDD_OK, DVDD_OK */
		dev_err(&lp->spi->dev, "Voltage error: %02x\n", status);
		return -EINVAL;
	}

	msleep(10);
	rc = at86rf230_read_single(lp, RG_IRQ_STATUS, &status); /* clear irq */
	dev_dbg(&lp->spi->dev, "IRQ Status: %02x\n", status);
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

	spi_set_drvdata(spi, lp);

	rc = gpio_request(lp->rstn, "rstn");
	if (rc)
		goto err_rstn;
	rc = gpio_request(lp->slp_tr, "slp_tr");
	if (rc)
		goto err_slp_tr;
	rc = gpio_direction_output(lp->rstn, 1);
	if (rc)
		goto err_gpio_dir;
	rc = gpio_direction_output(lp->slp_tr, 0);
	if (rc)
		goto err_gpio_dir;

	/* Reset */
	msleep(1);
	gpio_set_value(lp->rstn, 0);
	msleep(1);
	gpio_set_value(lp->rstn, 1);
	msleep(1);

	rc = at86rf230_read_single(lp, RG_MAN_ID_0, &man_id_0);
	if (rc)
		goto err_gpio_dir;
	rc = at86rf230_read_single(lp, RG_MAN_ID_1, &man_id_1);
	if (rc)
		goto err_gpio_dir;

	if (man_id_1 != 0x00 || man_id_0 != 0x1f) {
		dev_err(&spi->dev, "Non-Atmel device found (MAN_ID %02x %02x)\n", man_id_1, man_id_0);
		rc = -EINVAL;
		goto err_gpio_dir;
	}

	rc = at86rf230_read_single(lp, RG_PART_NUM, &lp->part);
	if (rc)
		goto err_gpio_dir;

	rc = at86rf230_read_single(lp, RG_VERSION_NUM, &lp->vers);
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

	rc = request_irq(spi->irq, at86rf230_isr, IRQF_DISABLED, dev_name(&spi->dev), lp);
	if (rc)
		goto err_gpio_dir;

	dev_dbg(&spi->dev, "registered at86rf230\n");
	return rc;

/*err_irq: */
	free_irq(spi->irq, lp);
err_gpio_dir:
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

	free_irq(spi->irq, lp);

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


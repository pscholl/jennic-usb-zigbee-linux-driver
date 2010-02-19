/*
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
 * Author:	Jonathan Cameron <jic23@cam.ac.uk>
 *
 * Modified 2010:	liuxue <linuxue@yahoo.cn>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/spi/spi.h>
#include <linux/spi/cc2420.h>
#include <linux/skbuff.h>
#include <linux/irq.h>
#include <net/mac802154.h>
#include <net/wpan-phy.h>

#define CC2420_WRITEREG(x) (x)
#define CC2420_READREG(x) (0x40 | x)

#define CC2420_FREQ_MASK 		0x3FF
#define CC2420_ADR_DECODE_MASK	0x0B00
#define CC2420_FIFOP_THR_MASK	0x003F
#define CC2420_CRC_MASK			0x80

#define CC2420_MANFIDLOW 	0x233D
#define CC2420_MANFIDHIGH 	0x3000 /* my chip appears to version 3 - broaden this with testing */

#define STATE_PDOWN 0
#define STATE_IDLE  1
#define STATE_RX_CALIB 2
#define STATE_RX_CALIB2 40

#define STATE_RX_SFD_SEARCH_MIN 3
#define STATE_RX_SFD_SEARCH_MAX 6

struct cc2420_local {
	struct cc2420_platform_data *pdata;
	struct spi_device *spi;
	struct ieee802154_dev *dev;
	u8 *buf;
	struct mutex bmux;
	int fifop_irq;
	int sfd_irq;
	struct work_struct fifop_irqwork;
	struct work_struct sfd_irqwork;
	spinlock_t lock;
	unsigned irq_disabled:1;/* P:lock */
	unsigned is_tx:1;		/* P:lock */

	struct completion tx_complete;
};
static int cc2420_get_status(struct cc2420_local *lp, u8 *status)
{
	int ret;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len = 1,
		.tx_buf = lp->buf,
		.rx_buf = lp->buf,
	};
	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);
	mutex_lock(&lp->bmux);
	lp->buf[0] = CC2420_WRITEREG(CC2420_SNOP);
	dev_vdbg(&lp->spi->dev, "get status command buf[0] = %02x\n", lp->buf[0]);
	ret = spi_sync(lp->spi, &msg);
	if (!ret)
		*status = lp->buf[0];
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", lp->buf[0]);
	mutex_unlock(&lp->bmux);
	return ret;

}
static int cc2420_cmd_strobe(struct cc2420_local *lp,
				 u8 addr)
{
	int ret;
	u8 status = 0xf;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len = 1,
		.tx_buf = lp->buf,
		.rx_buf = lp->buf,
	};
	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);
	mutex_lock(&lp->bmux);
	lp->buf[0] = CC2420_WRITEREG(addr);
	dev_vdbg(&lp->spi->dev, "cmd strobe buf[0] = %02x\n", lp->buf[0]);
	ret = spi_sync(lp->spi, &msg);
	if (!ret)
		status = lp->buf[0];
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", lp->buf[0]);

	mutex_unlock(&lp->bmux);

	return ret;
}

static int cc2420_read_16_bit_reg(struct cc2420_local *lp,
				  u8 addr, u16 *data)
{
	int ret;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len = 3,
		.tx_buf = lp->buf,
		.rx_buf = lp->buf,
	};

	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);
	mutex_lock(&lp->bmux);
	lp->buf[0] = CC2420_READREG(addr);
	dev_vdbg(&lp->spi->dev, "readreg addr buf[0] = %02x\n", lp->buf[0]);
	ret = spi_sync(lp->spi, &msg);
	dev_dbg(&lp->spi->dev, "status = %d\n", ret);
	mutex_unlock(&lp->bmux);
	dev_dbg(&lp->spi->dev, "buf[0] = %02x\n", lp->buf[0]);
	dev_dbg(&lp->spi->dev, "buf[1] = %02x\n", lp->buf[1]);
	dev_dbg(&lp->spi->dev, "buf[2] = %02x\n", lp->buf[2]);
	if (!ret)
		*data = ((u16) (lp->buf[1]) << 8) | lp->buf[2];
	return ret;
}

static int cc2420_write_16_bit_reg_partial(struct cc2420_local *lp,
					   u8 addr, u16 data, u16 mask)
{
	int ret;
	struct spi_message msg;
	struct spi_transfer xfer = {
		.len = 3,
		.tx_buf = lp->buf,
		.rx_buf = lp->buf,
	};
	dev_dbg(&lp->spi->dev, "data = %x\n", data);
	dev_dbg(&lp->spi->dev, "mask = %x\n", mask);
	spi_message_init(&msg);
	spi_message_add_tail(&xfer, &msg);
	mutex_lock(&lp->bmux);
	lp->buf[0] = CC2420_READREG(addr);
	dev_vdbg(&lp->spi->dev, "read addr buf[0] = %02x\n", lp->buf[0]);
	ret = spi_sync(lp->spi, &msg);
	if (ret)
		goto err_ret;
	dev_dbg(&lp->spi->dev, "read buf[0] = %02x\n", lp->buf[0]);
	dev_dbg(&lp->spi->dev, "buf[1] = %02x\n", lp->buf[1]);
	dev_dbg(&lp->spi->dev, "buf[2] = %02x\n", lp->buf[2]);

	lp->buf[0] = CC2420_WRITEREG(addr);

	//dev_vdbg(&lp->spi->dev, "test: ~(mask >> 8) | (data >> 8) = %x\n", ~(mask >> 8) | (data >> 8));
	//dev_vdbg(&lp->spi->dev, "test: ~(mask & 0xFF) | (data & 0xFF) = %x\n", ~(mask & 0xFF) | (data & 0xFF));
	//lp->buf[1] &= ~(mask >> 8) | (data >> 8);
	//lp->buf[2] &= ~(mask & 0xFF) | (data & 0xFF);
	lp->buf[1] &= ~(mask >> 8);
	lp->buf[2] &= ~(mask & 0xFF);
	lp->buf[1] |= (mask >> 8) & (data >> 8);
	lp->buf[2] |= (mask & 0xFF) & (data & 0xFF);
	dev_vdbg(&lp->spi->dev, "writereg addr buf[0] = %02x\n", lp->buf[0]);
	dev_dbg(&lp->spi->dev, "buf[1] = %02x\n", lp->buf[1]);
	dev_dbg(&lp->spi->dev, "buf[2] = %02x\n", lp->buf[2]);
	ret = spi_sync(lp->spi, &msg);
	if (ret)
		goto err_ret;
	dev_dbg(&lp->spi->dev, "return status buf[0] = %02x\n", lp->buf[0]);
	dev_dbg(&lp->spi->dev, "buf[1] = %02x\n", lp->buf[1]);
	dev_dbg(&lp->spi->dev, "buf[2] = %02x\n", lp->buf[2]);

err_ret:
	mutex_unlock(&lp->bmux);
	return ret;
}

static int
cc2420_channel(struct ieee802154_dev *dev, int channel)
{
	struct cc2420_local *lp = dev->priv;
	int ret;

	might_sleep();
	dev_dbg(&lp->spi->dev, "trying to set channel\n");

	BUG_ON(channel < CC2420_MIN_CHANNEL);
	BUG_ON(channel > CC2420_MAX_CHANNEL);

	ret = cc2420_write_16_bit_reg_partial(lp, CC2420_FSCTRL, 357 + 5*(channel - 11), CC2420_FREQ_MASK);

	dev->phy->current_channel = channel;
	return ret;
}

static int
cc2420_write_txfifo(struct cc2420_local *lp, u8 *data, u8 len)
{
	int status;
	struct spi_message msg;
	struct spi_transfer xfer_head = {
		.len		= 1,
		.tx_buf		= lp->buf,
		.rx_buf		= lp->buf,
	};
	struct spi_transfer xfer_buf = {
		.len		= len,
		.tx_buf		= data,
	};

	mutex_lock(&lp->bmux);
	lp->buf[0] = CC2420_WRITEREG(CC2420_TXFIFO);
	dev_vdbg(&lp->spi->dev, "TX_FIFO addr buf[0] = %02x\n", lp->buf[0]);

	spi_message_init(&msg);
	spi_message_add_tail(&xfer_head, &msg);
	spi_message_add_tail(&xfer_buf, &msg);

	status = spi_sync(lp->spi, &msg);
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	if (msg.status)
		status = msg.status;
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	dev_vdbg(&lp->spi->dev, "buf[0] = %02x\n", lp->buf[0]);

	mutex_unlock(&lp->bmux);
	return status;
}

static int
cc2420_read_rxfifo(struct cc2420_local *lp, u8 *data, u8 *len, u8 *lqi)
{
	int status;
	struct spi_message msg;
	struct spi_transfer xfer_head = {
		.len		= 2,
		.tx_buf		= lp->buf,
		.rx_buf		= lp->buf,
	};
	struct spi_transfer xfer_buf = {
		.len		= *len,
		.rx_buf		= data,
	};

	mutex_lock(&lp->bmux);
	lp->buf[0] = CC2420_READREG(CC2420_RXFIFO);
	lp->buf[1] = 0x00;
	dev_vdbg(&lp->spi->dev, "read rxfifo buf[0] = %02x\n", lp->buf[0]);
	dev_vdbg(&lp->spi->dev, "buf[1] = %02x\n", lp->buf[1]);
	spi_message_init(&msg);
	spi_message_add_tail(&xfer_head, &msg);
	spi_message_add_tail(&xfer_buf, &msg);

	status = spi_sync(lp->spi, &msg);
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	if (msg.status)
		status = msg.status;
	dev_vdbg(&lp->spi->dev, "status = %d\n", status);
	dev_vdbg(&lp->spi->dev, "return status buf[0] = %02x\n", lp->buf[0]);
	dev_vdbg(&lp->spi->dev, "length buf[1] = %02x\n", lp->buf[1]);

	*lqi = data[lp->buf[1] - 1] & 0x7f;
	*len = lp->buf[1]; /* it should be less than 130 */

	mutex_unlock(&lp->bmux);

	return status;
}


static int
cc2420_tx(struct ieee802154_dev *dev, struct sk_buff *skb)
{
	struct cc2420_local *lp = dev->priv;
	int rc;
	unsigned long flags;
	u8 status = 0;

	pr_debug("%s\n", __func__);

	might_sleep();

	rc = cc2420_cmd_strobe(lp, CC2420_SFLUSHTX);
	if (rc)
		goto err_rx;
	rc = cc2420_write_txfifo(lp, skb->data, skb->len);
	if (rc)
		goto err_rx;

	/* TODO: test CCA pin */

	rc = cc2420_get_status(lp, &status);
	if (rc) {
		goto err_rx;
	}
	if (status & CC2420_STATUS_TX_UNDERFLOW) {
		dev_err(&lp->spi->dev, "cc2420 tx underflow!\n");
		goto err_rx;
	}

	spin_lock_irqsave(&lp->lock, flags);
	BUG_ON(lp->is_tx);
	lp->is_tx = 1;
	INIT_COMPLETION(lp->tx_complete);
	spin_unlock_irqrestore(&lp->lock, flags);

	rc = cc2420_cmd_strobe(lp, CC2420_STXONCCA);
	if (rc)
		goto err;

	rc = wait_for_completion_interruptible(&lp->tx_complete);
	if (rc < 0)
		goto err;

	cc2420_cmd_strobe(lp, CC2420_SFLUSHTX);
	cc2420_cmd_strobe(lp, CC2420_SRXON);

	return rc;

err:
	spin_lock_irqsave(&lp->lock, flags);
	lp->is_tx = 0;
	spin_unlock_irqrestore(&lp->lock, flags);
err_rx:
	cc2420_cmd_strobe(lp, CC2420_SFLUSHTX);
	cc2420_cmd_strobe(lp, CC2420_SRXON);
	return rc;
}

static int cc2420_rx(struct cc2420_local *lp)
{
	u8 len = 128;
	u8 lqi = 0; /* link quality */
	int rc;
	struct sk_buff *skb;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	rc = cc2420_read_rxfifo(lp, skb_put(skb, len), &len, &lqi);
	if (len < 2) {
		kfree_skb(skb);
		return -EINVAL;
	}

	skb_trim(skb, len-1); /* We do not put CRC and Corr into
							the frame, but remain rssi value */

	ieee802154_rx_irqsafe(lp->dev, skb, lqi);

	dev_dbg(&lp->spi->dev, "RXFIFO: %d %d %x\n", rc, len, lqi);

	return 0;
}

static int
cc2420_ed(struct ieee802154_dev *dev, u8 *level)
{
	struct cc2420_local *lp = dev->priv;
	dev_dbg(&lp->spi->dev, "ed called\n");
	*level = 0xbe;
	return 0;
}

static int
cc2420_start(struct ieee802154_dev *dev)
{
	return cc2420_cmd_strobe(dev->priv, CC2420_SRXON);
}

static void
cc2420_stop(struct ieee802154_dev *dev)
{
	cc2420_cmd_strobe(dev->priv, CC2420_SRFOFF);
}

static struct ieee802154_ops cc2420_ops = {
	.owner 		= THIS_MODULE,
	.xmit 		= cc2420_tx,
	.ed 		= cc2420_ed,
	.start 		= cc2420_start,
	.stop 		= cc2420_stop,
	.set_channel = cc2420_channel,
};

static int cc2420_register(struct cc2420_local *lp)
{
	int ret = -ENOMEM;
	lp->dev = ieee802154_alloc_device(sizeof(*lp), &cc2420_ops);
	if (!lp->dev)
		goto err_ret;

	lp->dev->priv = lp;
	lp->dev->parent = &lp->spi->dev;
	//look this up.
	lp->dev->extra_tx_headroom = 0;
	//and this
	//lp->dev->channel_mask = 0x7ff;
	//and more.

	/* We do support only 2.4 Ghz */
	lp->dev->phy->channels_supported[0] = 0x7FFF800;
	lp->dev->flags = IEEE802154_HW_OMIT_CKSUM;

	dev_dbg(&lp->spi->dev, "registered cc2420\n");
	ret = ieee802154_register_device(lp->dev);
	if (ret)
		goto err_free_device;
	return 0;
err_free_device:
	ieee802154_free_device(lp->dev);
err_ret:
	return ret;
}

static void cc2420_unregister(struct cc2420_local *lp)
{
	ieee802154_unregister_device(lp->dev);
	//check this is needed
	ieee802154_free_device(lp->dev);
}

static irqreturn_t cc2420_isr(int irq, void *data)
{
	struct cc2420_local *lp = data;

	spin_lock(&lp->lock);
	if (!lp->irq_disabled) {
		disable_irq_nosync(irq);
		lp->irq_disabled = 1;
	}
	spin_unlock(&lp->lock);

	/* pin or value? */
	if (irq == lp->sfd_irq) {
		schedule_work(&lp->sfd_irqwork);
	}
	if (irq == lp->fifop_irq) {
		schedule_work(&lp->fifop_irqwork);
	}

	return IRQ_HANDLED;
}

static void cc2420_fifop_irqwork(struct work_struct *work)
{
	struct cc2420_local *lp
		= container_of(work, struct cc2420_local, fifop_irqwork);
	unsigned long flags;

	dev_dbg(&lp->spi->dev, "fifop interrupt received\n");

	if (gpio_get_value(lp->pdata->fifo)) {
		cc2420_rx(lp);
	}
	else {
		dev_vdbg(&lp->spi->dev, "rxfifo overflow\n");
	}

	cc2420_cmd_strobe(lp, CC2420_SFLUSHRX);
	cc2420_cmd_strobe(lp, CC2420_SFLUSHRX);

	spin_lock_irqsave(&lp->lock, flags);
	if (lp->irq_disabled) {
		lp->irq_disabled = 0;
		enable_irq(lp->fifop_irq);
	}
	spin_unlock_irqrestore(&lp->lock, flags);
}

static void cc2420_sfd_irqwork(struct work_struct *work)
{
	struct cc2420_local *lp
		= container_of(work, struct cc2420_local, sfd_irqwork);
	unsigned long flags;

	dev_dbg(&lp->spi->dev, "fifop interrupt received\n");

	spin_lock_irqsave(&lp->lock, flags);
	if (lp->is_tx) {
		lp->is_tx = 0;
		spin_unlock_irqrestore(&lp->lock, flags);
		complete(&lp->tx_complete);
	} else {
		spin_unlock_irqrestore(&lp->lock, flags);
	}

	spin_lock_irqsave(&lp->lock, flags);
	if (lp->irq_disabled) {
		lp->irq_disabled = 0;
		enable_irq(lp->sfd_irq);
	}
	spin_unlock_irqrestore(&lp->lock, flags);
}

static int cc2420_hw_init(struct cc2420_local *lp)
{
	int ret;
	u16 state;
	u8 status = 0xff;
	int timeout = 500; /* 500us delay */
	ret = cc2420_read_16_bit_reg(lp, CC2420_FSMSTATE, &state);
	if (ret)
		goto error_ret;
	/* reset has occured prior to this, so there should be no other option */
	if (state != STATE_PDOWN) {
		ret = -EINVAL;
		goto error_ret;
	}
	ret = cc2420_cmd_strobe(lp, CC2420_SXOSCON);
	if (ret)
		goto error_ret;

	do {
		ret = cc2420_get_status(lp, &status);
		if (ret)
			goto error_ret;
		if (timeout-- <= 0) {
			dev_err(&lp->spi->dev, "oscillator start failed!\n");
			return ret;
		}
		udelay(1);
	} while (!(status & CC2420_STATUS_XOSC16M_STABLE));

	dev_info(&lp->spi->dev, "oscillator succesfully brought up \n");

	return 0;
error_ret:
	return ret;
}

static int __devinit cc2420_probe(struct spi_device *spi)
{
	int ret;
	u16 manidl, manidh;
	struct cc2420_local *lp = kzalloc(sizeof *lp, GFP_KERNEL);
	if (!lp) {
		ret = -ENOMEM;
		goto error_ret;
	}

	lp->pdata = spi->dev.platform_data;
	if (!lp->pdata) {
		dev_err(&spi->dev, "no platform data\n");
		ret = -EINVAL;
		goto err_free_local;
	}
	spi_set_drvdata(spi, lp);
	mutex_init(&lp->bmux);
	INIT_WORK(&lp->fifop_irqwork, cc2420_fifop_irqwork);
	INIT_WORK(&lp->sfd_irqwork, cc2420_sfd_irqwork);
	spin_lock_init(&lp->lock);
	init_completion(&lp->tx_complete);

	lp->spi = spi;
	lp->buf = kmalloc(3*sizeof *lp->buf, GFP_KERNEL);
	if (!lp->buf) {
		ret = -ENOMEM;
		goto err_free_local;
	}

	/* Request all the gpio's */
	ret = gpio_request(lp->pdata->fifo, "fifo");
	if (ret)
		goto err_free_buf;
	ret = gpio_request(lp->pdata->cca, "cca");
	if (ret)
		goto err_free_gpio_fifo;
	/* This is causing problems as fifop is gpio 0 ? */
	ret = gpio_request(lp->pdata->fifop, "fifop");
	if (ret)
		goto err_free_gpio_cca;
	ret = gpio_request(lp->pdata->sfd, "sfd");
	if (ret)
		goto err_free_gpio_fifop;
	ret = gpio_request(lp->pdata->reset, "reset");
	if (ret)
		goto err_free_gpio_sfd;
	ret = gpio_request(lp->pdata->vreg, "vreg");
	if (ret)
		goto err_free_gpio_reset;
	/* Configure the gpios appropriately */

	/* Enable the voltage regulator */
	ret = gpio_direction_output(lp->pdata->vreg, 1);
	if (ret)
		goto err_free_gpio_reset;
	udelay(600); /* Time for regulator to power up */
	/* Toggle the reset */
	ret = gpio_direction_output(lp->pdata->reset, 0);
	if (ret)
		goto err_disable_vreg;
	udelay(10); /* no idea how long this should be? */
	ret = gpio_direction_output(lp->pdata->reset, 1);
	if (ret)
		goto err_disable_vreg;
	udelay(10);

	ret = gpio_direction_input(lp->pdata->cca);
	if (ret)
		goto err_disable_vreg;
	ret = gpio_direction_input(lp->pdata->fifo);
	if (ret)
		goto err_disable_vreg;
	ret = gpio_direction_input(lp->pdata->fifop);
	if (ret)
		goto err_disable_vreg;
	ret = gpio_direction_input(lp->pdata->sfd);
	if (ret)
		goto err_disable_vreg;


	/* Check this is actually a cc2420 */
	ret = cc2420_read_16_bit_reg(lp, CC2420_MANFIDL, &manidl);
	if (ret)
		goto err_free_gpio_vreg;
	ret = cc2420_read_16_bit_reg(lp, CC2420_MANFIDH, &manidh);
	if (ret)
		goto err_free_gpio_vreg;
	if (manidh != CC2420_MANFIDHIGH || manidl != CC2420_MANFIDLOW) {
		dev_err(&spi->dev, "Incorrect manufacturer id %x%x\n", manidh, manidl);
		ret = -ENODEV;
		goto err_free_gpio_vreg;
	}
	/* TODO: make it more readable */
	dev_info(&lp->spi->dev, "Found Chipon CC2420\n");
	dev_info(&lp->spi->dev, "Manufacturer ID:%x Version:%x Partnum:%x\n",
		   manidl & 0x0FFF, manidh >> 12, manidl >> 12);

	ret = cc2420_hw_init(lp);
	if (ret)
		goto err_disable_vreg;

	lp->fifop_irq = gpio_to_irq(lp->pdata->fifop);
	lp->sfd_irq = gpio_to_irq(lp->pdata->sfd);

	ret = request_irq(lp->fifop_irq,
					  cc2420_isr,
					  IRQF_TRIGGER_RISING | IRQF_SHARED,
					  dev_name(&spi->dev),
					  lp);
	if (ret) {
		dev_err(&spi->dev, "could not get fifop irq for some reason? \n");
		goto err_free_fifop_irq;
	}

	ret = request_irq(lp->sfd_irq,
					  cc2420_isr,
					  IRQF_TRIGGER_FALLING,
					  dev_name(&spi->dev),
					  lp);
	if (ret) {
		dev_err(&spi->dev, "could not get sfd irq for some reason? \n");
		goto err_free_sfd_irq;
	}

	dev_dbg(&lp->spi->dev, "Close addr decode\n");
	cc2420_write_16_bit_reg_partial(lp, CC2420_MDMCTRL0, 0, 1 << CC2420_MDMCTRL0_ADRDECODE);
	dev_info(&lp->spi->dev, "Set fifo threshold to 127\n");
	cc2420_write_16_bit_reg_partial(lp, CC2420_IOCFG0, 127, CC2420_FIFOP_THR_MASK);
	ret = cc2420_register(lp);
	if (ret)
		goto err_free_sfd_irq;

	return 0;
err_free_sfd_irq:
	free_irq(gpio_to_irq(lp->pdata->sfd), lp);
err_free_fifop_irq:
	free_irq(gpio_to_irq(lp->pdata->fifop), lp);
err_disable_vreg:
	gpio_set_value(lp->pdata->vreg, 0);
err_free_gpio_vreg:
	gpio_free(lp->pdata->vreg);
err_free_gpio_reset:
	gpio_free(lp->pdata->reset);
err_free_gpio_sfd:
	gpio_free(lp->pdata->sfd);
err_free_gpio_fifop:
	gpio_free(lp->pdata->fifop);
err_free_gpio_cca:
	gpio_free(lp->pdata->cca);
err_free_gpio_fifo:
	gpio_free(lp->pdata->fifo);
err_free_buf:
	kfree(lp->buf);
err_free_local:
	kfree(lp);
error_ret:
	return ret;
}

static int __devexit cc2420_remove(struct spi_device *spi)
{
	struct cc2420_local *lp = spi_get_drvdata(spi);

	cc2420_unregister(lp);
	free_irq(gpio_to_irq(lp->pdata->fifop), lp);
	free_irq(gpio_to_irq(lp->pdata->sfd), lp);
	gpio_free(lp->pdata->vreg);
	gpio_free(lp->pdata->reset);
	gpio_free(lp->pdata->sfd);
	gpio_free(lp->pdata->fifop);
	gpio_free(lp->pdata->cca);
	gpio_free(lp->pdata->fifo);
	kfree(lp->buf);
	kfree(lp);

	return 0;
}

static struct spi_driver cc2420_driver = {
	.driver = {
		.name = "cc2420",
		.owner = THIS_MODULE,
	},
	.probe = cc2420_probe,
	.remove = __devexit_p(cc2420_remove),
};

static int __init cc2420_init(void)
{
	return spi_register_driver(&cc2420_driver);
}
module_init(cc2420_init);

static void __exit cc2420_exit(void)
{
	spi_unregister_driver(&cc2420_driver);
}
module_exit(cc2420_exit);
MODULE_LICENSE("GPL v2");

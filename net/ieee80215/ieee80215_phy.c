/*
 * ieee80215_phy.c
 *
 * Description: IEEE 802.15.4 PHY layer
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

#if 0
#include <linux/hardirq.h>
#include <linux/skbuff.h>
#include <net/ieee80215_lib.h>
#include <net/ieee80215.h>
#endif
#include <linux/netdevice.h>
#include <net/ieee80215/phy.h>
#include <net/ieee80215/mac.h>
#include <net/ieee80215/netdev.h>
#include <net/ieee80215/af_ieee80215.h>

#if 0
static int phy_lock(ieee80215_phy_t *phy)
{
	int in_irq = in_interrupt(), ret;

	dbg_print(phy, PHY_CORE, DBG_ALL, "phy = 0x%p\n", phy);
	if (mutex_is_locked(&phy->lock)) {
		dbg_print(phy, PHY_CORE, DBG_ALL, "lock already aquired, waiting or return: %d\n", in_irq);
	}
	if (in_irq) {
		dbg_print(phy, PHY_CORE, DBG_ALL, "in irq\n");
		ret = mutex_trylock(&phy->lock);
		dbg_print(phy, PHY_CORE, DBG_ALL, "trylock: %d\n", ret);
		return ret;
	}
	dbg_print(phy, PHY_CORE, DBG_ALL, "normal lock\n");
	mutex_lock(&phy->lock);
	dbg_print(phy, PHY_CORE, DBG_ALL, "lock aquired\n");
	return 0;
}

static void phy_unlock(ieee80215_phy_t *phy)
{
	dbg_print(phy, PHY_CORE, DBG_ALL, "phy = 0x%p\n");
	mutex_unlock(&phy->lock);
}
#endif

/**
 * \brief PD-DATA.request to PHY from NHLE
 *
 * Called from MAC. This routine should add this request to the queue
 * and kick PHY layer to handle it.
 */
int ieee80215_pd_data_request(struct ieee80215_phy *phy, struct sk_buff *skb)
{
	dev_queue_xmit(skb);
	return 0;
}

#define DEFINED_CALLBACK(x) { 					\
	if(unlikely(!x)) {					\
		pr_debug("callback " # x " is not defined\n");	\
		return;						\
	}							\
}

/**
 * \brief PD-DATA.request PHY layer handler
 *
 * Called from workqueue to process data_request from NHLE
 *
 * \param data pointer to phy
 * \return errno if fail, 0 if Ok.
 */
void ieee80215_bg_pd_data_request(struct work_struct *work)
{
	ieee80215_phy_t *phy = container_of(work, ieee80215_phy_t, data_request);
	ieee80215_mpdu_t *psdu;
	ieee80215_PPDU_t *ppdu;
	unsigned int psdu_len;
	int ret = IEEE80215_PHY_SUCCESS;

#define dbg_print(format, ...)
	if (!phy->cmd_q) {
		pr_debug("Cannot dequeue packet\n");
		return;
	}

	psdu = skb_to_mpdu(phy->cmd_q);

	dbg_print(phy, PHY_CORE, DBG_INFO, "state: %d\n", phy->state);
	if (phy->state != PHY_TX_ON) {
		if (phy->state & PHY_TRX_OFF) {
			ret = IEEE80215_TRX_OFF;
		} else if (phy->state & PHY_RX_ON) {
			ret = IEEE80215_RX_ON;
		} else
			ret = IEEE80215_BUSY_RX;
		goto exit_dr;
	}

	if (psdu->skb->len+IEEE80215_MAX_PHY_OVERHEAD > IEEE80215_MAX_PHY_PACKET_SIZE) {
		dbg_print(phy, 0, DBG_ERR, "PHY pkt is longer that allowed: %d\n", psdu->skb->len);
		ret = IEEE80215_FRAME_TOO_LONG;
		goto exit_dr;
	}

	phy->state |= PHY_BUSY_TX;

	psdu_len = psdu->skb->len;
	ppdu = (ieee80215_PPDU_t*)skb_push(mpdu_to_skb(psdu), IEEE80215_MAX_PHY_OVERHEAD);
	memset(ppdu->preamble, 0, 4);
	ppdu->sfd = DEF_SFD;
	ppdu->flen = psdu_len;

	phy->dev_op->xmit(phy, (u8*)ppdu, psdu->skb->len);

	skb_pull(mpdu_to_skb(psdu), IEEE80215_MAX_PHY_OVERHEAD);
	phy->cmd_q = NULL;
	phy->state &= ~PHY_BUSY_TX;
	return;
exit_dr:
	DEFINED_CALLBACK(_mac(phy)->pd_data_confirm);
	_mac(phy)->pd_data_confirm(_mac(phy), ret);
	return;
}

/**
 * \brief PLME-CCA.request to PHY from NHLE
 *
 * Called by NHLE, MAC in this particular case in order to perform CCA.
 *
 * \param phy current phy pointer
 * \return 0 if Ok, errno if fail
 */
int ieee80215_plme_cca_request(struct ieee80215_phy *phy)
{
	queue_work(phy->worker, &phy->cca_request);
	return 0;
}

/**
 * \brief PLME-CCA.request PHY layer handler
 *
 * Called from workqueue to process CCA-request from NHLE
 */
void ieee80215_bg_plme_cca_request(struct work_struct *work)
{
	ieee80215_phy_t *phy = container_of(work, ieee80215_phy_t, cca_request);

	dbg_print(phy, PHY_CCA, DBG_ALL, "state: %d\n", phy->state);
	if (phy->state == PHY_TRX_OFF) {
		_mac(phy)->plme_cca_confirm(_mac(phy), IEEE80215_TRX_OFF);
	} else if(phy->state == PHY_TX_ON) {
		_mac(phy)->plme_cca_confirm(_mac(phy), IEEE80215_TX_ON);
	} else {
		phy->dev_op->cca(phy, phy->pib.cca_mode);
	}
}

/**
 * \brief PLME-ED.request to PHY from NHLE
 *
 * Called from NHLE, MAC in this particular case, in order to perform
 * ED.
 *
 * \param phy current phy pointer
 * \return 0 if Ok, errno if fail
 */
int ieee80215_plme_ed_request(struct ieee80215_phy *phy)
{
	queue_work(phy->worker, &phy->ed_request);
	return 0;
}

/**
 * \brief PLME-ED.request PHY layer handler
 *
 * Called from workqueue to process ED-request from NHLE
 */
void ieee80215_bg_plme_ed_request(struct work_struct *work)
{
	ieee80215_phy_t *phy = container_of(work, ieee80215_phy_t, ed_request);

	dbg_print(phy, 0, DBG_INFO, "state: %d\n", phy->state);

	if (phy->state == PHY_TRX_OFF) {
		_mac(phy)->plme_ed_confirm(_mac(phy), IEEE80215_TRX_OFF, 0);
	} else if(phy->state == PHY_TX_ON) {
		_mac(phy)->plme_ed_confirm(_mac(phy), IEEE80215_TX_ON, 0);
	} else {
		phy->dev_op->ed(phy);
	}
}

/**
 * \brief PLME-GET.request to PHY from NHLE
 *
 * Called from MAC in order to get attribute value from PHY's pib
 *
 * \param phy current phy pointer
 * \param pib_attr attribute to get
 * \return 0 if Ok, errno if fail
 */
int ieee80215_plme_get_request(struct ieee80215_phy *phy, int pib_attr)
{
	phy->cmd.cb[0] = pib_attr;
	queue_work(phy->worker, &phy->get_request);
	return 0;
}

/**
 * \brief PLME-GET.request PHY layer handler
 *
 * Called from workqueue to process GET-request from NHLE
 *
 * \param data pointer to current phy
 * \return 0 if Ok, errno if fail
 */
void ieee80215_bg_plme_get_request(struct work_struct *work)
{
	ieee80215_phy_t *phy = container_of(work, ieee80215_phy_t, get_request);
	int pib_attr = phy->cmd.cb[0], ret = IEEE80215_PHY_SUCCESS;

	phy->pib_attr.attr_type = pib_attr;
	switch (pib_attr) {
	case IEEE80215_PHY_CURRENT_CHANNEL:
		phy->pib_attr.attr.curr_channel = phy->pib.curr_channel;
		break;
	case IEEE80215_PHY_CHANNELS_SUPPORTED:
		phy->pib_attr.attr.supp_channels = phy->pib.supp_channels;
		break;
	case IEEE80215_PHY_TRANSMIT_POWER:
		phy->pib_attr.attr.trans_power = phy->pib.trans_power;
		break;
	case IEEE80215_PHY_CCA_MODE:
		phy->pib_attr.attr.cca_mode = phy->pib.cca_mode;
		break;
	default:
		ret = IEEE80215_UNSUPPORTED_ATTRIBUTE;
		break;
	}
	_mac(phy)->plme_get_confirm(_mac(phy), ret, &phy->pib_attr);
}

/**
 * \brief PLME-SET.request to PHY from NHLE
 *
 * Called by MAC to modify PHY's pib
 *
 * \param phy current phy pointer
 * \param a attribute information
 * \return 0 if Ok, errno if fail
 */
int ieee80215_plme_set_request(struct ieee80215_phy *phy, ieee80215_plme_pib_t a)
{
	memcpy(&phy->pib_attr, &a, sizeof(a));
	queue_work(phy->worker, &phy->set_request);
	return 0;
}

/**
 * \brief PLME-SET.request PHY layer handler
 *
 * Called from workqueue to process SET-request from NHLE
 *
 * \param data pointer to current phy
 * \return 0 if Ok, errno if fail
 */
void ieee80215_bg_plme_set_request(struct work_struct *work)
{
	ieee80215_phy_t *phy = container_of(work, ieee80215_phy_t, set_request);
	int ret = IEEE80215_PHY_SUCCESS;

	switch (phy->pib_attr.attr_type) {
	case IEEE80215_PHY_CURRENT_CHANNEL:
		if (phy->pib_attr.attr.curr_channel > IEEE80215_PHY_CURRENT_CHANNEL_MAX) {
			ret = IEEE80215_INVALID_PARAMETER;
		} else {
			phy->pib.curr_channel = phy->pib_attr.attr.curr_channel;
			dbg_print(phy, 0, DBG_INFO, "channel: %d\n", phy->pib.curr_channel);
			phy->dev_op->set_channel(phy, phy->pib.curr_channel);
			return;
		}
		break;
	case IEEE80215_PHY_CHANNELS_SUPPORTED:
		phy->pib.supp_channels = phy->pib_attr.attr.supp_channels;
		break;
	case IEEE80215_PHY_TRANSMIT_POWER:
		if (phy->pib_attr.attr.trans_power > IEEE80215_PHY_TRANSMIT_POWER_MAX) {
			ret = IEEE80215_INVALID_PARAMETER;
		} else {
			phy->pib.trans_power = phy->pib_attr.attr.trans_power;
		}
		break;
	case IEEE80215_PHY_CCA_MODE:
		if (phy->pib_attr.attr.cca_mode < IEEE80215_PHY_CCA_MODE_MIN
			|| phy->pib_attr.attr.cca_mode > IEEE80215_PHY_CCA_MODE_MAX) {
			ret = IEEE80215_INVALID_PARAMETER;
		} else {
			phy->pib.cca_mode = phy->pib_attr.attr.cca_mode;
		}
		break;
	default:
		ret = IEEE80215_UNSUPPORTED_ATTRIBUTE;
		break;
	}
	_mac(phy)->plme_set_confirm(_mac(phy), ret, &phy->pib_attr);
}

/**
 * \brief PLME-SET-TRX-STATE.request to PHY by NHLE
 *
 *  Called by MAC to set PHY's state
 *
 * \param phy current phy pointer
 * \param state state to change for PHY
 * \return 0 if Ok, errno if fail
 */
int ieee80215_plme_set_trx_request(struct ieee80215_phy *phy, int state)
{
	ieee80215_net_cmd(phy, IEEE80215_MSG_SET_STATE,
					state, 0);	
	return 0;
}

/**
 * \brief PLME-SET-TRX-STATE.request PHY layer handler
 *
 * Called from workqueue to process SET-TRX-STATE-request from NHLE
 *
 * \param data pointer to current phy
 * \return 0 if Ok, errno if fail
 */
#if 0
void ieee80215_bg_plme_set_trx_request(struct work_struct *work)
{
	ieee80215_phy_t *phy;
	int state, ret = IEEE80215_PHY_SUCCESS;

	phy = container_of(work, ieee80215_phy_t, set_trx_state_request);
	BUG_ON(!phy);
	BUG_ON(!_mac(phy));
	state = phy->cmd.cb[0];
	dbg_print(phy, 0, DBG_ALL, "requested state = %d\n", state);

#if 0
	if (phy_lock(phy)) {
		dbg_print(phy, 0, DBG_ALL, "Unable to lock phy\n");
		ret = IEEE80215_BUSY;
		goto err_exit;
	}
#endif
	if ((PHY_RX_ON == phy->state && IEEE80215_RX_ON == state)
		|| (PHY_TX_ON == phy->state && IEEE80215_TX_ON == state)
		|| (PHY_TRX_OFF == phy->state && IEEE80215_TRX_OFF == state)) {
		ret = state;
		goto err_exit;
	}
	if ((state == IEEE80215_TRX_OFF || state == IEEE80215_RX_ON)
		&& phy->state & PHY_BUSY_TX) {
		ret = IEEE80215_BUSY_TX;
		goto err_exit;
	}
	if ((state == IEEE80215_TX_ON || state == IEEE80215_TRX_OFF)
		&& phy->state & PHY_BUSY_RX) {
		ret = IEEE80215_BUSY_RX;
		goto err_exit;
	}
	switch (state) {
	case IEEE80215_RX_ON:
		phy->pending_state = PHY_RX_ON;
		break;
	case IEEE80215_TX_ON:
		phy->pending_state = PHY_TX_ON;
		break;
	case IEEE80215_TRX_OFF:
	case IEEE80215_FORCE_TRX_OFF:
		phy->pending_state = PHY_TRX_OFF;
		break;
	default:
		dbg_print(phy, 0, DBG_ERR, "unsupported requested state\n");
		BUG();
	}
	/*
	Can anybody explain what was locked?
	Why it was not in the _set_state_confirm()?
	phy_unlock(phy);
	*/
	phy->dev_op->set_state(phy, state);
	return;
err_exit:
	/*phy_unlock(phy);*/
	_mac(phy)->plme_set_trx_state_confirm(_mac(phy), ret);
	return;
}
#endif

/********************************************************/
/* hardware interface, callbacks */

static void _set_channel_confirm(struct ieee80215_phy *phy, u8 status)
{
	BUG_ON(!phy);
	BUG_ON(!_mac(phy));
	pr_debug("%s:%s status = %u\n", __FILE__,
			__FUNCTION__, status);
	if(!_mac(phy)->plme_set_confirm)
		return;
	_mac(phy)->plme_set_confirm(_mac(phy), status, &phy->pib_attr);
}

static void _ed_confirm(struct ieee80215_phy *phy, u8 status, u8 level)
{
	BUG_ON(!phy);
	BUG_ON(!_mac(phy));
	pr_debug("%s:%s status = %u, level = %u\n",
			__FILE__, __FUNCTION__,
			status, level);
	DEFINED_CALLBACK(_mac(phy)->plme_ed_confirm);
	_mac(phy)->plme_ed_confirm(_mac(phy), status, level);
}

static void _set_state_confirm(struct ieee80215_phy *phy, u8 status)
{
	BUG_ON(!phy);
	BUG_ON(!_mac(phy));
	pr_debug("%s:%s: status = %u\n", __FILE__,
			__FUNCTION__, status);
	DEFINED_CALLBACK(_mac(phy)->plme_set_trx_state_confirm);
	if (IEEE80215_PHY_SUCCESS == status) {
		phy->state = phy->pending_state;
	}
	_mac(phy)->plme_set_trx_state_confirm(_mac(phy), status);
}

static void _xmit_confirm(struct ieee80215_phy *phy, u8 status)
{
	BUG_ON(!phy);
	BUG_ON(!_mac(phy));
	pr_debug("%s:%s: status = %u\n", __FILE__,
			__FUNCTION__, status);
	DEFINED_CALLBACK(_mac(phy)->pd_data_confirm);
	_mac(phy)->pd_data_confirm(_mac(phy), status);
}

static void _cca_confirm(struct ieee80215_phy *phy, u8 status)
{
	BUG_ON(!phy);
	BUG_ON(!_mac(phy));
	pr_debug("%s:%s: status = %u\n", __FILE__,
			__FUNCTION__, status);
	DEFINED_CALLBACK(_mac(phy)->plme_cca_confirm);
	_mac(phy)->plme_cca_confirm(_mac(phy), status);
}

/**
 * \brief Receive data from driver to PHY in block mode
 *
 * Called from the device driver on data receive in block mode, provided to PHY,
 * and PHY indicate NHLE, MAC in our particular case.
 *
 * \param phy current phy pointer
 * \param len len of supplied ppdu
 * \param buf received ppdu itself
 * \param ppduLQ link quality level
 */
void _receive_block(struct ieee80215_phy *phy, unsigned int len, const char *buf, int ppduLQ)
{
	ieee80215_mpdu_t *msdu;
	ieee80215_PPDU_t *ppdu;

	if (!(phy->state & PHY_RX_ON)) {
		pr_debug("RX is not on\n");
		BUG();
	}

	if (len > IEEE80215_MAX_PHY_PACKET_SIZE) {
		pr_debug("PHY pkt is longer that allowed\n");
		return;
	}

	ppdu = (ieee80215_PPDU_t*)buf;
	if (ppdu->sfd != DEF_SFD) {
		pr_debug("received frame have no valid SFD\n");
		return;
	}

	pr_debug("psdu len: %u\n", ppdu->flen);
	msdu = dev_alloc_mpdu(ppdu->flen);
	if (!msdu) {
		pr_debug("Cannot allocate msdu skb\n");
		return;
	}
	/* Copying only PHY payload into ppdu */
	memcpy(skb_put(msdu->skb, ppdu->flen), buf + IEEE80215_MAX_PHY_OVERHEAD, ppdu->flen);
	msdu->lq = ppduLQ;
	msdu->timestamp = jiffies;

	if(!_mac(phy)->pd_data_indicate) {
		pr_debug("no data indication present\n");
		return;
	}
	_mac(phy)->pd_data_indicate(_mac(phy), msdu->skb);
	return;
}

/**
 * \brief receive data from driver to PHY in stream mode
 *
 * Called from the device driver on data receive in stream mode, provided to PHY,
 * and PHY indicate NHLE, MAC in our particular case. Stream mode mean that device
 * generate an receive event on each received data quantum. PHY should decide
 * from PPDU how big this data is. When PHY discover valid SFD, state should
 * change into BUSY_RX.
 *
 * \param phy current phy pointer
 * \param c current received char
 * \param ppduLQ link quality level
 */
void _receive_stream(struct ieee80215_phy *phy, char c, int ppduLQ)
{
#if 0
	int ret = 0;
	unsigned long flag;

	if(phy->state & PHY_TRX_OFF) {
		phy->r_idx = 0;
		ret = -ECOMM;
		goto exit_rs;
	}
	phy->rbuf[phy->r_idx++] = c;
	if(phy->r_idx == 5) {
		ieee80215_PPDU_t *ppdu = (ieee80215_PPDU_t*)phy->rbuf;
		if(ppdu->sfd == DEF_SFD) {
			dbg_print(phy, PHY_RECV, DBG_ALL, "valid SFD received\n");
			phy->state |= PHY_BUSY_RX;
		} else {
			dbg_print(phy, PHY_RECV, DBG_ERR, "SFD not found\n");
			phy->r_idx = 0;
			ret = -EINVAL;
			goto exit_rs;
		}
	}
	if(phy->state & PHY_BUSY_RX) {
		ieee80215_PPDU_t *ppdu = (ieee80215_PPDU_t*)phy->rbuf;
		if(ppdu->flen == phy->r_idx - IEEE80215_MAX_PHY_OVERHEAD) {
			ieee80215_mpdu_t *msdu;
			 msdu = alloc_mpdu(ppdu->flen, GFP_ATOMIC);
			if(!msdu) {
				dbg_print(phy, PHY_RECV, DBG_ERR_CRIT,
					  "Cannot allocate msdu skb\n");
				phy->state &= ~PHY_BUSY_RX;
				ret = -ENOMEM;
				goto exit_rs;
			}
			memcpy(msdu->head, phy->rbuf, ppdu->flen);
			msdu->len = ppdu->flen;
			msdu->lq = ppduLQ;
			msdu->timestamp = jiffies;
			phy->state &= ~PHY_BUSY_RX;
			phy->r_idx = 0;
			_mac(phy)->pd_data_indicate(_mac(phy), msdu);
		}
	}
exit_rs:
	return 0;
#endif
	dbg_print(phy, 0, DBG_INFO, "not implemented\n");
	BUG();
}

/********************************************************/

ieee80215_phy_t* ieee80215_phy_alloc(const char *dev_name)
{
	ieee80215_phy_t *phy = NULL;
	size_t nlen;

	phy = (ieee80215_phy_t*)kmalloc(sizeof(ieee80215_phy_t), GFP_KERNEL);
	if (!phy) {
		printk(KERN_ERR "phy kmalloc failed\n");
		return NULL;
	}

	nlen = strlen(dev_name)+5;
	phy->name = kmalloc(nlen, GFP_KERNEL);
	if(!phy->name) {
		printk(KERN_ERR "phy->name kmalloc failed\n");
		kfree(phy);
		return NULL;
	}
	snprintf(phy->name, nlen, "%s:%s", dev_name, "phy");

	phy->priv = NULL;

	return phy;
}

void ieee80215_phy_free(ieee80215_phy_t *phy)
{
	if (phy) {
		kfree(phy->name);
		kfree(phy);
	}
}

int ieee80215_phy_init(ieee80215_phy_t *phy)
{
	dbg_print(phy, 0, DBG_INFO, "phy = 0x%p\n", phy);

	BUG_ON(!phy);

	phy->pib.curr_channel = 0xff;
	phy->pib.supp_channels = 0x0;
	phy->pib.trans_power = 0x0;
	phy->pib.cca_mode = 0x0;

	phy->state = PHY_IDLE;

	phy->r_idx = 0;
	phy->s_idx = 0;
	phy->s_len = 0;

	/*mutex_init(&phy->lock);*/

	phy->cmd_q = NULL;
	phy->worker = create_workqueue(phy->name);
	if (!phy->worker) {
		dbg_print(phy, PHY_CORE, DBG_ERR_CRIT,
			  "Could not create worker\n");
		return -EFAULT;
	}

	INIT_WORK(&phy->data_request, ieee80215_bg_pd_data_request);
	INIT_WORK(&phy->cca_request, ieee80215_bg_plme_cca_request);
	INIT_WORK(&phy->ed_request, ieee80215_bg_plme_ed_request);
	INIT_WORK(&phy->get_request, ieee80215_bg_plme_get_request);
	INIT_WORK(&phy->set_request, ieee80215_bg_plme_set_request);
	// INIT_WORK(&phy->set_trx_state_request, ieee80215_bg_plme_set_trx_request);

	phy->pd_data_request = ieee80215_pd_data_request;
	phy->plme_cca_request = ieee80215_plme_cca_request;
	phy->plme_ed_request = ieee80215_plme_ed_request;
	phy->plme_get_request = ieee80215_plme_get_request;
	phy->plme_set_request = ieee80215_plme_set_request;
	// phy->plme_set_trx_state_request = ieee80215_plme_set_trx_request;

	phy->set_channel_confirm = _set_channel_confirm;
	phy->ed_confirm = _ed_confirm;
	phy->set_state_confirm = _set_state_confirm;
	phy->xmit_confirm = _xmit_confirm;
	phy->cca_confirm = _cca_confirm;
	phy->receive_block = _receive_block;
	phy->receive_stream = _receive_stream;

	return 0;
}

int ieee80215_phy_close(ieee80215_phy_t *phy)
{
	dbg_print(phy, 0, DBG_INFO, "phy = 0x%p\n", phy);

	BUG_ON(!phy);

	work_clear_pending(&phy->data_request);
	work_clear_pending(&phy->cca_request);
	work_clear_pending(&phy->ed_request);
	work_clear_pending(&phy->get_request);
	// work_clear_pending(&phy->set_trx_state_request);
	work_clear_pending(&phy->set_request);

	flush_workqueue(phy->worker);
	destroy_workqueue(phy->worker);
	phy->worker = NULL;

	return 0;
}


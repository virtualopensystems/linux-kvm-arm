/******************************************************************************
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2008 - 2010 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *****************************************************************************/
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/etherdevice.h>
#include <net/mac80211.h>

#include "iwl-eeprom.h"
#include "iwl-dev.h"
#include "iwl-core.h"
#include "iwl-sta.h"
#include "iwl-io.h"
#include "iwl-helpers.h"

/* For active scan, listen ACTIVE_DWELL_TIME (msec) on each channel after
 * sending probe req.  This should be set long enough to hear probe responses
 * from more than one AP.  */
#define IWL_ACTIVE_DWELL_TIME_24    (30)       /* all times in msec */
#define IWL_ACTIVE_DWELL_TIME_52    (20)

#define IWL_ACTIVE_DWELL_FACTOR_24GHZ (3)
#define IWL_ACTIVE_DWELL_FACTOR_52GHZ (2)

/* For passive scan, listen PASSIVE_DWELL_TIME (msec) on each channel.
 * Must be set longer than active dwell time.
 * For the most reliable scan, set > AP beacon interval (typically 100msec). */
#define IWL_PASSIVE_DWELL_TIME_24   (20)       /* all times in msec */
#define IWL_PASSIVE_DWELL_TIME_52   (10)
#define IWL_PASSIVE_DWELL_BASE      (100)
#define IWL_CHANNEL_TUNE_TIME       5



/**
 * iwl_scan_cancel - Cancel any currently executing HW scan
 *
 * NOTE: priv->mutex is not required before calling this function
 */
int iwl_scan_cancel(struct iwl_priv *priv)
{
	if (!test_bit(STATUS_SCAN_HW, &priv->status)) {
		clear_bit(STATUS_SCANNING, &priv->status);
		return 0;
	}

	if (test_bit(STATUS_SCANNING, &priv->status)) {
		if (!test_bit(STATUS_SCAN_ABORTING, &priv->status)) {
			IWL_DEBUG_SCAN(priv, "Queuing scan abort.\n");
			set_bit(STATUS_SCAN_ABORTING, &priv->status);
			queue_work(priv->workqueue, &priv->abort_scan);

		} else
			IWL_DEBUG_SCAN(priv, "Scan abort already in progress.\n");

		return test_bit(STATUS_SCANNING, &priv->status);
	}

	return 0;
}
EXPORT_SYMBOL(iwl_scan_cancel);
/**
 * iwl_scan_cancel_timeout - Cancel any currently executing HW scan
 * @ms: amount of time to wait (in milliseconds) for scan to abort
 *
 * NOTE: priv->mutex must be held before calling this function
 */
int iwl_scan_cancel_timeout(struct iwl_priv *priv, unsigned long ms)
{
	unsigned long now = jiffies;
	int ret;

	ret = iwl_scan_cancel(priv);
	if (ret && ms) {
		mutex_unlock(&priv->mutex);
		while (!time_after(jiffies, now + msecs_to_jiffies(ms)) &&
				test_bit(STATUS_SCANNING, &priv->status))
			msleep(1);
		mutex_lock(&priv->mutex);

		return test_bit(STATUS_SCANNING, &priv->status);
	}

	return ret;
}
EXPORT_SYMBOL(iwl_scan_cancel_timeout);

static int iwl_send_scan_abort(struct iwl_priv *priv)
{
	int ret = 0;
	struct iwl_rx_packet *pkt;
	struct iwl_host_cmd cmd = {
		.id = REPLY_SCAN_ABORT_CMD,
		.flags = CMD_WANT_SKB,
	};

	/* If there isn't a scan actively going on in the hardware
	 * then we are in between scan bands and not actually
	 * actively scanning, so don't send the abort command */
	if (!test_bit(STATUS_SCAN_HW, &priv->status)) {
		clear_bit(STATUS_SCAN_ABORTING, &priv->status);
		return 0;
	}

	ret = iwl_send_cmd_sync(priv, &cmd);
	if (ret) {
		clear_bit(STATUS_SCAN_ABORTING, &priv->status);
		return ret;
	}

	pkt = (struct iwl_rx_packet *)cmd.reply_page;
	if (pkt->u.status != CAN_ABORT_STATUS) {
		/* The scan abort will return 1 for success or
		 * 2 for "failure".  A failure condition can be
		 * due to simply not being in an active scan which
		 * can occur if we send the scan abort before we
		 * the microcode has notified us that a scan is
		 * completed. */
		IWL_DEBUG_INFO(priv, "SCAN_ABORT returned %d.\n", pkt->u.status);
		clear_bit(STATUS_SCAN_ABORTING, &priv->status);
		clear_bit(STATUS_SCAN_HW, &priv->status);
	}

	iwl_free_pages(priv, cmd.reply_page);

	return ret;
}

/* Service response to REPLY_SCAN_CMD (0x80) */
static void iwl_rx_reply_scan(struct iwl_priv *priv,
			      struct iwl_rx_mem_buffer *rxb)
{
#ifdef CONFIG_IWLWIFI_DEBUG
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_scanreq_notification *notif =
	    (struct iwl_scanreq_notification *)pkt->u.raw;

	IWL_DEBUG_RX(priv, "Scan request status = 0x%x\n", notif->status);
#endif
}

/* Service SCAN_START_NOTIFICATION (0x82) */
static void iwl_rx_scan_start_notif(struct iwl_priv *priv,
				    struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_scanstart_notification *notif =
	    (struct iwl_scanstart_notification *)pkt->u.raw;
	priv->scan_start_tsf = le32_to_cpu(notif->tsf_low);
	IWL_DEBUG_SCAN(priv, "Scan start: "
		       "%d [802.11%s] "
		       "(TSF: 0x%08X:%08X) - %d (beacon timer %u)\n",
		       notif->channel,
		       notif->band ? "bg" : "a",
		       le32_to_cpu(notif->tsf_high),
		       le32_to_cpu(notif->tsf_low),
		       notif->status, notif->beacon_timer);
}

/* Service SCAN_RESULTS_NOTIFICATION (0x83) */
static void iwl_rx_scan_results_notif(struct iwl_priv *priv,
				      struct iwl_rx_mem_buffer *rxb)
{
#ifdef CONFIG_IWLWIFI_DEBUG
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_scanresults_notification *notif =
	    (struct iwl_scanresults_notification *)pkt->u.raw;

	IWL_DEBUG_SCAN(priv, "Scan ch.res: "
		       "%d [802.11%s] "
		       "(TSF: 0x%08X:%08X) - %d "
		       "elapsed=%lu usec\n",
		       notif->channel,
		       notif->band ? "bg" : "a",
		       le32_to_cpu(notif->tsf_high),
		       le32_to_cpu(notif->tsf_low),
		       le32_to_cpu(notif->statistics[0]),
		       le32_to_cpu(notif->tsf_low) - priv->scan_start_tsf);
#endif

	if (!priv->is_internal_short_scan)
		priv->next_scan_jiffies = 0;
}

/* Service SCAN_COMPLETE_NOTIFICATION (0x84) */
static void iwl_rx_scan_complete_notif(struct iwl_priv *priv,
				       struct iwl_rx_mem_buffer *rxb)
{
#ifdef CONFIG_IWLWIFI_DEBUG
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_scancomplete_notification *scan_notif = (void *)pkt->u.raw;

	IWL_DEBUG_SCAN(priv, "Scan complete: %d channels (TSF 0x%08X:%08X) - %d\n",
		       scan_notif->scanned_channels,
		       scan_notif->tsf_low,
		       scan_notif->tsf_high, scan_notif->status);
#endif

	/* The HW is no longer scanning */
	clear_bit(STATUS_SCAN_HW, &priv->status);

	IWL_DEBUG_INFO(priv, "Scan pass on %sGHz took %dms\n",
		       (priv->scan_bands & BIT(IEEE80211_BAND_2GHZ)) ?
						"2.4" : "5.2",
		       jiffies_to_msecs(elapsed_jiffies
					(priv->scan_pass_start, jiffies)));

	/* Remove this scanned band from the list of pending
	 * bands to scan, band G precedes A in order of scanning
	 * as seen in iwl_bg_request_scan */
	if (priv->scan_bands & BIT(IEEE80211_BAND_2GHZ))
		priv->scan_bands &= ~BIT(IEEE80211_BAND_2GHZ);
	else if (priv->scan_bands &  BIT(IEEE80211_BAND_5GHZ))
		priv->scan_bands &= ~BIT(IEEE80211_BAND_5GHZ);

	/* If a request to abort was given, or the scan did not succeed
	 * then we reset the scan state machine and terminate,
	 * re-queuing another scan if one has been requested */
	if (test_bit(STATUS_SCAN_ABORTING, &priv->status)) {
		IWL_DEBUG_INFO(priv, "Aborted scan completed.\n");
		clear_bit(STATUS_SCAN_ABORTING, &priv->status);
	} else {
		/* If there are more bands on this scan pass reschedule */
		if (priv->scan_bands)
			goto reschedule;
	}

	if (!priv->is_internal_short_scan)
		priv->next_scan_jiffies = 0;

	IWL_DEBUG_INFO(priv, "Setting scan to off\n");

	clear_bit(STATUS_SCANNING, &priv->status);

	IWL_DEBUG_INFO(priv, "Scan took %dms\n",
		jiffies_to_msecs(elapsed_jiffies(priv->scan_start, jiffies)));

	queue_work(priv->workqueue, &priv->scan_completed);

	return;

reschedule:
	priv->scan_pass_start = jiffies;
	queue_work(priv->workqueue, &priv->request_scan);
}

void iwl_setup_rx_scan_handlers(struct iwl_priv *priv)
{
	/* scan handlers */
	priv->rx_handlers[REPLY_SCAN_CMD] = iwl_rx_reply_scan;
	priv->rx_handlers[SCAN_START_NOTIFICATION] = iwl_rx_scan_start_notif;
	priv->rx_handlers[SCAN_RESULTS_NOTIFICATION] =
					iwl_rx_scan_results_notif;
	priv->rx_handlers[SCAN_COMPLETE_NOTIFICATION] =
					iwl_rx_scan_complete_notif;
}
EXPORT_SYMBOL(iwl_setup_rx_scan_handlers);

inline u16 iwl_get_active_dwell_time(struct iwl_priv *priv,
				     enum ieee80211_band band,
				     u8 n_probes)
{
	if (band == IEEE80211_BAND_5GHZ)
		return IWL_ACTIVE_DWELL_TIME_52 +
			IWL_ACTIVE_DWELL_FACTOR_52GHZ * (n_probes + 1);
	else
		return IWL_ACTIVE_DWELL_TIME_24 +
			IWL_ACTIVE_DWELL_FACTOR_24GHZ * (n_probes + 1);
}
EXPORT_SYMBOL(iwl_get_active_dwell_time);

u16 iwl_get_passive_dwell_time(struct iwl_priv *priv,
			       enum ieee80211_band band)
{
	u16 passive = (band == IEEE80211_BAND_2GHZ) ?
	    IWL_PASSIVE_DWELL_BASE + IWL_PASSIVE_DWELL_TIME_24 :
	    IWL_PASSIVE_DWELL_BASE + IWL_PASSIVE_DWELL_TIME_52;

	if (iwl_is_associated(priv)) {
		/* If we're associated, we clamp the maximum passive
		 * dwell time to be 98% of the beacon interval (minus
		 * 2 * channel tune time) */
		passive = priv->beacon_int;
		if ((passive > IWL_PASSIVE_DWELL_BASE) || !passive)
			passive = IWL_PASSIVE_DWELL_BASE;
		passive = (passive * 98) / 100 - IWL_CHANNEL_TUNE_TIME * 2;
	}

	return passive;
}
EXPORT_SYMBOL(iwl_get_passive_dwell_time);

static int iwl_get_single_channel_for_scan(struct iwl_priv *priv,
				     enum ieee80211_band band,
				     struct iwl_scan_channel *scan_ch)
{
	const struct ieee80211_supported_band *sband;
	const struct iwl_channel_info *ch_info;
	u16 passive_dwell = 0;
	u16 active_dwell = 0;
	int i, added = 0;
	u16 channel = 0;

	sband = iwl_get_hw_mode(priv, band);
	if (!sband) {
		IWL_ERR(priv, "invalid band\n");
		return added;
	}

	active_dwell = iwl_get_active_dwell_time(priv, band, 0);
	passive_dwell = iwl_get_passive_dwell_time(priv, band);

	if (passive_dwell <= active_dwell)
		passive_dwell = active_dwell + 1;

	/* only scan single channel, good enough to reset the RF */
	/* pick the first valid not in-use channel */
	if (band == IEEE80211_BAND_5GHZ) {
		for (i = 14; i < priv->channel_count; i++) {
			if (priv->channel_info[i].channel !=
			    le16_to_cpu(priv->staging_rxon.channel)) {
				channel = priv->channel_info[i].channel;
				ch_info = iwl_get_channel_info(priv,
					band, channel);
				if (is_channel_valid(ch_info))
					break;
			}
		}
	} else {
		for (i = 0; i < 14; i++) {
			if (priv->channel_info[i].channel !=
			    le16_to_cpu(priv->staging_rxon.channel)) {
					channel =
						priv->channel_info[i].channel;
					ch_info = iwl_get_channel_info(priv,
						band, channel);
					if (is_channel_valid(ch_info))
						break;
			}
		}
	}
	if (channel) {
		scan_ch->channel = cpu_to_le16(channel);
		scan_ch->type = SCAN_CHANNEL_TYPE_PASSIVE;
		scan_ch->active_dwell = cpu_to_le16(active_dwell);
		scan_ch->passive_dwell = cpu_to_le16(passive_dwell);
		/* Set txpower levels to defaults */
		scan_ch->dsp_atten = 110;
		if (band == IEEE80211_BAND_5GHZ)
			scan_ch->tx_gain = ((1 << 5) | (3 << 3)) | 3;
		else
			scan_ch->tx_gain = ((1 << 5) | (5 << 3));
		added++;
	} else
		IWL_ERR(priv, "no valid channel found\n");
	return added;
}

static int iwl_get_channels_for_scan(struct iwl_priv *priv,
				     enum ieee80211_band band,
				     u8 is_active, u8 n_probes,
				     struct iwl_scan_channel *scan_ch)
{
	struct ieee80211_channel *chan;
	const struct ieee80211_supported_band *sband;
	const struct iwl_channel_info *ch_info;
	u16 passive_dwell = 0;
	u16 active_dwell = 0;
	int added, i;
	u16 channel;

	sband = iwl_get_hw_mode(priv, band);
	if (!sband)
		return 0;

	active_dwell = iwl_get_active_dwell_time(priv, band, n_probes);
	passive_dwell = iwl_get_passive_dwell_time(priv, band);

	if (passive_dwell <= active_dwell)
		passive_dwell = active_dwell + 1;

	for (i = 0, added = 0; i < priv->scan_request->n_channels; i++) {
		chan = priv->scan_request->channels[i];

		if (chan->band != band)
			continue;

		channel = ieee80211_frequency_to_channel(chan->center_freq);
		scan_ch->channel = cpu_to_le16(channel);

		ch_info = iwl_get_channel_info(priv, band, channel);
		if (!is_channel_valid(ch_info)) {
			IWL_DEBUG_SCAN(priv, "Channel %d is INVALID for this band.\n",
					channel);
			continue;
		}

		if (!is_active || is_channel_passive(ch_info) ||
		    (chan->flags & IEEE80211_CHAN_PASSIVE_SCAN))
			scan_ch->type = SCAN_CHANNEL_TYPE_PASSIVE;
		else
			scan_ch->type = SCAN_CHANNEL_TYPE_ACTIVE;

		if (n_probes)
			scan_ch->type |= IWL_SCAN_PROBE_MASK(n_probes);

		scan_ch->active_dwell = cpu_to_le16(active_dwell);
		scan_ch->passive_dwell = cpu_to_le16(passive_dwell);

		/* Set txpower levels to defaults */
		scan_ch->dsp_atten = 110;

		/* NOTE: if we were doing 6Mb OFDM for scans we'd use
		 * power level:
		 * scan_ch->tx_gain = ((1 << 5) | (2 << 3)) | 3;
		 */
		if (band == IEEE80211_BAND_5GHZ)
			scan_ch->tx_gain = ((1 << 5) | (3 << 3)) | 3;
		else
			scan_ch->tx_gain = ((1 << 5) | (5 << 3));

		IWL_DEBUG_SCAN(priv, "Scanning ch=%d prob=0x%X [%s %d]\n",
			       channel, le32_to_cpu(scan_ch->type),
			       (scan_ch->type & SCAN_CHANNEL_TYPE_ACTIVE) ?
				"ACTIVE" : "PASSIVE",
			       (scan_ch->type & SCAN_CHANNEL_TYPE_ACTIVE) ?
			       active_dwell : passive_dwell);

		scan_ch++;
		added++;
	}

	IWL_DEBUG_SCAN(priv, "total channels to scan %d \n", added);
	return added;
}

void iwl_init_scan_params(struct iwl_priv *priv)
{
	u8 ant_idx = fls(priv->hw_params.valid_tx_ant) - 1;
	if (!priv->scan_tx_ant[IEEE80211_BAND_5GHZ])
		priv->scan_tx_ant[IEEE80211_BAND_5GHZ] = ant_idx;
	if (!priv->scan_tx_ant[IEEE80211_BAND_2GHZ])
		priv->scan_tx_ant[IEEE80211_BAND_2GHZ] = ant_idx;
}
EXPORT_SYMBOL(iwl_init_scan_params);

static int iwl_scan_initiate(struct iwl_priv *priv)
{
	IWL_DEBUG_INFO(priv, "Starting scan...\n");
	set_bit(STATUS_SCANNING, &priv->status);
	priv->is_internal_short_scan = false;
	priv->scan_start = jiffies;
	priv->scan_pass_start = priv->scan_start;

	queue_work(priv->workqueue, &priv->request_scan);

	return 0;
}

#define IWL_DELAY_NEXT_SCAN (HZ*2)

int iwl_mac_hw_scan(struct ieee80211_hw *hw,
		     struct cfg80211_scan_request *req)
{
	unsigned long flags;
	struct iwl_priv *priv = hw->priv;
	int ret, i;

	IWL_DEBUG_MAC80211(priv, "enter\n");

	mutex_lock(&priv->mutex);
	spin_lock_irqsave(&priv->lock, flags);

	if (!iwl_is_ready_rf(priv)) {
		ret = -EIO;
		IWL_DEBUG_MAC80211(priv, "leave - not ready or exit pending\n");
		goto out_unlock;
	}

	if (test_bit(STATUS_SCANNING, &priv->status)) {
		IWL_DEBUG_SCAN(priv, "Scan already in progress.\n");
		ret = -EAGAIN;
		goto out_unlock;
	}

	if (test_bit(STATUS_SCAN_ABORTING, &priv->status)) {
		IWL_DEBUG_SCAN(priv, "Scan request while abort pending\n");
		ret = -EAGAIN;
		goto out_unlock;
	}

	/* We don't schedule scan within next_scan_jiffies period.
	 * Avoid scanning during possible EAPOL exchange, return
	 * success immediately.
	 */
	if (priv->next_scan_jiffies &&
	    time_after(priv->next_scan_jiffies, jiffies)) {
		IWL_DEBUG_SCAN(priv, "scan rejected: within next scan period\n");
		queue_work(priv->workqueue, &priv->scan_completed);
		ret = 0;
		goto out_unlock;
	}

	priv->scan_bands = 0;
	for (i = 0; i < req->n_channels; i++)
		priv->scan_bands |= BIT(req->channels[i]->band);

	priv->scan_request = req;

	ret = iwl_scan_initiate(priv);

	IWL_DEBUG_MAC80211(priv, "leave\n");

out_unlock:
	spin_unlock_irqrestore(&priv->lock, flags);
	mutex_unlock(&priv->mutex);

	return ret;
}
EXPORT_SYMBOL(iwl_mac_hw_scan);

/*
 * internal short scan, this function should only been called while associated.
 * It will reset and tune the radio to prevent possible RF related problem
 */
int iwl_internal_short_hw_scan(struct iwl_priv *priv)
{
	int ret = 0;

	if (!iwl_is_ready_rf(priv)) {
		ret = -EIO;
		IWL_DEBUG_SCAN(priv, "not ready or exit pending\n");
		goto out;
	}
	if (test_bit(STATUS_SCANNING, &priv->status)) {
		IWL_DEBUG_SCAN(priv, "Scan already in progress.\n");
		ret = -EAGAIN;
		goto out;
	}
	if (test_bit(STATUS_SCAN_ABORTING, &priv->status)) {
		IWL_DEBUG_SCAN(priv, "Scan request while abort pending\n");
		ret = -EAGAIN;
		goto out;
	}

	priv->scan_bands = 0;
	if (priv->band == IEEE80211_BAND_5GHZ)
		priv->scan_bands |= BIT(IEEE80211_BAND_5GHZ);
	else
		priv->scan_bands |= BIT(IEEE80211_BAND_2GHZ);

	IWL_DEBUG_SCAN(priv, "Start internal short scan...\n");
	set_bit(STATUS_SCANNING, &priv->status);
	priv->is_internal_short_scan = true;
	queue_work(priv->workqueue, &priv->request_scan);

out:
	return ret;
}
EXPORT_SYMBOL(iwl_internal_short_hw_scan);

#define IWL_SCAN_CHECK_WATCHDOG (7 * HZ)

void iwl_bg_scan_check(struct work_struct *data)
{
	struct iwl_priv *priv =
	    container_of(data, struct iwl_priv, scan_check.work);

	if (test_bit(STATUS_EXIT_PENDING, &priv->status))
		return;

	mutex_lock(&priv->mutex);
	if (test_bit(STATUS_SCANNING, &priv->status) ||
	    test_bit(STATUS_SCAN_ABORTING, &priv->status)) {
		IWL_DEBUG_SCAN(priv, "Scan completion watchdog resetting "
			"adapter (%dms)\n",
			jiffies_to_msecs(IWL_SCAN_CHECK_WATCHDOG));

		if (!test_bit(STATUS_EXIT_PENDING, &priv->status))
			iwl_send_scan_abort(priv);
	}
	mutex_unlock(&priv->mutex);
}
EXPORT_SYMBOL(iwl_bg_scan_check);

/**
 * iwl_fill_probe_req - fill in all required fields and IE for probe request
 */

u16 iwl_fill_probe_req(struct iwl_priv *priv, struct ieee80211_mgmt *frame,
		       const u8 *ies, int ie_len, int left)
{
	int len = 0;
	u8 *pos = NULL;

	/* Make sure there is enough space for the probe request,
	 * two mandatory IEs and the data */
	left -= 24;
	if (left < 0)
		return 0;

	frame->frame_control = cpu_to_le16(IEEE80211_STYPE_PROBE_REQ);
	memcpy(frame->da, iwl_bcast_addr, ETH_ALEN);
	memcpy(frame->sa, priv->mac_addr, ETH_ALEN);
	memcpy(frame->bssid, iwl_bcast_addr, ETH_ALEN);
	frame->seq_ctrl = 0;

	len += 24;

	/* ...next IE... */
	pos = &frame->u.probe_req.variable[0];

	/* fill in our indirect SSID IE */
	left -= 2;
	if (left < 0)
		return 0;
	*pos++ = WLAN_EID_SSID;
	*pos++ = 0;

	len += 2;

	if (WARN_ON(left < ie_len))
		return len;

	if (ies)
		memcpy(pos, ies, ie_len);
	len += ie_len;
	left -= ie_len;

	return (u16)len;
}
EXPORT_SYMBOL(iwl_fill_probe_req);

static void iwl_bg_request_scan(struct work_struct *data)
{
	struct iwl_priv *priv =
	    container_of(data, struct iwl_priv, request_scan);
	struct iwl_host_cmd cmd = {
		.id = REPLY_SCAN_CMD,
		.len = sizeof(struct iwl_scan_cmd),
		.flags = CMD_SIZE_HUGE,
	};
	struct iwl_scan_cmd *scan;
	struct ieee80211_conf *conf = NULL;
	int ret = 0;
	u32 rate_flags = 0;
	u16 cmd_len;
	u16 rx_chain = 0;
	enum ieee80211_band band;
	u8 n_probes = 0;
	u8 rx_ant = priv->hw_params.valid_rx_ant;
	u8 rate;
	bool is_active = false;
	int  chan_mod;
	u8 active_chains;

	conf = ieee80211_get_hw_conf(priv->hw);

	mutex_lock(&priv->mutex);

	cancel_delayed_work(&priv->scan_check);

	if (!iwl_is_ready(priv)) {
		IWL_WARN(priv, "request scan called when driver not ready.\n");
		goto done;
	}

	/* Make sure the scan wasn't canceled before this queued work
	 * was given the chance to run... */
	if (!test_bit(STATUS_SCANNING, &priv->status))
		goto done;

	/* This should never be called or scheduled if there is currently
	 * a scan active in the hardware. */
	if (test_bit(STATUS_SCAN_HW, &priv->status)) {
		IWL_DEBUG_INFO(priv, "Multiple concurrent scan requests in parallel. "
			       "Ignoring second request.\n");
		ret = -EIO;
		goto done;
	}

	if (test_bit(STATUS_EXIT_PENDING, &priv->status)) {
		IWL_DEBUG_SCAN(priv, "Aborting scan due to device shutdown\n");
		goto done;
	}

	if (test_bit(STATUS_SCAN_ABORTING, &priv->status)) {
		IWL_DEBUG_HC(priv, "Scan request while abort pending.  Queuing.\n");
		goto done;
	}

	if (iwl_is_rfkill(priv)) {
		IWL_DEBUG_HC(priv, "Aborting scan due to RF Kill activation\n");
		goto done;
	}

	if (!test_bit(STATUS_READY, &priv->status)) {
		IWL_DEBUG_HC(priv, "Scan request while uninitialized.  Queuing.\n");
		goto done;
	}

	if (!priv->scan_bands) {
		IWL_DEBUG_HC(priv, "Aborting scan due to no requested bands\n");
		goto done;
	}

	if (!priv->scan) {
		priv->scan = kmalloc(sizeof(struct iwl_scan_cmd) +
				     IWL_MAX_SCAN_SIZE, GFP_KERNEL);
		if (!priv->scan) {
			ret = -ENOMEM;
			goto done;
		}
	}
	scan = priv->scan;
	memset(scan, 0, sizeof(struct iwl_scan_cmd) + IWL_MAX_SCAN_SIZE);

	scan->quiet_plcp_th = IWL_PLCP_QUIET_THRESH;
	scan->quiet_time = IWL_ACTIVE_QUIET_TIME;

	if (iwl_is_associated(priv)) {
		u16 interval = 0;
		u32 extra;
		u32 suspend_time = 100;
		u32 scan_suspend_time = 100;
		unsigned long flags;

		IWL_DEBUG_INFO(priv, "Scanning while associated...\n");
		spin_lock_irqsave(&priv->lock, flags);
		interval = priv->beacon_int;
		spin_unlock_irqrestore(&priv->lock, flags);

		scan->suspend_time = 0;
		scan->max_out_time = cpu_to_le32(200 * 1024);
		if (!interval)
			interval = suspend_time;

		extra = (suspend_time / interval) << 22;
		scan_suspend_time = (extra |
		    ((suspend_time % interval) * 1024));
		scan->suspend_time = cpu_to_le32(scan_suspend_time);
		IWL_DEBUG_SCAN(priv, "suspend_time 0x%X beacon interval %d\n",
			       scan_suspend_time, interval);
	}

	if (priv->is_internal_short_scan) {
		IWL_DEBUG_SCAN(priv, "Start internal passive scan.\n");
	} else if (priv->scan_request->n_ssids) {
		int i, p = 0;
		IWL_DEBUG_SCAN(priv, "Kicking off active scan\n");
		for (i = 0; i < priv->scan_request->n_ssids; i++) {
			/* always does wildcard anyway */
			if (!priv->scan_request->ssids[i].ssid_len)
				continue;
			scan->direct_scan[p].id = WLAN_EID_SSID;
			scan->direct_scan[p].len =
				priv->scan_request->ssids[i].ssid_len;
			memcpy(scan->direct_scan[p].ssid,
			       priv->scan_request->ssids[i].ssid,
			       priv->scan_request->ssids[i].ssid_len);
			n_probes++;
			p++;
		}
		is_active = true;
	} else
		IWL_DEBUG_SCAN(priv, "Start passive scan.\n");

	scan->tx_cmd.tx_flags = TX_CMD_FLG_SEQ_CTL_MSK;
	scan->tx_cmd.sta_id = priv->hw_params.bcast_sta_id;
	scan->tx_cmd.stop_time.life_time = TX_CMD_LIFE_TIME_INFINITE;


	if (priv->scan_bands & BIT(IEEE80211_BAND_2GHZ)) {
		band = IEEE80211_BAND_2GHZ;
		scan->flags = RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK;
		chan_mod = le32_to_cpu(priv->active_rxon.flags & RXON_FLG_CHANNEL_MODE_MSK)
				       >> RXON_FLG_CHANNEL_MODE_POS;
		if (chan_mod == CHANNEL_MODE_PURE_40) {
			rate = IWL_RATE_6M_PLCP;
		} else {
			rate = IWL_RATE_1M_PLCP;
			rate_flags = RATE_MCS_CCK_MSK;
		}
		scan->good_CRC_th = 0;
	} else if (priv->scan_bands & BIT(IEEE80211_BAND_5GHZ)) {
		band = IEEE80211_BAND_5GHZ;
		rate = IWL_RATE_6M_PLCP;
		/*
		 * If active scaning is requested but a certain channel
		 * is marked passive, we can do active scanning if we
		 * detect transmissions.
		 */
		scan->good_CRC_th = is_active ? IWL_GOOD_CRC_TH : 0;

		/* Force use of chains B and C (0x6) for scan Rx for 4965
		 * Avoid A (0x1) because of its off-channel reception on A-band.
		 */
		if ((priv->hw_rev & CSR_HW_REV_TYPE_MSK) == CSR_HW_REV_TYPE_4965)
			rx_ant = ANT_BC;
	} else {
		IWL_WARN(priv, "Invalid scan band count\n");
		goto done;
	}

	priv->scan_tx_ant[band] =
			 iwl_toggle_tx_ant(priv, priv->scan_tx_ant[band]);
	rate_flags |= iwl_ant_idx_to_flags(priv->scan_tx_ant[band]);
	scan->tx_cmd.rate_n_flags = iwl_hw_set_rate_n_flags(rate, rate_flags);

	/* In power save mode use one chain, otherwise use all chains */
	if (test_bit(STATUS_POWER_PMI, &priv->status)) {
		/* rx_ant has been set to all valid chains previously */
		active_chains = rx_ant &
				((u8)(priv->chain_noise_data.active_chains));
		if (!active_chains)
			active_chains = rx_ant;

		IWL_DEBUG_SCAN(priv, "chain_noise_data.active_chains: %u\n",
				priv->chain_noise_data.active_chains);

		rx_ant = first_antenna(active_chains);
	}
	/* MIMO is not used here, but value is required */
	rx_chain |= priv->hw_params.valid_rx_ant << RXON_RX_CHAIN_VALID_POS;
	rx_chain |= rx_ant << RXON_RX_CHAIN_FORCE_MIMO_SEL_POS;
	rx_chain |= rx_ant << RXON_RX_CHAIN_FORCE_SEL_POS;
	rx_chain |= 0x1 << RXON_RX_CHAIN_DRIVER_FORCE_POS;
	scan->rx_chain = cpu_to_le16(rx_chain);
	if (!priv->is_internal_short_scan) {
		cmd_len = iwl_fill_probe_req(priv,
					(struct ieee80211_mgmt *)scan->data,
					priv->scan_request->ie,
					priv->scan_request->ie_len,
					IWL_MAX_SCAN_SIZE - sizeof(*scan));
	} else {
		cmd_len = iwl_fill_probe_req(priv,
					(struct ieee80211_mgmt *)scan->data,
					NULL, 0,
					IWL_MAX_SCAN_SIZE - sizeof(*scan));

	}
	scan->tx_cmd.len = cpu_to_le16(cmd_len);
	if (iwl_is_monitor_mode(priv))
		scan->filter_flags = RXON_FILTER_PROMISC_MSK;

	scan->filter_flags |= (RXON_FILTER_ACCEPT_GRP_MSK |
			       RXON_FILTER_BCON_AWARE_MSK);

	if (priv->is_internal_short_scan) {
		scan->channel_count =
			iwl_get_single_channel_for_scan(priv, band,
				(void *)&scan->data[le16_to_cpu(
				scan->tx_cmd.len)]);
	} else {
		scan->channel_count =
			iwl_get_channels_for_scan(priv, band,
				is_active, n_probes,
				(void *)&scan->data[le16_to_cpu(
				scan->tx_cmd.len)]);
	}
	if (scan->channel_count == 0) {
		IWL_DEBUG_SCAN(priv, "channel count %d\n", scan->channel_count);
		goto done;
	}

	cmd.len += le16_to_cpu(scan->tx_cmd.len) +
	    scan->channel_count * sizeof(struct iwl_scan_channel);
	cmd.data = scan;
	scan->len = cpu_to_le16(cmd.len);

	set_bit(STATUS_SCAN_HW, &priv->status);
	ret = iwl_send_cmd_sync(priv, &cmd);
	if (ret)
		goto done;

	queue_delayed_work(priv->workqueue, &priv->scan_check,
			   IWL_SCAN_CHECK_WATCHDOG);

	mutex_unlock(&priv->mutex);
	return;

 done:
	/* Cannot perform scan. Make sure we clear scanning
	* bits from status so next scan request can be performed.
	* If we don't clear scanning status bit here all next scan
	* will fail
	*/
	clear_bit(STATUS_SCAN_HW, &priv->status);
	clear_bit(STATUS_SCANNING, &priv->status);
	/* inform mac80211 scan aborted */
	queue_work(priv->workqueue, &priv->scan_completed);
	mutex_unlock(&priv->mutex);
}

void iwl_bg_abort_scan(struct work_struct *work)
{
	struct iwl_priv *priv = container_of(work, struct iwl_priv, abort_scan);

	if (!test_bit(STATUS_READY, &priv->status) ||
	    !test_bit(STATUS_GEO_CONFIGURED, &priv->status))
		return;

	mutex_lock(&priv->mutex);

	set_bit(STATUS_SCAN_ABORTING, &priv->status);
	iwl_send_scan_abort(priv);

	mutex_unlock(&priv->mutex);
}
EXPORT_SYMBOL(iwl_bg_abort_scan);

void iwl_bg_scan_completed(struct work_struct *work)
{
	struct iwl_priv *priv =
	    container_of(work, struct iwl_priv, scan_completed);

	IWL_DEBUG_SCAN(priv, "SCAN complete scan\n");

	cancel_delayed_work(&priv->scan_check);

	if (!priv->is_internal_short_scan)
		ieee80211_scan_completed(priv->hw, false);
	else {
		priv->is_internal_short_scan = false;
		IWL_DEBUG_SCAN(priv, "internal short scan completed\n");
	}

	if (test_bit(STATUS_EXIT_PENDING, &priv->status))
		return;

	/* Since setting the TXPOWER may have been deferred while
	 * performing the scan, fire one off */
	mutex_lock(&priv->mutex);
	iwl_set_tx_power(priv, priv->tx_power_user_lmt, true);
	mutex_unlock(&priv->mutex);
}
EXPORT_SYMBOL(iwl_bg_scan_completed);

void iwl_setup_scan_deferred_work(struct iwl_priv *priv)
{
	INIT_WORK(&priv->scan_completed, iwl_bg_scan_completed);
	INIT_WORK(&priv->request_scan, iwl_bg_request_scan);
	INIT_WORK(&priv->abort_scan, iwl_bg_abort_scan);
	INIT_DELAYED_WORK(&priv->scan_check, iwl_bg_scan_check);
}
EXPORT_SYMBOL(iwl_setup_scan_deferred_work);


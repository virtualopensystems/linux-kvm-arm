/*
 * Copyright (c) 2008-2009 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/io.h>
#include <linux/slab.h>
#include <asm/unaligned.h>

#include "hw.h"
#include "rc.h"
#include "initvals.h"

#define ATH9K_CLOCK_RATE_CCK		22
#define ATH9K_CLOCK_RATE_5GHZ_OFDM	40
#define ATH9K_CLOCK_RATE_2GHZ_OFDM	44

static bool ath9k_hw_set_reset_reg(struct ath_hw *ah, u32 type);
static void ath9k_hw_set_regs(struct ath_hw *ah, struct ath9k_channel *chan);
static u32 ath9k_hw_ini_fixup(struct ath_hw *ah,
			      struct ar5416_eeprom_def *pEepData,
			      u32 reg, u32 value);

MODULE_AUTHOR("Atheros Communications");
MODULE_DESCRIPTION("Support for Atheros 802.11n wireless LAN cards.");
MODULE_SUPPORTED_DEVICE("Atheros 802.11n WLAN cards");
MODULE_LICENSE("Dual BSD/GPL");

static int __init ath9k_init(void)
{
	return 0;
}
module_init(ath9k_init);

static void __exit ath9k_exit(void)
{
	return;
}
module_exit(ath9k_exit);

/********************/
/* Helper Functions */
/********************/

static u32 ath9k_hw_mac_clks(struct ath_hw *ah, u32 usecs)
{
	struct ieee80211_conf *conf = &ath9k_hw_common(ah)->hw->conf;

	if (!ah->curchan) /* should really check for CCK instead */
		return usecs *ATH9K_CLOCK_RATE_CCK;
	if (conf->channel->band == IEEE80211_BAND_2GHZ)
		return usecs *ATH9K_CLOCK_RATE_2GHZ_OFDM;
	return usecs *ATH9K_CLOCK_RATE_5GHZ_OFDM;
}

static u32 ath9k_hw_mac_to_clks(struct ath_hw *ah, u32 usecs)
{
	struct ieee80211_conf *conf = &ath9k_hw_common(ah)->hw->conf;

	if (conf_is_ht40(conf))
		return ath9k_hw_mac_clks(ah, usecs) * 2;
	else
		return ath9k_hw_mac_clks(ah, usecs);
}

bool ath9k_hw_wait(struct ath_hw *ah, u32 reg, u32 mask, u32 val, u32 timeout)
{
	int i;

	BUG_ON(timeout < AH_TIME_QUANTUM);

	for (i = 0; i < (timeout / AH_TIME_QUANTUM); i++) {
		if ((REG_READ(ah, reg) & mask) == val)
			return true;

		udelay(AH_TIME_QUANTUM);
	}

	ath_print(ath9k_hw_common(ah), ATH_DBG_ANY,
		  "timeout (%d us) on reg 0x%x: 0x%08x & 0x%08x != 0x%08x\n",
		  timeout, reg, REG_READ(ah, reg), mask, val);

	return false;
}
EXPORT_SYMBOL(ath9k_hw_wait);

u32 ath9k_hw_reverse_bits(u32 val, u32 n)
{
	u32 retval;
	int i;

	for (i = 0, retval = 0; i < n; i++) {
		retval = (retval << 1) | (val & 1);
		val >>= 1;
	}
	return retval;
}

bool ath9k_get_channel_edges(struct ath_hw *ah,
			     u16 flags, u16 *low,
			     u16 *high)
{
	struct ath9k_hw_capabilities *pCap = &ah->caps;

	if (flags & CHANNEL_5GHZ) {
		*low = pCap->low_5ghz_chan;
		*high = pCap->high_5ghz_chan;
		return true;
	}
	if ((flags & CHANNEL_2GHZ)) {
		*low = pCap->low_2ghz_chan;
		*high = pCap->high_2ghz_chan;
		return true;
	}
	return false;
}

u16 ath9k_hw_computetxtime(struct ath_hw *ah,
			   u8 phy, int kbps,
			   u32 frameLen, u16 rateix,
			   bool shortPreamble)
{
	u32 bitsPerSymbol, numBits, numSymbols, phyTime, txTime;

	if (kbps == 0)
		return 0;

	switch (phy) {
	case WLAN_RC_PHY_CCK:
		phyTime = CCK_PREAMBLE_BITS + CCK_PLCP_BITS;
		if (shortPreamble)
			phyTime >>= 1;
		numBits = frameLen << 3;
		txTime = CCK_SIFS_TIME + phyTime + ((numBits * 1000) / kbps);
		break;
	case WLAN_RC_PHY_OFDM:
		if (ah->curchan && IS_CHAN_QUARTER_RATE(ah->curchan)) {
			bitsPerSymbol =	(kbps * OFDM_SYMBOL_TIME_QUARTER) / 1000;
			numBits = OFDM_PLCP_BITS + (frameLen << 3);
			numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol);
			txTime = OFDM_SIFS_TIME_QUARTER
				+ OFDM_PREAMBLE_TIME_QUARTER
				+ (numSymbols * OFDM_SYMBOL_TIME_QUARTER);
		} else if (ah->curchan &&
			   IS_CHAN_HALF_RATE(ah->curchan)) {
			bitsPerSymbol =	(kbps * OFDM_SYMBOL_TIME_HALF) / 1000;
			numBits = OFDM_PLCP_BITS + (frameLen << 3);
			numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol);
			txTime = OFDM_SIFS_TIME_HALF +
				OFDM_PREAMBLE_TIME_HALF
				+ (numSymbols * OFDM_SYMBOL_TIME_HALF);
		} else {
			bitsPerSymbol = (kbps * OFDM_SYMBOL_TIME) / 1000;
			numBits = OFDM_PLCP_BITS + (frameLen << 3);
			numSymbols = DIV_ROUND_UP(numBits, bitsPerSymbol);
			txTime = OFDM_SIFS_TIME + OFDM_PREAMBLE_TIME
				+ (numSymbols * OFDM_SYMBOL_TIME);
		}
		break;
	default:
		ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
			  "Unknown phy %u (rate ix %u)\n", phy, rateix);
		txTime = 0;
		break;
	}

	return txTime;
}
EXPORT_SYMBOL(ath9k_hw_computetxtime);

void ath9k_hw_get_channel_centers(struct ath_hw *ah,
				  struct ath9k_channel *chan,
				  struct chan_centers *centers)
{
	int8_t extoff;

	if (!IS_CHAN_HT40(chan)) {
		centers->ctl_center = centers->ext_center =
			centers->synth_center = chan->channel;
		return;
	}

	if ((chan->chanmode == CHANNEL_A_HT40PLUS) ||
	    (chan->chanmode == CHANNEL_G_HT40PLUS)) {
		centers->synth_center =
			chan->channel + HT40_CHANNEL_CENTER_SHIFT;
		extoff = 1;
	} else {
		centers->synth_center =
			chan->channel - HT40_CHANNEL_CENTER_SHIFT;
		extoff = -1;
	}

	centers->ctl_center =
		centers->synth_center - (extoff * HT40_CHANNEL_CENTER_SHIFT);
	/* 25 MHz spacing is supported by hw but not on upper layers */
	centers->ext_center =
		centers->synth_center + (extoff * HT40_CHANNEL_CENTER_SHIFT);
}

/******************/
/* Chip Revisions */
/******************/

static void ath9k_hw_read_revisions(struct ath_hw *ah)
{
	u32 val;

	val = REG_READ(ah, AR_SREV) & AR_SREV_ID;

	if (val == 0xFF) {
		val = REG_READ(ah, AR_SREV);
		ah->hw_version.macVersion =
			(val & AR_SREV_VERSION2) >> AR_SREV_TYPE2_S;
		ah->hw_version.macRev = MS(val, AR_SREV_REVISION2);
		ah->is_pciexpress = (val & AR_SREV_TYPE2_HOST_MODE) ? 0 : 1;
	} else {
		if (!AR_SREV_9100(ah))
			ah->hw_version.macVersion = MS(val, AR_SREV_VERSION);

		ah->hw_version.macRev = val & AR_SREV_REVISION;

		if (ah->hw_version.macVersion == AR_SREV_VERSION_5416_PCIE)
			ah->is_pciexpress = true;
	}
}

static int ath9k_hw_get_radiorev(struct ath_hw *ah)
{
	u32 val;
	int i;

	REG_WRITE(ah, AR_PHY(0x36), 0x00007058);

	for (i = 0; i < 8; i++)
		REG_WRITE(ah, AR_PHY(0x20), 0x00010000);
	val = (REG_READ(ah, AR_PHY(256)) >> 24) & 0xff;
	val = ((val & 0xf0) >> 4) | ((val & 0x0f) << 4);

	return ath9k_hw_reverse_bits(val, 8);
}

/************************************/
/* HW Attach, Detach, Init Routines */
/************************************/

static void ath9k_hw_disablepcie(struct ath_hw *ah)
{
	if (AR_SREV_9100(ah))
		return;

	REG_WRITE(ah, AR_PCIE_SERDES, 0x9248fc00);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x24924924);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x28000029);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x57160824);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x25980579);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x00000000);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x1aaabe40);
	REG_WRITE(ah, AR_PCIE_SERDES, 0xbe105554);
	REG_WRITE(ah, AR_PCIE_SERDES, 0x000e1007);

	REG_WRITE(ah, AR_PCIE_SERDES2, 0x00000000);
}

static bool ath9k_hw_chip_test(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	u32 regAddr[2] = { AR_STA_ID0, AR_PHY_BASE + (8 << 2) };
	u32 regHold[2];
	u32 patternData[4] = { 0x55555555,
			       0xaaaaaaaa,
			       0x66666666,
			       0x99999999 };
	int i, j;

	for (i = 0; i < 2; i++) {
		u32 addr = regAddr[i];
		u32 wrData, rdData;

		regHold[i] = REG_READ(ah, addr);
		for (j = 0; j < 0x100; j++) {
			wrData = (j << 16) | j;
			REG_WRITE(ah, addr, wrData);
			rdData = REG_READ(ah, addr);
			if (rdData != wrData) {
				ath_print(common, ATH_DBG_FATAL,
					  "address test failed "
					  "addr: 0x%08x - wr:0x%08x != "
					  "rd:0x%08x\n",
					  addr, wrData, rdData);
				return false;
			}
		}
		for (j = 0; j < 4; j++) {
			wrData = patternData[j];
			REG_WRITE(ah, addr, wrData);
			rdData = REG_READ(ah, addr);
			if (wrData != rdData) {
				ath_print(common, ATH_DBG_FATAL,
					  "address test failed "
					  "addr: 0x%08x - wr:0x%08x != "
					  "rd:0x%08x\n",
					  addr, wrData, rdData);
				return false;
			}
		}
		REG_WRITE(ah, regAddr[i], regHold[i]);
	}
	udelay(100);

	return true;
}

static void ath9k_hw_init_config(struct ath_hw *ah)
{
	int i;

	ah->config.dma_beacon_response_time = 2;
	ah->config.sw_beacon_response_time = 10;
	ah->config.additional_swba_backoff = 0;
	ah->config.ack_6mb = 0x0;
	ah->config.cwm_ignore_extcca = 0;
	ah->config.pcie_powersave_enable = 0;
	ah->config.pcie_clock_req = 0;
	ah->config.pcie_waen = 0;
	ah->config.analog_shiftreg = 1;
	ah->config.ofdm_trig_low = 200;
	ah->config.ofdm_trig_high = 500;
	ah->config.cck_trig_high = 200;
	ah->config.cck_trig_low = 100;
	ah->config.enable_ani = 1;

	for (i = 0; i < AR_EEPROM_MODAL_SPURS; i++) {
		ah->config.spurchans[i][0] = AR_NO_SPUR;
		ah->config.spurchans[i][1] = AR_NO_SPUR;
	}

	if (ah->hw_version.devid != AR2427_DEVID_PCIE)
		ah->config.ht_enable = 1;
	else
		ah->config.ht_enable = 0;

	ah->config.rx_intr_mitigation = true;

	/*
	 * We need this for PCI devices only (Cardbus, PCI, miniPCI)
	 * _and_ if on non-uniprocessor systems (Multiprocessor/HT).
	 * This means we use it for all AR5416 devices, and the few
	 * minor PCI AR9280 devices out there.
	 *
	 * Serialization is required because these devices do not handle
	 * well the case of two concurrent reads/writes due to the latency
	 * involved. During one read/write another read/write can be issued
	 * on another CPU while the previous read/write may still be working
	 * on our hardware, if we hit this case the hardware poops in a loop.
	 * We prevent this by serializing reads and writes.
	 *
	 * This issue is not present on PCI-Express devices or pre-AR5416
	 * devices (legacy, 802.11abg).
	 */
	if (num_possible_cpus() > 1)
		ah->config.serialize_regmode = SER_REG_MODE_AUTO;
}
EXPORT_SYMBOL(ath9k_hw_init);

static void ath9k_hw_init_defaults(struct ath_hw *ah)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);

	regulatory->country_code = CTRY_DEFAULT;
	regulatory->power_limit = MAX_RATE_POWER;
	regulatory->tp_scale = ATH9K_TP_SCALE_MAX;

	ah->hw_version.magic = AR5416_MAGIC;
	ah->hw_version.subvendorid = 0;

	ah->ah_flags = 0;
	if (ah->hw_version.devid == AR5416_AR9100_DEVID)
		ah->hw_version.macVersion = AR_SREV_VERSION_9100;
	if (!AR_SREV_9100(ah))
		ah->ah_flags = AH_USE_EEPROM;

	ah->atim_window = 0;
	ah->sta_id1_defaults = AR_STA_ID1_CRPT_MIC_ENABLE;
	ah->beacon_interval = 100;
	ah->enable_32kHz_clock = DONT_USE_32KHZ;
	ah->slottime = (u32) -1;
	ah->globaltxtimeout = (u32) -1;
	ah->power_mode = ATH9K_PM_UNDEFINED;
}

static int ath9k_hw_rf_claim(struct ath_hw *ah)
{
	u32 val;

	REG_WRITE(ah, AR_PHY(0), 0x00000007);

	val = ath9k_hw_get_radiorev(ah);
	switch (val & AR_RADIO_SREV_MAJOR) {
	case 0:
		val = AR_RAD5133_SREV_MAJOR;
		break;
	case AR_RAD5133_SREV_MAJOR:
	case AR_RAD5122_SREV_MAJOR:
	case AR_RAD2133_SREV_MAJOR:
	case AR_RAD2122_SREV_MAJOR:
		break;
	default:
		ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
			  "Radio Chip Rev 0x%02X not supported\n",
			  val & AR_RADIO_SREV_MAJOR);
		return -EOPNOTSUPP;
	}

	ah->hw_version.analog5GhzRev = val;

	return 0;
}

static int ath9k_hw_init_macaddr(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	u32 sum;
	int i;
	u16 eeval;

	sum = 0;
	for (i = 0; i < 3; i++) {
		eeval = ah->eep_ops->get_eeprom(ah, AR_EEPROM_MAC(i));
		sum += eeval;
		common->macaddr[2 * i] = eeval >> 8;
		common->macaddr[2 * i + 1] = eeval & 0xff;
	}
	if (sum == 0 || sum == 0xffff * 3)
		return -EADDRNOTAVAIL;

	return 0;
}

static void ath9k_hw_init_rxgain_ini(struct ath_hw *ah)
{
	u32 rxgain_type;

	if (ah->eep_ops->get_eeprom(ah, EEP_MINOR_REV) >= AR5416_EEP_MINOR_VER_17) {
		rxgain_type = ah->eep_ops->get_eeprom(ah, EEP_RXGAIN_TYPE);

		if (rxgain_type == AR5416_EEP_RXGAIN_13DB_BACKOFF)
			INIT_INI_ARRAY(&ah->iniModesRxGain,
			ar9280Modes_backoff_13db_rxgain_9280_2,
			ARRAY_SIZE(ar9280Modes_backoff_13db_rxgain_9280_2), 6);
		else if (rxgain_type == AR5416_EEP_RXGAIN_23DB_BACKOFF)
			INIT_INI_ARRAY(&ah->iniModesRxGain,
			ar9280Modes_backoff_23db_rxgain_9280_2,
			ARRAY_SIZE(ar9280Modes_backoff_23db_rxgain_9280_2), 6);
		else
			INIT_INI_ARRAY(&ah->iniModesRxGain,
			ar9280Modes_original_rxgain_9280_2,
			ARRAY_SIZE(ar9280Modes_original_rxgain_9280_2), 6);
	} else {
		INIT_INI_ARRAY(&ah->iniModesRxGain,
			ar9280Modes_original_rxgain_9280_2,
			ARRAY_SIZE(ar9280Modes_original_rxgain_9280_2), 6);
	}
}

static void ath9k_hw_init_txgain_ini(struct ath_hw *ah)
{
	u32 txgain_type;

	if (ah->eep_ops->get_eeprom(ah, EEP_MINOR_REV) >= AR5416_EEP_MINOR_VER_19) {
		txgain_type = ah->eep_ops->get_eeprom(ah, EEP_TXGAIN_TYPE);

		if (txgain_type == AR5416_EEP_TXGAIN_HIGH_POWER)
			INIT_INI_ARRAY(&ah->iniModesTxGain,
			ar9280Modes_high_power_tx_gain_9280_2,
			ARRAY_SIZE(ar9280Modes_high_power_tx_gain_9280_2), 6);
		else
			INIT_INI_ARRAY(&ah->iniModesTxGain,
			ar9280Modes_original_tx_gain_9280_2,
			ARRAY_SIZE(ar9280Modes_original_tx_gain_9280_2), 6);
	} else {
		INIT_INI_ARRAY(&ah->iniModesTxGain,
		ar9280Modes_original_tx_gain_9280_2,
		ARRAY_SIZE(ar9280Modes_original_tx_gain_9280_2), 6);
	}
}

static int ath9k_hw_post_init(struct ath_hw *ah)
{
	int ecode;

	if (!ath9k_hw_chip_test(ah))
		return -ENODEV;

	ecode = ath9k_hw_rf_claim(ah);
	if (ecode != 0)
		return ecode;

	ecode = ath9k_hw_eeprom_init(ah);
	if (ecode != 0)
		return ecode;

	ath_print(ath9k_hw_common(ah), ATH_DBG_CONFIG,
		  "Eeprom VER: %d, REV: %d\n",
		  ah->eep_ops->get_eeprom_ver(ah),
		  ah->eep_ops->get_eeprom_rev(ah));

        if (!AR_SREV_9280_10_OR_LATER(ah)) {
		ecode = ath9k_hw_rf_alloc_ext_banks(ah);
		if (ecode) {
			ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
				  "Failed allocating banks for "
				  "external radio\n");
			return ecode;
		}
	}

	if (!AR_SREV_9100(ah)) {
		ath9k_hw_ani_setup(ah);
		ath9k_hw_ani_init(ah);
	}

	return 0;
}

static bool ath9k_hw_devid_supported(u16 devid)
{
	switch (devid) {
	case AR5416_DEVID_PCI:
	case AR5416_DEVID_PCIE:
	case AR5416_AR9100_DEVID:
	case AR9160_DEVID_PCI:
	case AR9280_DEVID_PCI:
	case AR9280_DEVID_PCIE:
	case AR9285_DEVID_PCIE:
	case AR5416_DEVID_AR9287_PCI:
	case AR5416_DEVID_AR9287_PCIE:
	case AR9271_USB:
	case AR2427_DEVID_PCIE:
		return true;
	default:
		break;
	}
	return false;
}

static bool ath9k_hw_macversion_supported(u32 macversion)
{
	switch (macversion) {
	case AR_SREV_VERSION_5416_PCI:
	case AR_SREV_VERSION_5416_PCIE:
	case AR_SREV_VERSION_9160:
	case AR_SREV_VERSION_9100:
	case AR_SREV_VERSION_9280:
	case AR_SREV_VERSION_9285:
	case AR_SREV_VERSION_9287:
	case AR_SREV_VERSION_9271:
		return true;
	default:
		break;
	}
	return false;
}

static void ath9k_hw_init_cal_settings(struct ath_hw *ah)
{
	if (AR_SREV_9160_10_OR_LATER(ah)) {
		if (AR_SREV_9280_10_OR_LATER(ah)) {
			ah->iq_caldata.calData = &iq_cal_single_sample;
			ah->adcgain_caldata.calData =
				&adc_gain_cal_single_sample;
			ah->adcdc_caldata.calData =
				&adc_dc_cal_single_sample;
			ah->adcdc_calinitdata.calData =
				&adc_init_dc_cal;
		} else {
			ah->iq_caldata.calData = &iq_cal_multi_sample;
			ah->adcgain_caldata.calData =
				&adc_gain_cal_multi_sample;
			ah->adcdc_caldata.calData =
				&adc_dc_cal_multi_sample;
			ah->adcdc_calinitdata.calData =
				&adc_init_dc_cal;
		}
		ah->supp_cals = ADC_GAIN_CAL | ADC_DC_CAL | IQ_MISMATCH_CAL;
	}
}

static void ath9k_hw_init_mode_regs(struct ath_hw *ah)
{
	if (AR_SREV_9271(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar9271Modes_9271,
			       ARRAY_SIZE(ar9271Modes_9271), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar9271Common_9271,
			       ARRAY_SIZE(ar9271Common_9271), 2);
		INIT_INI_ARRAY(&ah->iniModes_9271_1_0_only,
			       ar9271Modes_9271_1_0_only,
			       ARRAY_SIZE(ar9271Modes_9271_1_0_only), 6);
		return;
	}

	if (AR_SREV_9287_11_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar9287Modes_9287_1_1,
				ARRAY_SIZE(ar9287Modes_9287_1_1), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar9287Common_9287_1_1,
				ARRAY_SIZE(ar9287Common_9287_1_1), 2);
		if (ah->config.pcie_clock_req)
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9287PciePhy_clkreq_off_L1_9287_1_1,
			ARRAY_SIZE(ar9287PciePhy_clkreq_off_L1_9287_1_1), 2);
		else
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9287PciePhy_clkreq_always_on_L1_9287_1_1,
			ARRAY_SIZE(ar9287PciePhy_clkreq_always_on_L1_9287_1_1),
					2);
	} else if (AR_SREV_9287_10_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar9287Modes_9287_1_0,
				ARRAY_SIZE(ar9287Modes_9287_1_0), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar9287Common_9287_1_0,
				ARRAY_SIZE(ar9287Common_9287_1_0), 2);

		if (ah->config.pcie_clock_req)
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9287PciePhy_clkreq_off_L1_9287_1_0,
			ARRAY_SIZE(ar9287PciePhy_clkreq_off_L1_9287_1_0), 2);
		else
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9287PciePhy_clkreq_always_on_L1_9287_1_0,
			ARRAY_SIZE(ar9287PciePhy_clkreq_always_on_L1_9287_1_0),
				  2);
	} else if (AR_SREV_9285_12_OR_LATER(ah)) {


		INIT_INI_ARRAY(&ah->iniModes, ar9285Modes_9285_1_2,
			       ARRAY_SIZE(ar9285Modes_9285_1_2), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar9285Common_9285_1_2,
			       ARRAY_SIZE(ar9285Common_9285_1_2), 2);

		if (ah->config.pcie_clock_req) {
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9285PciePhy_clkreq_off_L1_9285_1_2,
			ARRAY_SIZE(ar9285PciePhy_clkreq_off_L1_9285_1_2), 2);
		} else {
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9285PciePhy_clkreq_always_on_L1_9285_1_2,
			ARRAY_SIZE(ar9285PciePhy_clkreq_always_on_L1_9285_1_2),
				  2);
		}
	} else if (AR_SREV_9285_10_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar9285Modes_9285,
			       ARRAY_SIZE(ar9285Modes_9285), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar9285Common_9285,
			       ARRAY_SIZE(ar9285Common_9285), 2);

		if (ah->config.pcie_clock_req) {
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9285PciePhy_clkreq_off_L1_9285,
			ARRAY_SIZE(ar9285PciePhy_clkreq_off_L1_9285), 2);
		} else {
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			ar9285PciePhy_clkreq_always_on_L1_9285,
			ARRAY_SIZE(ar9285PciePhy_clkreq_always_on_L1_9285), 2);
		}
	} else if (AR_SREV_9280_20_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar9280Modes_9280_2,
			       ARRAY_SIZE(ar9280Modes_9280_2), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar9280Common_9280_2,
			       ARRAY_SIZE(ar9280Common_9280_2), 2);

		if (ah->config.pcie_clock_req) {
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			       ar9280PciePhy_clkreq_off_L1_9280,
			       ARRAY_SIZE(ar9280PciePhy_clkreq_off_L1_9280),2);
		} else {
			INIT_INI_ARRAY(&ah->iniPcieSerdes,
			       ar9280PciePhy_clkreq_always_on_L1_9280,
			       ARRAY_SIZE(ar9280PciePhy_clkreq_always_on_L1_9280), 2);
		}
		INIT_INI_ARRAY(&ah->iniModesAdditional,
			       ar9280Modes_fast_clock_9280_2,
			       ARRAY_SIZE(ar9280Modes_fast_clock_9280_2), 3);
	} else if (AR_SREV_9280_10_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar9280Modes_9280,
			       ARRAY_SIZE(ar9280Modes_9280), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar9280Common_9280,
			       ARRAY_SIZE(ar9280Common_9280), 2);
	} else if (AR_SREV_9160_10_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar5416Modes_9160,
			       ARRAY_SIZE(ar5416Modes_9160), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar5416Common_9160,
			       ARRAY_SIZE(ar5416Common_9160), 2);
		INIT_INI_ARRAY(&ah->iniBank0, ar5416Bank0_9160,
			       ARRAY_SIZE(ar5416Bank0_9160), 2);
		INIT_INI_ARRAY(&ah->iniBB_RfGain, ar5416BB_RfGain_9160,
			       ARRAY_SIZE(ar5416BB_RfGain_9160), 3);
		INIT_INI_ARRAY(&ah->iniBank1, ar5416Bank1_9160,
			       ARRAY_SIZE(ar5416Bank1_9160), 2);
		INIT_INI_ARRAY(&ah->iniBank2, ar5416Bank2_9160,
			       ARRAY_SIZE(ar5416Bank2_9160), 2);
		INIT_INI_ARRAY(&ah->iniBank3, ar5416Bank3_9160,
			       ARRAY_SIZE(ar5416Bank3_9160), 3);
		INIT_INI_ARRAY(&ah->iniBank6, ar5416Bank6_9160,
			       ARRAY_SIZE(ar5416Bank6_9160), 3);
		INIT_INI_ARRAY(&ah->iniBank6TPC, ar5416Bank6TPC_9160,
			       ARRAY_SIZE(ar5416Bank6TPC_9160), 3);
		INIT_INI_ARRAY(&ah->iniBank7, ar5416Bank7_9160,
			       ARRAY_SIZE(ar5416Bank7_9160), 2);
		if (AR_SREV_9160_11(ah)) {
			INIT_INI_ARRAY(&ah->iniAddac,
				       ar5416Addac_91601_1,
				       ARRAY_SIZE(ar5416Addac_91601_1), 2);
		} else {
			INIT_INI_ARRAY(&ah->iniAddac, ar5416Addac_9160,
				       ARRAY_SIZE(ar5416Addac_9160), 2);
		}
	} else if (AR_SREV_9100_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModes, ar5416Modes_9100,
			       ARRAY_SIZE(ar5416Modes_9100), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar5416Common_9100,
			       ARRAY_SIZE(ar5416Common_9100), 2);
		INIT_INI_ARRAY(&ah->iniBank0, ar5416Bank0_9100,
			       ARRAY_SIZE(ar5416Bank0_9100), 2);
		INIT_INI_ARRAY(&ah->iniBB_RfGain, ar5416BB_RfGain_9100,
			       ARRAY_SIZE(ar5416BB_RfGain_9100), 3);
		INIT_INI_ARRAY(&ah->iniBank1, ar5416Bank1_9100,
			       ARRAY_SIZE(ar5416Bank1_9100), 2);
		INIT_INI_ARRAY(&ah->iniBank2, ar5416Bank2_9100,
			       ARRAY_SIZE(ar5416Bank2_9100), 2);
		INIT_INI_ARRAY(&ah->iniBank3, ar5416Bank3_9100,
			       ARRAY_SIZE(ar5416Bank3_9100), 3);
		INIT_INI_ARRAY(&ah->iniBank6, ar5416Bank6_9100,
			       ARRAY_SIZE(ar5416Bank6_9100), 3);
		INIT_INI_ARRAY(&ah->iniBank6TPC, ar5416Bank6TPC_9100,
			       ARRAY_SIZE(ar5416Bank6TPC_9100), 3);
		INIT_INI_ARRAY(&ah->iniBank7, ar5416Bank7_9100,
			       ARRAY_SIZE(ar5416Bank7_9100), 2);
		INIT_INI_ARRAY(&ah->iniAddac, ar5416Addac_9100,
			       ARRAY_SIZE(ar5416Addac_9100), 2);
	} else {
		INIT_INI_ARRAY(&ah->iniModes, ar5416Modes,
			       ARRAY_SIZE(ar5416Modes), 6);
		INIT_INI_ARRAY(&ah->iniCommon, ar5416Common,
			       ARRAY_SIZE(ar5416Common), 2);
		INIT_INI_ARRAY(&ah->iniBank0, ar5416Bank0,
			       ARRAY_SIZE(ar5416Bank0), 2);
		INIT_INI_ARRAY(&ah->iniBB_RfGain, ar5416BB_RfGain,
			       ARRAY_SIZE(ar5416BB_RfGain), 3);
		INIT_INI_ARRAY(&ah->iniBank1, ar5416Bank1,
			       ARRAY_SIZE(ar5416Bank1), 2);
		INIT_INI_ARRAY(&ah->iniBank2, ar5416Bank2,
			       ARRAY_SIZE(ar5416Bank2), 2);
		INIT_INI_ARRAY(&ah->iniBank3, ar5416Bank3,
			       ARRAY_SIZE(ar5416Bank3), 3);
		INIT_INI_ARRAY(&ah->iniBank6, ar5416Bank6,
			       ARRAY_SIZE(ar5416Bank6), 3);
		INIT_INI_ARRAY(&ah->iniBank6TPC, ar5416Bank6TPC,
			       ARRAY_SIZE(ar5416Bank6TPC), 3);
		INIT_INI_ARRAY(&ah->iniBank7, ar5416Bank7,
			       ARRAY_SIZE(ar5416Bank7), 2);
		INIT_INI_ARRAY(&ah->iniAddac, ar5416Addac,
			       ARRAY_SIZE(ar5416Addac), 2);
	}
}

static void ath9k_hw_init_mode_gain_regs(struct ath_hw *ah)
{
	if (AR_SREV_9287_11_OR_LATER(ah))
		INIT_INI_ARRAY(&ah->iniModesRxGain,
		ar9287Modes_rx_gain_9287_1_1,
		ARRAY_SIZE(ar9287Modes_rx_gain_9287_1_1), 6);
	else if (AR_SREV_9287_10(ah))
		INIT_INI_ARRAY(&ah->iniModesRxGain,
		ar9287Modes_rx_gain_9287_1_0,
		ARRAY_SIZE(ar9287Modes_rx_gain_9287_1_0), 6);
	else if (AR_SREV_9280_20(ah))
		ath9k_hw_init_rxgain_ini(ah);

	if (AR_SREV_9287_11_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniModesTxGain,
		ar9287Modes_tx_gain_9287_1_1,
		ARRAY_SIZE(ar9287Modes_tx_gain_9287_1_1), 6);
	} else if (AR_SREV_9287_10(ah)) {
		INIT_INI_ARRAY(&ah->iniModesTxGain,
		ar9287Modes_tx_gain_9287_1_0,
		ARRAY_SIZE(ar9287Modes_tx_gain_9287_1_0), 6);
	} else if (AR_SREV_9280_20(ah)) {
		ath9k_hw_init_txgain_ini(ah);
	} else if (AR_SREV_9285_12_OR_LATER(ah)) {
		u32 txgain_type = ah->eep_ops->get_eeprom(ah, EEP_TXGAIN_TYPE);

		/* txgain table */
		if (txgain_type == AR5416_EEP_TXGAIN_HIGH_POWER) {
			INIT_INI_ARRAY(&ah->iniModesTxGain,
			ar9285Modes_high_power_tx_gain_9285_1_2,
			ARRAY_SIZE(ar9285Modes_high_power_tx_gain_9285_1_2), 6);
		} else {
			INIT_INI_ARRAY(&ah->iniModesTxGain,
			ar9285Modes_original_tx_gain_9285_1_2,
			ARRAY_SIZE(ar9285Modes_original_tx_gain_9285_1_2), 6);
		}

	}
}

static void ath9k_hw_init_eeprom_fix(struct ath_hw *ah)
{
	u32 i, j;

	if (ah->hw_version.devid == AR9280_DEVID_PCI) {

		/* EEPROM Fixup */
		for (i = 0; i < ah->iniModes.ia_rows; i++) {
			u32 reg = INI_RA(&ah->iniModes, i, 0);

			for (j = 1; j < ah->iniModes.ia_columns; j++) {
				u32 val = INI_RA(&ah->iniModes, i, j);

				INI_RA(&ah->iniModes, i, j) =
					ath9k_hw_ini_fixup(ah,
							   &ah->eeprom.def,
							   reg, val);
			}
		}
	}
}

int ath9k_hw_init(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);
	int r = 0;

	if (!ath9k_hw_devid_supported(ah->hw_version.devid)) {
		ath_print(common, ATH_DBG_FATAL,
			  "Unsupported device ID: 0x%0x\n",
			  ah->hw_version.devid);
		return -EOPNOTSUPP;
	}

	ath9k_hw_init_defaults(ah);
	ath9k_hw_init_config(ah);

	if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_POWER_ON)) {
		ath_print(common, ATH_DBG_FATAL,
			  "Couldn't reset chip\n");
		return -EIO;
	}

	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE)) {
		ath_print(common, ATH_DBG_FATAL, "Couldn't wakeup chip\n");
		return -EIO;
	}

	if (ah->config.serialize_regmode == SER_REG_MODE_AUTO) {
		if (ah->hw_version.macVersion == AR_SREV_VERSION_5416_PCI ||
		    (AR_SREV_9280(ah) && !ah->is_pciexpress)) {
			ah->config.serialize_regmode =
				SER_REG_MODE_ON;
		} else {
			ah->config.serialize_regmode =
				SER_REG_MODE_OFF;
		}
	}

	ath_print(common, ATH_DBG_RESET, "serialize_regmode is %d\n",
		ah->config.serialize_regmode);

	if (AR_SREV_9285(ah) || AR_SREV_9271(ah))
		ah->config.max_txtrig_level = MAX_TX_FIFO_THRESHOLD >> 1;
	else
		ah->config.max_txtrig_level = MAX_TX_FIFO_THRESHOLD;

	if (!ath9k_hw_macversion_supported(ah->hw_version.macVersion)) {
		ath_print(common, ATH_DBG_FATAL,
			  "Mac Chip Rev 0x%02x.%x is not supported by "
			  "this driver\n", ah->hw_version.macVersion,
			  ah->hw_version.macRev);
		return -EOPNOTSUPP;
	}

	if (AR_SREV_9100(ah)) {
		ah->iq_caldata.calData = &iq_cal_multi_sample;
		ah->supp_cals = IQ_MISMATCH_CAL;
		ah->is_pciexpress = false;
	}

	if (AR_SREV_9271(ah))
		ah->is_pciexpress = false;

	ah->hw_version.phyRev = REG_READ(ah, AR_PHY_CHIP_ID);

	ath9k_hw_init_cal_settings(ah);

	ah->ani_function = ATH9K_ANI_ALL;
	if (AR_SREV_9280_10_OR_LATER(ah)) {
		ah->ani_function &= ~ATH9K_ANI_NOISE_IMMUNITY_LEVEL;
		ah->ath9k_hw_rf_set_freq = &ath9k_hw_ar9280_set_channel;
		ah->ath9k_hw_spur_mitigate_freq = &ath9k_hw_9280_spur_mitigate;
	} else {
		ah->ath9k_hw_rf_set_freq = &ath9k_hw_set_channel;
		ah->ath9k_hw_spur_mitigate_freq = &ath9k_hw_spur_mitigate;
	}

	ath9k_hw_init_mode_regs(ah);

	if (ah->is_pciexpress)
		ath9k_hw_configpcipowersave(ah, 0, 0);
	else
		ath9k_hw_disablepcie(ah);

	/* Support for Japan ch.14 (2484) spread */
	if (AR_SREV_9287_11_OR_LATER(ah)) {
		INIT_INI_ARRAY(&ah->iniCckfirNormal,
		       ar9287Common_normal_cck_fir_coeff_92871_1,
		       ARRAY_SIZE(ar9287Common_normal_cck_fir_coeff_92871_1), 2);
		INIT_INI_ARRAY(&ah->iniCckfirJapan2484,
		       ar9287Common_japan_2484_cck_fir_coeff_92871_1,
		       ARRAY_SIZE(ar9287Common_japan_2484_cck_fir_coeff_92871_1), 2);
	}

	r = ath9k_hw_post_init(ah);
	if (r)
		return r;

	ath9k_hw_init_mode_gain_regs(ah);
	r = ath9k_hw_fill_cap_info(ah);
	if (r)
		return r;

	ath9k_hw_init_eeprom_fix(ah);

	r = ath9k_hw_init_macaddr(ah);
	if (r) {
		ath_print(common, ATH_DBG_FATAL,
			  "Failed to initialize MAC address\n");
		return r;
	}

	if (AR_SREV_9285(ah) || AR_SREV_9271(ah))
		ah->tx_trig_level = (AR_FTRIG_256B >> AR_FTRIG_S);
	else
		ah->tx_trig_level = (AR_FTRIG_512B >> AR_FTRIG_S);

	ath9k_init_nfcal_hist_buffer(ah);

	common->state = ATH_HW_INITIALIZED;

	return 0;
}

static void ath9k_hw_init_bb(struct ath_hw *ah,
			     struct ath9k_channel *chan)
{
	u32 synthDelay;

	synthDelay = REG_READ(ah, AR_PHY_RX_DELAY) & AR_PHY_RX_DELAY_DELAY;
	if (IS_CHAN_B(chan))
		synthDelay = (4 * synthDelay) / 22;
	else
		synthDelay /= 10;

	REG_WRITE(ah, AR_PHY_ACTIVE, AR_PHY_ACTIVE_EN);

	udelay(synthDelay + BASE_ACTIVATE_DELAY);
}

static void ath9k_hw_init_qos(struct ath_hw *ah)
{
	REG_WRITE(ah, AR_MIC_QOS_CONTROL, 0x100aa);
	REG_WRITE(ah, AR_MIC_QOS_SELECT, 0x3210);

	REG_WRITE(ah, AR_QOS_NO_ACK,
		  SM(2, AR_QOS_NO_ACK_TWO_BIT) |
		  SM(5, AR_QOS_NO_ACK_BIT_OFF) |
		  SM(0, AR_QOS_NO_ACK_BYTE_OFF));

	REG_WRITE(ah, AR_TXOP_X, AR_TXOP_X_VAL);
	REG_WRITE(ah, AR_TXOP_0_3, 0xFFFFFFFF);
	REG_WRITE(ah, AR_TXOP_4_7, 0xFFFFFFFF);
	REG_WRITE(ah, AR_TXOP_8_11, 0xFFFFFFFF);
	REG_WRITE(ah, AR_TXOP_12_15, 0xFFFFFFFF);
}

static void ath9k_hw_change_target_baud(struct ath_hw *ah, u32 freq, u32 baud)
{
	u32 lcr;
	u32 baud_divider = freq * 1000 * 1000 / 16 / baud;

	lcr = REG_READ(ah , 0x5100c);
	lcr |= 0x80;

	REG_WRITE(ah, 0x5100c, lcr);
	REG_WRITE(ah, 0x51004, (baud_divider >> 8));
	REG_WRITE(ah, 0x51000, (baud_divider & 0xff));

	lcr &= ~0x80;
	REG_WRITE(ah, 0x5100c, lcr);
}

static void ath9k_hw_init_pll(struct ath_hw *ah,
			      struct ath9k_channel *chan)
{
	u32 pll;

	if (AR_SREV_9100(ah)) {
		if (chan && IS_CHAN_5GHZ(chan))
			pll = 0x1450;
		else
			pll = 0x1458;
	} else {
		if (AR_SREV_9280_10_OR_LATER(ah)) {
			pll = SM(0x5, AR_RTC_9160_PLL_REFDIV);

			if (chan && IS_CHAN_HALF_RATE(chan))
				pll |= SM(0x1, AR_RTC_9160_PLL_CLKSEL);
			else if (chan && IS_CHAN_QUARTER_RATE(chan))
				pll |= SM(0x2, AR_RTC_9160_PLL_CLKSEL);

			if (chan && IS_CHAN_5GHZ(chan)) {
				pll |= SM(0x28, AR_RTC_9160_PLL_DIV);


				if (AR_SREV_9280_20(ah)) {
					if (((chan->channel % 20) == 0)
					    || ((chan->channel % 10) == 0))
						pll = 0x2850;
					else
						pll = 0x142c;
				}
			} else {
				pll |= SM(0x2c, AR_RTC_9160_PLL_DIV);
			}

		} else if (AR_SREV_9160_10_OR_LATER(ah)) {

			pll = SM(0x5, AR_RTC_9160_PLL_REFDIV);

			if (chan && IS_CHAN_HALF_RATE(chan))
				pll |= SM(0x1, AR_RTC_9160_PLL_CLKSEL);
			else if (chan && IS_CHAN_QUARTER_RATE(chan))
				pll |= SM(0x2, AR_RTC_9160_PLL_CLKSEL);

			if (chan && IS_CHAN_5GHZ(chan))
				pll |= SM(0x50, AR_RTC_9160_PLL_DIV);
			else
				pll |= SM(0x58, AR_RTC_9160_PLL_DIV);
		} else {
			pll = AR_RTC_PLL_REFDIV_5 | AR_RTC_PLL_DIV2;

			if (chan && IS_CHAN_HALF_RATE(chan))
				pll |= SM(0x1, AR_RTC_PLL_CLKSEL);
			else if (chan && IS_CHAN_QUARTER_RATE(chan))
				pll |= SM(0x2, AR_RTC_PLL_CLKSEL);

			if (chan && IS_CHAN_5GHZ(chan))
				pll |= SM(0xa, AR_RTC_PLL_DIV);
			else
				pll |= SM(0xb, AR_RTC_PLL_DIV);
		}
	}
	REG_WRITE(ah, AR_RTC_PLL_CONTROL, pll);

	/* Switch the core clock for ar9271 to 117Mhz */
	if (AR_SREV_9271(ah)) {
		if ((pll == 0x142c) || (pll == 0x2850) ) {
			udelay(500);
			/* set CLKOBS to output AHB clock */
			REG_WRITE(ah, 0x7020, 0xe);
			/*
			 * 0x304: 117Mhz, ahb_ratio: 1x1
			 * 0x306: 40Mhz, ahb_ratio: 1x1
			 */
			REG_WRITE(ah, 0x50040, 0x304);
			/*
			 * makes adjustments for the baud dividor to keep the
			 * targetted baud rate based on the used core clock.
			 */
			ath9k_hw_change_target_baud(ah, AR9271_CORE_CLOCK,
						    AR9271_TARGET_BAUD_RATE);
		}
	}

	udelay(RTC_PLL_SETTLE_DELAY);

	REG_WRITE(ah, AR_RTC_SLEEP_CLK, AR_RTC_FORCE_DERIVED_CLK);
}

static void ath9k_hw_init_chain_masks(struct ath_hw *ah)
{
	int rx_chainmask, tx_chainmask;

	rx_chainmask = ah->rxchainmask;
	tx_chainmask = ah->txchainmask;

	switch (rx_chainmask) {
	case 0x5:
		REG_SET_BIT(ah, AR_PHY_ANALOG_SWAP,
			    AR_PHY_SWAP_ALT_CHAIN);
	case 0x3:
		if (ah->hw_version.macVersion == AR_SREV_REVISION_5416_10) {
			REG_WRITE(ah, AR_PHY_RX_CHAINMASK, 0x7);
			REG_WRITE(ah, AR_PHY_CAL_CHAINMASK, 0x7);
			break;
		}
	case 0x1:
	case 0x2:
	case 0x7:
		REG_WRITE(ah, AR_PHY_RX_CHAINMASK, rx_chainmask);
		REG_WRITE(ah, AR_PHY_CAL_CHAINMASK, rx_chainmask);
		break;
	default:
		break;
	}

	REG_WRITE(ah, AR_SELFGEN_MASK, tx_chainmask);
	if (tx_chainmask == 0x5) {
		REG_SET_BIT(ah, AR_PHY_ANALOG_SWAP,
			    AR_PHY_SWAP_ALT_CHAIN);
	}
	if (AR_SREV_9100(ah))
		REG_WRITE(ah, AR_PHY_ANALOG_SWAP,
			  REG_READ(ah, AR_PHY_ANALOG_SWAP) | 0x00000001);
}

static void ath9k_hw_init_interrupt_masks(struct ath_hw *ah,
					  enum nl80211_iftype opmode)
{
	ah->mask_reg = AR_IMR_TXERR |
		AR_IMR_TXURN |
		AR_IMR_RXERR |
		AR_IMR_RXORN |
		AR_IMR_BCNMISC;

	if (ah->config.rx_intr_mitigation)
		ah->mask_reg |= AR_IMR_RXINTM | AR_IMR_RXMINTR;
	else
		ah->mask_reg |= AR_IMR_RXOK;

	ah->mask_reg |= AR_IMR_TXOK;

	if (opmode == NL80211_IFTYPE_AP)
		ah->mask_reg |= AR_IMR_MIB;

	REG_WRITE(ah, AR_IMR, ah->mask_reg);
	REG_WRITE(ah, AR_IMR_S2, REG_READ(ah, AR_IMR_S2) | AR_IMR_S2_GTT);

	if (!AR_SREV_9100(ah)) {
		REG_WRITE(ah, AR_INTR_SYNC_CAUSE, 0xFFFFFFFF);
		REG_WRITE(ah, AR_INTR_SYNC_ENABLE, AR_INTR_SYNC_DEFAULT);
		REG_WRITE(ah, AR_INTR_SYNC_MASK, 0);
	}
}

static void ath9k_hw_setslottime(struct ath_hw *ah, u32 us)
{
	u32 val = ath9k_hw_mac_to_clks(ah, us);
	val = min(val, (u32) 0xFFFF);
	REG_WRITE(ah, AR_D_GBL_IFS_SLOT, val);
}

static void ath9k_hw_set_ack_timeout(struct ath_hw *ah, u32 us)
{
	u32 val = ath9k_hw_mac_to_clks(ah, us);
	val = min(val, (u32) MS(0xFFFFFFFF, AR_TIME_OUT_ACK));
	REG_RMW_FIELD(ah, AR_TIME_OUT, AR_TIME_OUT_ACK, val);
}

static void ath9k_hw_set_cts_timeout(struct ath_hw *ah, u32 us)
{
	u32 val = ath9k_hw_mac_to_clks(ah, us);
	val = min(val, (u32) MS(0xFFFFFFFF, AR_TIME_OUT_CTS));
	REG_RMW_FIELD(ah, AR_TIME_OUT, AR_TIME_OUT_CTS, val);
}

static bool ath9k_hw_set_global_txtimeout(struct ath_hw *ah, u32 tu)
{
	if (tu > 0xFFFF) {
		ath_print(ath9k_hw_common(ah), ATH_DBG_XMIT,
			  "bad global tx timeout %u\n", tu);
		ah->globaltxtimeout = (u32) -1;
		return false;
	} else {
		REG_RMW_FIELD(ah, AR_GTXTO, AR_GTXTO_TIMEOUT_LIMIT, tu);
		ah->globaltxtimeout = tu;
		return true;
	}
}

void ath9k_hw_init_global_settings(struct ath_hw *ah)
{
	struct ieee80211_conf *conf = &ath9k_hw_common(ah)->hw->conf;
	int acktimeout;
	int slottime;
	int sifstime;

	ath_print(ath9k_hw_common(ah), ATH_DBG_RESET, "ah->misc_mode 0x%x\n",
		  ah->misc_mode);

	if (ah->misc_mode != 0)
		REG_WRITE(ah, AR_PCU_MISC,
			  REG_READ(ah, AR_PCU_MISC) | ah->misc_mode);

	if (conf->channel && conf->channel->band == IEEE80211_BAND_5GHZ)
		sifstime = 16;
	else
		sifstime = 10;

	/* As defined by IEEE 802.11-2007 17.3.8.6 */
	slottime = ah->slottime + 3 * ah->coverage_class;
	acktimeout = slottime + sifstime;

	/*
	 * Workaround for early ACK timeouts, add an offset to match the
	 * initval's 64us ack timeout value.
	 * This was initially only meant to work around an issue with delayed
	 * BA frames in some implementations, but it has been found to fix ACK
	 * timeout issues in other cases as well.
	 */
	if (conf->channel && conf->channel->band == IEEE80211_BAND_2GHZ)
		acktimeout += 64 - sifstime - ah->slottime;

	ath9k_hw_setslottime(ah, slottime);
	ath9k_hw_set_ack_timeout(ah, acktimeout);
	ath9k_hw_set_cts_timeout(ah, acktimeout);
	if (ah->globaltxtimeout != (u32) -1)
		ath9k_hw_set_global_txtimeout(ah, ah->globaltxtimeout);
}
EXPORT_SYMBOL(ath9k_hw_init_global_settings);

void ath9k_hw_deinit(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);

	if (common->state <= ATH_HW_INITIALIZED)
		goto free_hw;

	if (!AR_SREV_9100(ah))
		ath9k_hw_ani_disable(ah);

	ath9k_hw_setpower(ah, ATH9K_PM_FULL_SLEEP);

free_hw:
	if (!AR_SREV_9280_10_OR_LATER(ah))
		ath9k_hw_rf_free_ext_banks(ah);
	kfree(ah);
	ah = NULL;
}
EXPORT_SYMBOL(ath9k_hw_deinit);

/*******/
/* INI */
/*******/

static void ath9k_hw_override_ini(struct ath_hw *ah,
				  struct ath9k_channel *chan)
{
	u32 val;

	if (AR_SREV_9271(ah)) {
		/*
		 * Enable spectral scan to solution for issues with stuck
		 * beacons on AR9271 1.0. The beacon stuck issue is not seeon on
		 * AR9271 1.1
		 */
		if (AR_SREV_9271_10(ah)) {
			val = REG_READ(ah, AR_PHY_SPECTRAL_SCAN) |
			      AR_PHY_SPECTRAL_SCAN_ENABLE;
			REG_WRITE(ah, AR_PHY_SPECTRAL_SCAN, val);
		}
		else if (AR_SREV_9271_11(ah))
			/*
			 * change AR_PHY_RF_CTL3 setting to fix MAC issue
			 * present on AR9271 1.1
			 */
			REG_WRITE(ah, AR_PHY_RF_CTL3, 0x3a020001);
		return;
	}

	/*
	 * Set the RX_ABORT and RX_DIS and clear if off only after
	 * RXE is set for MAC. This prevents frames with corrupted
	 * descriptor status.
	 */
	REG_SET_BIT(ah, AR_DIAG_SW, (AR_DIAG_RX_DIS | AR_DIAG_RX_ABORT));

	if (AR_SREV_9280_10_OR_LATER(ah)) {
		val = REG_READ(ah, AR_PCU_MISC_MODE2) &
			       (~AR_PCU_MISC_MODE2_HWWAR1);

		if (AR_SREV_9287_10_OR_LATER(ah))
			val = val & (~AR_PCU_MISC_MODE2_HWWAR2);

		REG_WRITE(ah, AR_PCU_MISC_MODE2, val);
	}

	if (!AR_SREV_5416_20_OR_LATER(ah) ||
	    AR_SREV_9280_10_OR_LATER(ah))
		return;
	/*
	 * Disable BB clock gating
	 * Necessary to avoid issues on AR5416 2.0
	 */
	REG_WRITE(ah, 0x9800 + (651 << 2), 0x11);

	/*
	 * Disable RIFS search on some chips to avoid baseband
	 * hang issues.
	 */
	if (AR_SREV_9100(ah) || AR_SREV_9160(ah)) {
		val = REG_READ(ah, AR_PHY_HEAVY_CLIP_FACTOR_RIFS);
		val &= ~AR_PHY_RIFS_INIT_DELAY;
		REG_WRITE(ah, AR_PHY_HEAVY_CLIP_FACTOR_RIFS, val);
	}
}

static u32 ath9k_hw_def_ini_fixup(struct ath_hw *ah,
			      struct ar5416_eeprom_def *pEepData,
			      u32 reg, u32 value)
{
	struct base_eep_header *pBase = &(pEepData->baseEepHeader);
	struct ath_common *common = ath9k_hw_common(ah);

	switch (ah->hw_version.devid) {
	case AR9280_DEVID_PCI:
		if (reg == 0x7894) {
			ath_print(common, ATH_DBG_EEPROM,
				"ini VAL: %x  EEPROM: %x\n", value,
				(pBase->version & 0xff));

			if ((pBase->version & 0xff) > 0x0a) {
				ath_print(common, ATH_DBG_EEPROM,
					  "PWDCLKIND: %d\n",
					  pBase->pwdclkind);
				value &= ~AR_AN_TOP2_PWDCLKIND;
				value |= AR_AN_TOP2_PWDCLKIND &
					(pBase->pwdclkind << AR_AN_TOP2_PWDCLKIND_S);
			} else {
				ath_print(common, ATH_DBG_EEPROM,
					  "PWDCLKIND Earlier Rev\n");
			}

			ath_print(common, ATH_DBG_EEPROM,
				  "final ini VAL: %x\n", value);
		}
		break;
	}

	return value;
}

static u32 ath9k_hw_ini_fixup(struct ath_hw *ah,
			      struct ar5416_eeprom_def *pEepData,
			      u32 reg, u32 value)
{
	if (ah->eep_map == EEP_MAP_4KBITS)
		return value;
	else
		return ath9k_hw_def_ini_fixup(ah, pEepData, reg, value);
}

static void ath9k_olc_init(struct ath_hw *ah)
{
	u32 i;

	if (OLC_FOR_AR9287_10_LATER) {
		REG_SET_BIT(ah, AR_PHY_TX_PWRCTRL9,
				AR_PHY_TX_PWRCTRL9_RES_DC_REMOVAL);
		ath9k_hw_analog_shift_rmw(ah, AR9287_AN_TXPC0,
				AR9287_AN_TXPC0_TXPCMODE,
				AR9287_AN_TXPC0_TXPCMODE_S,
				AR9287_AN_TXPC0_TXPCMODE_TEMPSENSE);
		udelay(100);
	} else {
		for (i = 0; i < AR9280_TX_GAIN_TABLE_SIZE; i++)
			ah->originalGain[i] =
				MS(REG_READ(ah, AR_PHY_TX_GAIN_TBL1 + i * 4),
						AR_PHY_TX_GAIN);
		ah->PDADCdelta = 0;
	}
}

static u32 ath9k_regd_get_ctl(struct ath_regulatory *reg,
			      struct ath9k_channel *chan)
{
	u32 ctl = ath_regd_get_band_ctl(reg, chan->chan->band);

	if (IS_CHAN_B(chan))
		ctl |= CTL_11B;
	else if (IS_CHAN_G(chan))
		ctl |= CTL_11G;
	else
		ctl |= CTL_11A;

	return ctl;
}

static int ath9k_hw_process_ini(struct ath_hw *ah,
				struct ath9k_channel *chan)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	int i, regWrites = 0;
	struct ieee80211_channel *channel = chan->chan;
	u32 modesIndex, freqIndex;

	switch (chan->chanmode) {
	case CHANNEL_A:
	case CHANNEL_A_HT20:
		modesIndex = 1;
		freqIndex = 1;
		break;
	case CHANNEL_A_HT40PLUS:
	case CHANNEL_A_HT40MINUS:
		modesIndex = 2;
		freqIndex = 1;
		break;
	case CHANNEL_G:
	case CHANNEL_G_HT20:
	case CHANNEL_B:
		modesIndex = 4;
		freqIndex = 2;
		break;
	case CHANNEL_G_HT40PLUS:
	case CHANNEL_G_HT40MINUS:
		modesIndex = 3;
		freqIndex = 2;
		break;

	default:
		return -EINVAL;
	}

	REG_WRITE(ah, AR_PHY(0), 0x00000007);
	REG_WRITE(ah, AR_PHY_ADC_SERIAL_CTL, AR_PHY_SEL_EXTERNAL_RADIO);
	ah->eep_ops->set_addac(ah, chan);

	if (AR_SREV_5416_22_OR_LATER(ah)) {
		REG_WRITE_ARRAY(&ah->iniAddac, 1, regWrites);
	} else {
		struct ar5416IniArray temp;
		u32 addacSize =
			sizeof(u32) * ah->iniAddac.ia_rows *
			ah->iniAddac.ia_columns;

		memcpy(ah->addac5416_21,
		       ah->iniAddac.ia_array, addacSize);

		(ah->addac5416_21)[31 * ah->iniAddac.ia_columns + 1] = 0;

		temp.ia_array = ah->addac5416_21;
		temp.ia_columns = ah->iniAddac.ia_columns;
		temp.ia_rows = ah->iniAddac.ia_rows;
		REG_WRITE_ARRAY(&temp, 1, regWrites);
	}

	REG_WRITE(ah, AR_PHY_ADC_SERIAL_CTL, AR_PHY_SEL_INTERNAL_ADDAC);

	for (i = 0; i < ah->iniModes.ia_rows; i++) {
		u32 reg = INI_RA(&ah->iniModes, i, 0);
		u32 val = INI_RA(&ah->iniModes, i, modesIndex);

		REG_WRITE(ah, reg, val);

		if (reg >= 0x7800 && reg < 0x78a0
		    && ah->config.analog_shiftreg) {
			udelay(100);
		}

		DO_DELAY(regWrites);
	}

	if (AR_SREV_9280(ah) || AR_SREV_9287_10_OR_LATER(ah))
		REG_WRITE_ARRAY(&ah->iniModesRxGain, modesIndex, regWrites);

	if (AR_SREV_9280(ah) || AR_SREV_9285_12_OR_LATER(ah) ||
	    AR_SREV_9287_10_OR_LATER(ah))
		REG_WRITE_ARRAY(&ah->iniModesTxGain, modesIndex, regWrites);

	for (i = 0; i < ah->iniCommon.ia_rows; i++) {
		u32 reg = INI_RA(&ah->iniCommon, i, 0);
		u32 val = INI_RA(&ah->iniCommon, i, 1);

		REG_WRITE(ah, reg, val);

		if (reg >= 0x7800 && reg < 0x78a0
		    && ah->config.analog_shiftreg) {
			udelay(100);
		}

		DO_DELAY(regWrites);
	}

	ath9k_hw_write_regs(ah, freqIndex, regWrites);

	if (AR_SREV_9271_10(ah))
		REG_WRITE_ARRAY(&ah->iniModes_9271_1_0_only,
				modesIndex, regWrites);

	if (AR_SREV_9280_20(ah) && IS_CHAN_A_5MHZ_SPACED(chan)) {
		REG_WRITE_ARRAY(&ah->iniModesAdditional, modesIndex,
				regWrites);
	}

	ath9k_hw_override_ini(ah, chan);
	ath9k_hw_set_regs(ah, chan);
	ath9k_hw_init_chain_masks(ah);

	if (OLC_FOR_AR9280_20_LATER)
		ath9k_olc_init(ah);

	ah->eep_ops->set_txpower(ah, chan,
				 ath9k_regd_get_ctl(regulatory, chan),
				 channel->max_antenna_gain * 2,
				 channel->max_power * 2,
				 min((u32) MAX_RATE_POWER,
				 (u32) regulatory->power_limit));

	if (!ath9k_hw_set_rf_regs(ah, chan, freqIndex)) {
		ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
			  "ar5416SetRfRegs failed\n");
		return -EIO;
	}

	return 0;
}

/****************************************/
/* Reset and Channel Switching Routines */
/****************************************/

static void ath9k_hw_set_rfmode(struct ath_hw *ah, struct ath9k_channel *chan)
{
	u32 rfMode = 0;

	if (chan == NULL)
		return;

	rfMode |= (IS_CHAN_B(chan) || IS_CHAN_G(chan))
		? AR_PHY_MODE_DYNAMIC : AR_PHY_MODE_OFDM;

	if (!AR_SREV_9280_10_OR_LATER(ah))
		rfMode |= (IS_CHAN_5GHZ(chan)) ?
			AR_PHY_MODE_RF5GHZ : AR_PHY_MODE_RF2GHZ;

	if (AR_SREV_9280_20(ah) && IS_CHAN_A_5MHZ_SPACED(chan))
		rfMode |= (AR_PHY_MODE_DYNAMIC | AR_PHY_MODE_DYN_CCK_DISABLE);

	REG_WRITE(ah, AR_PHY_MODE, rfMode);
}

static void ath9k_hw_mark_phy_inactive(struct ath_hw *ah)
{
	REG_WRITE(ah, AR_PHY_ACTIVE, AR_PHY_ACTIVE_DIS);
}

static inline void ath9k_hw_set_dma(struct ath_hw *ah)
{
	u32 regval;

	/*
	 * set AHB_MODE not to do cacheline prefetches
	*/
	regval = REG_READ(ah, AR_AHB_MODE);
	REG_WRITE(ah, AR_AHB_MODE, regval | AR_AHB_PREFETCH_RD_EN);

	/*
	 * let mac dma reads be in 128 byte chunks
	 */
	regval = REG_READ(ah, AR_TXCFG) & ~AR_TXCFG_DMASZ_MASK;
	REG_WRITE(ah, AR_TXCFG, regval | AR_TXCFG_DMASZ_128B);

	/*
	 * Restore TX Trigger Level to its pre-reset value.
	 * The initial value depends on whether aggregation is enabled, and is
	 * adjusted whenever underruns are detected.
	 */
	REG_RMW_FIELD(ah, AR_TXCFG, AR_FTRIG, ah->tx_trig_level);

	/*
	 * let mac dma writes be in 128 byte chunks
	 */
	regval = REG_READ(ah, AR_RXCFG) & ~AR_RXCFG_DMASZ_MASK;
	REG_WRITE(ah, AR_RXCFG, regval | AR_RXCFG_DMASZ_128B);

	/*
	 * Setup receive FIFO threshold to hold off TX activities
	 */
	REG_WRITE(ah, AR_RXFIFO_CFG, 0x200);

	/*
	 * reduce the number of usable entries in PCU TXBUF to avoid
	 * wrap around issues.
	 */
	if (AR_SREV_9285(ah)) {
		/* For AR9285 the number of Fifos are reduced to half.
		 * So set the usable tx buf size also to half to
		 * avoid data/delimiter underruns
		 */
		REG_WRITE(ah, AR_PCU_TXBUF_CTRL,
			  AR_9285_PCU_TXBUF_CTRL_USABLE_SIZE);
	} else if (!AR_SREV_9271(ah)) {
		REG_WRITE(ah, AR_PCU_TXBUF_CTRL,
			  AR_PCU_TXBUF_CTRL_USABLE_SIZE);
	}
}

static void ath9k_hw_set_operating_mode(struct ath_hw *ah, int opmode)
{
	u32 val;

	val = REG_READ(ah, AR_STA_ID1);
	val &= ~(AR_STA_ID1_STA_AP | AR_STA_ID1_ADHOC);
	switch (opmode) {
	case NL80211_IFTYPE_AP:
		REG_WRITE(ah, AR_STA_ID1, val | AR_STA_ID1_STA_AP
			  | AR_STA_ID1_KSRCH_MODE);
		REG_CLR_BIT(ah, AR_CFG, AR_CFG_AP_ADHOC_INDICATION);
		break;
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_MESH_POINT:
		REG_WRITE(ah, AR_STA_ID1, val | AR_STA_ID1_ADHOC
			  | AR_STA_ID1_KSRCH_MODE);
		REG_SET_BIT(ah, AR_CFG, AR_CFG_AP_ADHOC_INDICATION);
		break;
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_MONITOR:
		REG_WRITE(ah, AR_STA_ID1, val | AR_STA_ID1_KSRCH_MODE);
		break;
	}
}

static inline void ath9k_hw_get_delta_slope_vals(struct ath_hw *ah,
						 u32 coef_scaled,
						 u32 *coef_mantissa,
						 u32 *coef_exponent)
{
	u32 coef_exp, coef_man;

	for (coef_exp = 31; coef_exp > 0; coef_exp--)
		if ((coef_scaled >> coef_exp) & 0x1)
			break;

	coef_exp = 14 - (coef_exp - COEF_SCALE_S);

	coef_man = coef_scaled + (1 << (COEF_SCALE_S - coef_exp - 1));

	*coef_mantissa = coef_man >> (COEF_SCALE_S - coef_exp);
	*coef_exponent = coef_exp - 16;
}

static void ath9k_hw_set_delta_slope(struct ath_hw *ah,
				     struct ath9k_channel *chan)
{
	u32 coef_scaled, ds_coef_exp, ds_coef_man;
	u32 clockMhzScaled = 0x64000000;
	struct chan_centers centers;

	if (IS_CHAN_HALF_RATE(chan))
		clockMhzScaled = clockMhzScaled >> 1;
	else if (IS_CHAN_QUARTER_RATE(chan))
		clockMhzScaled = clockMhzScaled >> 2;

	ath9k_hw_get_channel_centers(ah, chan, &centers);
	coef_scaled = clockMhzScaled / centers.synth_center;

	ath9k_hw_get_delta_slope_vals(ah, coef_scaled, &ds_coef_man,
				      &ds_coef_exp);

	REG_RMW_FIELD(ah, AR_PHY_TIMING3,
		      AR_PHY_TIMING3_DSC_MAN, ds_coef_man);
	REG_RMW_FIELD(ah, AR_PHY_TIMING3,
		      AR_PHY_TIMING3_DSC_EXP, ds_coef_exp);

	coef_scaled = (9 * coef_scaled) / 10;

	ath9k_hw_get_delta_slope_vals(ah, coef_scaled, &ds_coef_man,
				      &ds_coef_exp);

	REG_RMW_FIELD(ah, AR_PHY_HALFGI,
		      AR_PHY_HALFGI_DSC_MAN, ds_coef_man);
	REG_RMW_FIELD(ah, AR_PHY_HALFGI,
		      AR_PHY_HALFGI_DSC_EXP, ds_coef_exp);
}

static bool ath9k_hw_set_reset(struct ath_hw *ah, int type)
{
	u32 rst_flags;
	u32 tmpReg;

	if (AR_SREV_9100(ah)) {
		u32 val = REG_READ(ah, AR_RTC_DERIVED_CLK);
		val &= ~AR_RTC_DERIVED_CLK_PERIOD;
		val |= SM(1, AR_RTC_DERIVED_CLK_PERIOD);
		REG_WRITE(ah, AR_RTC_DERIVED_CLK, val);
		(void)REG_READ(ah, AR_RTC_DERIVED_CLK);
	}

	REG_WRITE(ah, AR_RTC_FORCE_WAKE, AR_RTC_FORCE_WAKE_EN |
		  AR_RTC_FORCE_WAKE_ON_INT);

	if (AR_SREV_9100(ah)) {
		rst_flags = AR_RTC_RC_MAC_WARM | AR_RTC_RC_MAC_COLD |
			AR_RTC_RC_COLD_RESET | AR_RTC_RC_WARM_RESET;
	} else {
		tmpReg = REG_READ(ah, AR_INTR_SYNC_CAUSE);
		if (tmpReg &
		    (AR_INTR_SYNC_LOCAL_TIMEOUT |
		     AR_INTR_SYNC_RADM_CPL_TIMEOUT)) {
			REG_WRITE(ah, AR_INTR_SYNC_ENABLE, 0);
			REG_WRITE(ah, AR_RC, AR_RC_AHB | AR_RC_HOSTIF);
		} else {
			REG_WRITE(ah, AR_RC, AR_RC_AHB);
		}

		rst_flags = AR_RTC_RC_MAC_WARM;
		if (type == ATH9K_RESET_COLD)
			rst_flags |= AR_RTC_RC_MAC_COLD;
	}

	REG_WRITE(ah, AR_RTC_RC, rst_flags);
	udelay(50);

	REG_WRITE(ah, AR_RTC_RC, 0);
	if (!ath9k_hw_wait(ah, AR_RTC_RC, AR_RTC_RC_M, 0, AH_WAIT_TIMEOUT)) {
		ath_print(ath9k_hw_common(ah), ATH_DBG_RESET,
			  "RTC stuck in MAC reset\n");
		return false;
	}

	if (!AR_SREV_9100(ah))
		REG_WRITE(ah, AR_RC, 0);

	if (AR_SREV_9100(ah))
		udelay(50);

	return true;
}

static bool ath9k_hw_set_reset_power_on(struct ath_hw *ah)
{
	REG_WRITE(ah, AR_RTC_FORCE_WAKE, AR_RTC_FORCE_WAKE_EN |
		  AR_RTC_FORCE_WAKE_ON_INT);

	if (!AR_SREV_9100(ah))
		REG_WRITE(ah, AR_RC, AR_RC_AHB);

	REG_WRITE(ah, AR_RTC_RESET, 0);
	udelay(2);

	if (!AR_SREV_9100(ah))
		REG_WRITE(ah, AR_RC, 0);

	REG_WRITE(ah, AR_RTC_RESET, 1);

	if (!ath9k_hw_wait(ah,
			   AR_RTC_STATUS,
			   AR_RTC_STATUS_M,
			   AR_RTC_STATUS_ON,
			   AH_WAIT_TIMEOUT)) {
		ath_print(ath9k_hw_common(ah), ATH_DBG_RESET,
			  "RTC not waking up\n");
		return false;
	}

	ath9k_hw_read_revisions(ah);

	return ath9k_hw_set_reset(ah, ATH9K_RESET_WARM);
}

static bool ath9k_hw_set_reset_reg(struct ath_hw *ah, u32 type)
{
	REG_WRITE(ah, AR_RTC_FORCE_WAKE,
		  AR_RTC_FORCE_WAKE_EN | AR_RTC_FORCE_WAKE_ON_INT);

	switch (type) {
	case ATH9K_RESET_POWER_ON:
		return ath9k_hw_set_reset_power_on(ah);
	case ATH9K_RESET_WARM:
	case ATH9K_RESET_COLD:
		return ath9k_hw_set_reset(ah, type);
	default:
		return false;
	}
}

static void ath9k_hw_set_regs(struct ath_hw *ah, struct ath9k_channel *chan)
{
	u32 phymode;
	u32 enableDacFifo = 0;

	if (AR_SREV_9285_10_OR_LATER(ah))
		enableDacFifo = (REG_READ(ah, AR_PHY_TURBO) &
					 AR_PHY_FC_ENABLE_DAC_FIFO);

	phymode = AR_PHY_FC_HT_EN | AR_PHY_FC_SHORT_GI_40
		| AR_PHY_FC_SINGLE_HT_LTF1 | AR_PHY_FC_WALSH | enableDacFifo;

	if (IS_CHAN_HT40(chan)) {
		phymode |= AR_PHY_FC_DYN2040_EN;

		if ((chan->chanmode == CHANNEL_A_HT40PLUS) ||
		    (chan->chanmode == CHANNEL_G_HT40PLUS))
			phymode |= AR_PHY_FC_DYN2040_PRI_CH;

	}
	REG_WRITE(ah, AR_PHY_TURBO, phymode);

	ath9k_hw_set11nmac2040(ah);

	REG_WRITE(ah, AR_GTXTO, 25 << AR_GTXTO_TIMEOUT_LIMIT_S);
	REG_WRITE(ah, AR_CST, 0xF << AR_CST_TIMEOUT_LIMIT_S);
}

static bool ath9k_hw_chip_reset(struct ath_hw *ah,
				struct ath9k_channel *chan)
{
	if (AR_SREV_9280(ah) && ah->eep_ops->get_eeprom(ah, EEP_OL_PWRCTRL)) {
		if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_POWER_ON))
			return false;
	} else if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_WARM))
		return false;

	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE))
		return false;

	ah->chip_fullsleep = false;
	ath9k_hw_init_pll(ah, chan);
	ath9k_hw_set_rfmode(ah, chan);

	return true;
}

static bool ath9k_hw_channel_change(struct ath_hw *ah,
				    struct ath9k_channel *chan)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	struct ath_common *common = ath9k_hw_common(ah);
	struct ieee80211_channel *channel = chan->chan;
	u32 synthDelay, qnum;
	int r;

	for (qnum = 0; qnum < AR_NUM_QCU; qnum++) {
		if (ath9k_hw_numtxpending(ah, qnum)) {
			ath_print(common, ATH_DBG_QUEUE,
				  "Transmit frames pending on "
				  "queue %d\n", qnum);
			return false;
		}
	}

	REG_WRITE(ah, AR_PHY_RFBUS_REQ, AR_PHY_RFBUS_REQ_EN);
	if (!ath9k_hw_wait(ah, AR_PHY_RFBUS_GRANT, AR_PHY_RFBUS_GRANT_EN,
			   AR_PHY_RFBUS_GRANT_EN, AH_WAIT_TIMEOUT)) {
		ath_print(common, ATH_DBG_FATAL,
			  "Could not kill baseband RX\n");
		return false;
	}

	ath9k_hw_set_regs(ah, chan);

	r = ah->ath9k_hw_rf_set_freq(ah, chan);
	if (r) {
		ath_print(common, ATH_DBG_FATAL,
			  "Failed to set channel\n");
		return false;
	}

	ah->eep_ops->set_txpower(ah, chan,
			     ath9k_regd_get_ctl(regulatory, chan),
			     channel->max_antenna_gain * 2,
			     channel->max_power * 2,
			     min((u32) MAX_RATE_POWER,
			     (u32) regulatory->power_limit));

	synthDelay = REG_READ(ah, AR_PHY_RX_DELAY) & AR_PHY_RX_DELAY_DELAY;
	if (IS_CHAN_B(chan))
		synthDelay = (4 * synthDelay) / 22;
	else
		synthDelay /= 10;

	udelay(synthDelay + BASE_ACTIVATE_DELAY);

	REG_WRITE(ah, AR_PHY_RFBUS_REQ, 0);

	if (IS_CHAN_OFDM(chan) || IS_CHAN_HT(chan))
		ath9k_hw_set_delta_slope(ah, chan);

	ah->ath9k_hw_spur_mitigate_freq(ah, chan);

	if (!chan->oneTimeCalsDone)
		chan->oneTimeCalsDone = true;

	return true;
}

static void ath9k_enable_rfkill(struct ath_hw *ah)
{
	REG_SET_BIT(ah, AR_GPIO_INPUT_EN_VAL,
		    AR_GPIO_INPUT_EN_VAL_RFSILENT_BB);

	REG_CLR_BIT(ah, AR_GPIO_INPUT_MUX2,
		    AR_GPIO_INPUT_MUX2_RFSILENT);

	ath9k_hw_cfg_gpio_input(ah, ah->rfkill_gpio);
	REG_SET_BIT(ah, AR_PHY_TEST, RFSILENT_BB);
}

int ath9k_hw_reset(struct ath_hw *ah, struct ath9k_channel *chan,
		    bool bChannelChange)
{
	struct ath_common *common = ath9k_hw_common(ah);
	u32 saveLedState;
	struct ath9k_channel *curchan = ah->curchan;
	u32 saveDefAntenna;
	u32 macStaId1;
	u64 tsf = 0;
	int i, rx_chainmask, r;

	ah->txchainmask = common->tx_chainmask;
	ah->rxchainmask = common->rx_chainmask;

	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE))
		return -EIO;

	if (curchan && !ah->chip_fullsleep)
		ath9k_hw_getnf(ah, curchan);

	if (bChannelChange &&
	    (ah->chip_fullsleep != true) &&
	    (ah->curchan != NULL) &&
	    (chan->channel != ah->curchan->channel) &&
	    ((chan->channelFlags & CHANNEL_ALL) ==
	     (ah->curchan->channelFlags & CHANNEL_ALL)) &&
	     !(AR_SREV_9280(ah) || IS_CHAN_A_5MHZ_SPACED(chan) ||
	     IS_CHAN_A_5MHZ_SPACED(ah->curchan))) {

		if (ath9k_hw_channel_change(ah, chan)) {
			ath9k_hw_loadnf(ah, ah->curchan);
			ath9k_hw_start_nfcal(ah);
			return 0;
		}
	}

	saveDefAntenna = REG_READ(ah, AR_DEF_ANTENNA);
	if (saveDefAntenna == 0)
		saveDefAntenna = 1;

	macStaId1 = REG_READ(ah, AR_STA_ID1) & AR_STA_ID1_BASE_RATE_11B;

	/* For chips on which RTC reset is done, save TSF before it gets cleared */
	if (AR_SREV_9280(ah) && ah->eep_ops->get_eeprom(ah, EEP_OL_PWRCTRL))
		tsf = ath9k_hw_gettsf64(ah);

	saveLedState = REG_READ(ah, AR_CFG_LED) &
		(AR_CFG_LED_ASSOC_CTL | AR_CFG_LED_MODE_SEL |
		 AR_CFG_LED_BLINK_THRESH_SEL | AR_CFG_LED_BLINK_SLOW);

	ath9k_hw_mark_phy_inactive(ah);

	if (AR_SREV_9271(ah) && ah->htc_reset_init) {
		REG_WRITE(ah,
			  AR9271_RESET_POWER_DOWN_CONTROL,
			  AR9271_RADIO_RF_RST);
		udelay(50);
	}

	if (!ath9k_hw_chip_reset(ah, chan)) {
		ath_print(common, ATH_DBG_FATAL, "Chip reset failed\n");
		return -EINVAL;
	}

	if (AR_SREV_9271(ah) && ah->htc_reset_init) {
		ah->htc_reset_init = false;
		REG_WRITE(ah,
			  AR9271_RESET_POWER_DOWN_CONTROL,
			  AR9271_GATE_MAC_CTL);
		udelay(50);
	}

	/* Restore TSF */
	if (tsf && AR_SREV_9280(ah) && ah->eep_ops->get_eeprom(ah, EEP_OL_PWRCTRL))
		ath9k_hw_settsf64(ah, tsf);

	if (AR_SREV_9280_10_OR_LATER(ah))
		REG_SET_BIT(ah, AR_GPIO_INPUT_EN_VAL, AR_GPIO_JTAG_DISABLE);

	if (AR_SREV_9287_12_OR_LATER(ah)) {
		/* Enable ASYNC FIFO */
		REG_SET_BIT(ah, AR_MAC_PCU_ASYNC_FIFO_REG3,
				AR_MAC_PCU_ASYNC_FIFO_REG3_DATAPATH_SEL);
		REG_SET_BIT(ah, AR_PHY_MODE, AR_PHY_MODE_ASYNCFIFO);
		REG_CLR_BIT(ah, AR_MAC_PCU_ASYNC_FIFO_REG3,
				AR_MAC_PCU_ASYNC_FIFO_REG3_SOFT_RESET);
		REG_SET_BIT(ah, AR_MAC_PCU_ASYNC_FIFO_REG3,
				AR_MAC_PCU_ASYNC_FIFO_REG3_SOFT_RESET);
	}
	r = ath9k_hw_process_ini(ah, chan);
	if (r)
		return r;

	/* Setup MFP options for CCMP */
	if (AR_SREV_9280_20_OR_LATER(ah)) {
		/* Mask Retry(b11), PwrMgt(b12), MoreData(b13) to 0 in mgmt
		 * frames when constructing CCMP AAD. */
		REG_RMW_FIELD(ah, AR_AES_MUTE_MASK1, AR_AES_MUTE_MASK1_FC_MGMT,
			      0xc7ff);
		ah->sw_mgmt_crypto = false;
	} else if (AR_SREV_9160_10_OR_LATER(ah)) {
		/* Disable hardware crypto for management frames */
		REG_CLR_BIT(ah, AR_PCU_MISC_MODE2,
			    AR_PCU_MISC_MODE2_MGMT_CRYPTO_ENABLE);
		REG_SET_BIT(ah, AR_PCU_MISC_MODE2,
			    AR_PCU_MISC_MODE2_NO_CRYPTO_FOR_NON_DATA_PKT);
		ah->sw_mgmt_crypto = true;
	} else
		ah->sw_mgmt_crypto = true;

	if (IS_CHAN_OFDM(chan) || IS_CHAN_HT(chan))
		ath9k_hw_set_delta_slope(ah, chan);

	ah->ath9k_hw_spur_mitigate_freq(ah, chan);
	ah->eep_ops->set_board_values(ah, chan);

	REG_WRITE(ah, AR_STA_ID0, get_unaligned_le32(common->macaddr));
	REG_WRITE(ah, AR_STA_ID1, get_unaligned_le16(common->macaddr + 4)
		  | macStaId1
		  | AR_STA_ID1_RTS_USE_DEF
		  | (ah->config.
		     ack_6mb ? AR_STA_ID1_ACKCTS_6MB : 0)
		  | ah->sta_id1_defaults);
	ath9k_hw_set_operating_mode(ah, ah->opmode);

	ath_hw_setbssidmask(common);

	REG_WRITE(ah, AR_DEF_ANTENNA, saveDefAntenna);

	ath9k_hw_write_associd(ah);

	REG_WRITE(ah, AR_ISR, ~0);

	REG_WRITE(ah, AR_RSSI_THR, INIT_RSSI_THR);

	r = ah->ath9k_hw_rf_set_freq(ah, chan);
	if (r)
		return r;

	for (i = 0; i < AR_NUM_DCU; i++)
		REG_WRITE(ah, AR_DQCUMASK(i), 1 << i);

	ah->intr_txqs = 0;
	for (i = 0; i < ah->caps.total_queues; i++)
		ath9k_hw_resettxqueue(ah, i);

	ath9k_hw_init_interrupt_masks(ah, ah->opmode);
	ath9k_hw_init_qos(ah);

	if (ah->caps.hw_caps & ATH9K_HW_CAP_RFSILENT)
		ath9k_enable_rfkill(ah);

	ath9k_hw_init_global_settings(ah);

	if (AR_SREV_9287_12_OR_LATER(ah)) {
		REG_WRITE(ah, AR_D_GBL_IFS_SIFS,
			  AR_D_GBL_IFS_SIFS_ASYNC_FIFO_DUR);
		REG_WRITE(ah, AR_D_GBL_IFS_SLOT,
			  AR_D_GBL_IFS_SLOT_ASYNC_FIFO_DUR);
		REG_WRITE(ah, AR_D_GBL_IFS_EIFS,
			  AR_D_GBL_IFS_EIFS_ASYNC_FIFO_DUR);

		REG_WRITE(ah, AR_TIME_OUT, AR_TIME_OUT_ACK_CTS_ASYNC_FIFO_DUR);
		REG_WRITE(ah, AR_USEC, AR_USEC_ASYNC_FIFO_DUR);

		REG_SET_BIT(ah, AR_MAC_PCU_LOGIC_ANALYZER,
			    AR_MAC_PCU_LOGIC_ANALYZER_DISBUG20768);
		REG_RMW_FIELD(ah, AR_AHB_MODE, AR_AHB_CUSTOM_BURST_EN,
			      AR_AHB_CUSTOM_BURST_ASYNC_FIFO_VAL);
	}
	if (AR_SREV_9287_12_OR_LATER(ah)) {
		REG_SET_BIT(ah, AR_PCU_MISC_MODE2,
				AR_PCU_MISC_MODE2_ENABLE_AGGWEP);
	}

	REG_WRITE(ah, AR_STA_ID1,
		  REG_READ(ah, AR_STA_ID1) | AR_STA_ID1_PRESERVE_SEQNUM);

	ath9k_hw_set_dma(ah);

	REG_WRITE(ah, AR_OBS, 8);

	if (ah->config.rx_intr_mitigation) {
		REG_RMW_FIELD(ah, AR_RIMT, AR_RIMT_LAST, 500);
		REG_RMW_FIELD(ah, AR_RIMT, AR_RIMT_FIRST, 2000);
	}

	ath9k_hw_init_bb(ah, chan);

	if (!ath9k_hw_init_cal(ah, chan))
		return -EIO;

	rx_chainmask = ah->rxchainmask;
	if ((rx_chainmask == 0x5) || (rx_chainmask == 0x3)) {
		REG_WRITE(ah, AR_PHY_RX_CHAINMASK, rx_chainmask);
		REG_WRITE(ah, AR_PHY_CAL_CHAINMASK, rx_chainmask);
	}

	REG_WRITE(ah, AR_CFG_LED, saveLedState | AR_CFG_SCLK_32KHZ);

	/*
	 * For big endian systems turn on swapping for descriptors
	 */
	if (AR_SREV_9100(ah)) {
		u32 mask;
		mask = REG_READ(ah, AR_CFG);
		if (mask & (AR_CFG_SWRB | AR_CFG_SWTB | AR_CFG_SWRG)) {
			ath_print(common, ATH_DBG_RESET,
				"CFG Byte Swap Set 0x%x\n", mask);
		} else {
			mask =
				INIT_CONFIG_STATUS | AR_CFG_SWRB | AR_CFG_SWTB;
			REG_WRITE(ah, AR_CFG, mask);
			ath_print(common, ATH_DBG_RESET,
				"Setting CFG 0x%x\n", REG_READ(ah, AR_CFG));
		}
	} else {
		/* Configure AR9271 target WLAN */
                if (AR_SREV_9271(ah))
			REG_WRITE(ah, AR_CFG, AR_CFG_SWRB | AR_CFG_SWTB);
#ifdef __BIG_ENDIAN
                else
			REG_WRITE(ah, AR_CFG, AR_CFG_SWTD | AR_CFG_SWRD);
#endif
	}

	if (ah->btcoex_hw.enabled)
		ath9k_hw_btcoex_enable(ah);

	return 0;
}
EXPORT_SYMBOL(ath9k_hw_reset);

/************************/
/* Key Cache Management */
/************************/

bool ath9k_hw_keyreset(struct ath_hw *ah, u16 entry)
{
	u32 keyType;

	if (entry >= ah->caps.keycache_size) {
		ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
			  "keychache entry %u out of range\n", entry);
		return false;
	}

	keyType = REG_READ(ah, AR_KEYTABLE_TYPE(entry));

	REG_WRITE(ah, AR_KEYTABLE_KEY0(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY1(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY2(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY3(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_KEY4(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_TYPE(entry), AR_KEYTABLE_TYPE_CLR);
	REG_WRITE(ah, AR_KEYTABLE_MAC0(entry), 0);
	REG_WRITE(ah, AR_KEYTABLE_MAC1(entry), 0);

	if (keyType == AR_KEYTABLE_TYPE_TKIP && ATH9K_IS_MIC_ENABLED(ah)) {
		u16 micentry = entry + 64;

		REG_WRITE(ah, AR_KEYTABLE_KEY0(micentry), 0);
		REG_WRITE(ah, AR_KEYTABLE_KEY1(micentry), 0);
		REG_WRITE(ah, AR_KEYTABLE_KEY2(micentry), 0);
		REG_WRITE(ah, AR_KEYTABLE_KEY3(micentry), 0);

	}

	return true;
}
EXPORT_SYMBOL(ath9k_hw_keyreset);

bool ath9k_hw_keysetmac(struct ath_hw *ah, u16 entry, const u8 *mac)
{
	u32 macHi, macLo;

	if (entry >= ah->caps.keycache_size) {
		ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
			  "keychache entry %u out of range\n", entry);
		return false;
	}

	if (mac != NULL) {
		macHi = (mac[5] << 8) | mac[4];
		macLo = (mac[3] << 24) |
			(mac[2] << 16) |
			(mac[1] << 8) |
			mac[0];
		macLo >>= 1;
		macLo |= (macHi & 1) << 31;
		macHi >>= 1;
	} else {
		macLo = macHi = 0;
	}
	REG_WRITE(ah, AR_KEYTABLE_MAC0(entry), macLo);
	REG_WRITE(ah, AR_KEYTABLE_MAC1(entry), macHi | AR_KEYTABLE_VALID);

	return true;
}
EXPORT_SYMBOL(ath9k_hw_keysetmac);

bool ath9k_hw_set_keycache_entry(struct ath_hw *ah, u16 entry,
				 const struct ath9k_keyval *k,
				 const u8 *mac)
{
	const struct ath9k_hw_capabilities *pCap = &ah->caps;
	struct ath_common *common = ath9k_hw_common(ah);
	u32 key0, key1, key2, key3, key4;
	u32 keyType;

	if (entry >= pCap->keycache_size) {
		ath_print(common, ATH_DBG_FATAL,
			  "keycache entry %u out of range\n", entry);
		return false;
	}

	switch (k->kv_type) {
	case ATH9K_CIPHER_AES_OCB:
		keyType = AR_KEYTABLE_TYPE_AES;
		break;
	case ATH9K_CIPHER_AES_CCM:
		if (!(pCap->hw_caps & ATH9K_HW_CAP_CIPHER_AESCCM)) {
			ath_print(common, ATH_DBG_ANY,
				  "AES-CCM not supported by mac rev 0x%x\n",
				  ah->hw_version.macRev);
			return false;
		}
		keyType = AR_KEYTABLE_TYPE_CCM;
		break;
	case ATH9K_CIPHER_TKIP:
		keyType = AR_KEYTABLE_TYPE_TKIP;
		if (ATH9K_IS_MIC_ENABLED(ah)
		    && entry + 64 >= pCap->keycache_size) {
			ath_print(common, ATH_DBG_ANY,
				  "entry %u inappropriate for TKIP\n", entry);
			return false;
		}
		break;
	case ATH9K_CIPHER_WEP:
		if (k->kv_len < WLAN_KEY_LEN_WEP40) {
			ath_print(common, ATH_DBG_ANY,
				  "WEP key length %u too small\n", k->kv_len);
			return false;
		}
		if (k->kv_len <= WLAN_KEY_LEN_WEP40)
			keyType = AR_KEYTABLE_TYPE_40;
		else if (k->kv_len <= WLAN_KEY_LEN_WEP104)
			keyType = AR_KEYTABLE_TYPE_104;
		else
			keyType = AR_KEYTABLE_TYPE_128;
		break;
	case ATH9K_CIPHER_CLR:
		keyType = AR_KEYTABLE_TYPE_CLR;
		break;
	default:
		ath_print(common, ATH_DBG_FATAL,
			  "cipher %u not supported\n", k->kv_type);
		return false;
	}

	key0 = get_unaligned_le32(k->kv_val + 0);
	key1 = get_unaligned_le16(k->kv_val + 4);
	key2 = get_unaligned_le32(k->kv_val + 6);
	key3 = get_unaligned_le16(k->kv_val + 10);
	key4 = get_unaligned_le32(k->kv_val + 12);
	if (k->kv_len <= WLAN_KEY_LEN_WEP104)
		key4 &= 0xff;

	/*
	 * Note: Key cache registers access special memory area that requires
	 * two 32-bit writes to actually update the values in the internal
	 * memory. Consequently, the exact order and pairs used here must be
	 * maintained.
	 */

	if (keyType == AR_KEYTABLE_TYPE_TKIP && ATH9K_IS_MIC_ENABLED(ah)) {
		u16 micentry = entry + 64;

		/*
		 * Write inverted key[47:0] first to avoid Michael MIC errors
		 * on frames that could be sent or received at the same time.
		 * The correct key will be written in the end once everything
		 * else is ready.
		 */
		REG_WRITE(ah, AR_KEYTABLE_KEY0(entry), ~key0);
		REG_WRITE(ah, AR_KEYTABLE_KEY1(entry), ~key1);

		/* Write key[95:48] */
		REG_WRITE(ah, AR_KEYTABLE_KEY2(entry), key2);
		REG_WRITE(ah, AR_KEYTABLE_KEY3(entry), key3);

		/* Write key[127:96] and key type */
		REG_WRITE(ah, AR_KEYTABLE_KEY4(entry), key4);
		REG_WRITE(ah, AR_KEYTABLE_TYPE(entry), keyType);

		/* Write MAC address for the entry */
		(void) ath9k_hw_keysetmac(ah, entry, mac);

		if (ah->misc_mode & AR_PCU_MIC_NEW_LOC_ENA) {
			/*
			 * TKIP uses two key cache entries:
			 * Michael MIC TX/RX keys in the same key cache entry
			 * (idx = main index + 64):
			 * key0 [31:0] = RX key [31:0]
			 * key1 [15:0] = TX key [31:16]
			 * key1 [31:16] = reserved
			 * key2 [31:0] = RX key [63:32]
			 * key3 [15:0] = TX key [15:0]
			 * key3 [31:16] = reserved
			 * key4 [31:0] = TX key [63:32]
			 */
			u32 mic0, mic1, mic2, mic3, mic4;

			mic0 = get_unaligned_le32(k->kv_mic + 0);
			mic2 = get_unaligned_le32(k->kv_mic + 4);
			mic1 = get_unaligned_le16(k->kv_txmic + 2) & 0xffff;
			mic3 = get_unaligned_le16(k->kv_txmic + 0) & 0xffff;
			mic4 = get_unaligned_le32(k->kv_txmic + 4);

			/* Write RX[31:0] and TX[31:16] */
			REG_WRITE(ah, AR_KEYTABLE_KEY0(micentry), mic0);
			REG_WRITE(ah, AR_KEYTABLE_KEY1(micentry), mic1);

			/* Write RX[63:32] and TX[15:0] */
			REG_WRITE(ah, AR_KEYTABLE_KEY2(micentry), mic2);
			REG_WRITE(ah, AR_KEYTABLE_KEY3(micentry), mic3);

			/* Write TX[63:32] and keyType(reserved) */
			REG_WRITE(ah, AR_KEYTABLE_KEY4(micentry), mic4);
			REG_WRITE(ah, AR_KEYTABLE_TYPE(micentry),
				  AR_KEYTABLE_TYPE_CLR);

		} else {
			/*
			 * TKIP uses four key cache entries (two for group
			 * keys):
			 * Michael MIC TX/RX keys are in different key cache
			 * entries (idx = main index + 64 for TX and
			 * main index + 32 + 96 for RX):
			 * key0 [31:0] = TX/RX MIC key [31:0]
			 * key1 [31:0] = reserved
			 * key2 [31:0] = TX/RX MIC key [63:32]
			 * key3 [31:0] = reserved
			 * key4 [31:0] = reserved
			 *
			 * Upper layer code will call this function separately
			 * for TX and RX keys when these registers offsets are
			 * used.
			 */
			u32 mic0, mic2;

			mic0 = get_unaligned_le32(k->kv_mic + 0);
			mic2 = get_unaligned_le32(k->kv_mic + 4);

			/* Write MIC key[31:0] */
			REG_WRITE(ah, AR_KEYTABLE_KEY0(micentry), mic0);
			REG_WRITE(ah, AR_KEYTABLE_KEY1(micentry), 0);

			/* Write MIC key[63:32] */
			REG_WRITE(ah, AR_KEYTABLE_KEY2(micentry), mic2);
			REG_WRITE(ah, AR_KEYTABLE_KEY3(micentry), 0);

			/* Write TX[63:32] and keyType(reserved) */
			REG_WRITE(ah, AR_KEYTABLE_KEY4(micentry), 0);
			REG_WRITE(ah, AR_KEYTABLE_TYPE(micentry),
				  AR_KEYTABLE_TYPE_CLR);
		}

		/* MAC address registers are reserved for the MIC entry */
		REG_WRITE(ah, AR_KEYTABLE_MAC0(micentry), 0);
		REG_WRITE(ah, AR_KEYTABLE_MAC1(micentry), 0);

		/*
		 * Write the correct (un-inverted) key[47:0] last to enable
		 * TKIP now that all other registers are set with correct
		 * values.
		 */
		REG_WRITE(ah, AR_KEYTABLE_KEY0(entry), key0);
		REG_WRITE(ah, AR_KEYTABLE_KEY1(entry), key1);
	} else {
		/* Write key[47:0] */
		REG_WRITE(ah, AR_KEYTABLE_KEY0(entry), key0);
		REG_WRITE(ah, AR_KEYTABLE_KEY1(entry), key1);

		/* Write key[95:48] */
		REG_WRITE(ah, AR_KEYTABLE_KEY2(entry), key2);
		REG_WRITE(ah, AR_KEYTABLE_KEY3(entry), key3);

		/* Write key[127:96] and key type */
		REG_WRITE(ah, AR_KEYTABLE_KEY4(entry), key4);
		REG_WRITE(ah, AR_KEYTABLE_TYPE(entry), keyType);

		/* Write MAC address for the entry */
		(void) ath9k_hw_keysetmac(ah, entry, mac);
	}

	return true;
}
EXPORT_SYMBOL(ath9k_hw_set_keycache_entry);

bool ath9k_hw_keyisvalid(struct ath_hw *ah, u16 entry)
{
	if (entry < ah->caps.keycache_size) {
		u32 val = REG_READ(ah, AR_KEYTABLE_MAC1(entry));
		if (val & AR_KEYTABLE_VALID)
			return true;
	}
	return false;
}
EXPORT_SYMBOL(ath9k_hw_keyisvalid);

/******************************/
/* Power Management (Chipset) */
/******************************/

static void ath9k_set_power_sleep(struct ath_hw *ah, int setChip)
{
	REG_SET_BIT(ah, AR_STA_ID1, AR_STA_ID1_PWR_SAV);
	if (setChip) {
		REG_CLR_BIT(ah, AR_RTC_FORCE_WAKE,
			    AR_RTC_FORCE_WAKE_EN);
		if (!AR_SREV_9100(ah))
			REG_WRITE(ah, AR_RC, AR_RC_AHB | AR_RC_HOSTIF);

		if(!AR_SREV_5416(ah))
			REG_CLR_BIT(ah, (AR_RTC_RESET),
				    AR_RTC_RESET_EN);
	}
}

static void ath9k_set_power_network_sleep(struct ath_hw *ah, int setChip)
{
	REG_SET_BIT(ah, AR_STA_ID1, AR_STA_ID1_PWR_SAV);
	if (setChip) {
		struct ath9k_hw_capabilities *pCap = &ah->caps;

		if (!(pCap->hw_caps & ATH9K_HW_CAP_AUTOSLEEP)) {
			REG_WRITE(ah, AR_RTC_FORCE_WAKE,
				  AR_RTC_FORCE_WAKE_ON_INT);
		} else {
			REG_CLR_BIT(ah, AR_RTC_FORCE_WAKE,
				    AR_RTC_FORCE_WAKE_EN);
		}
	}
}

static bool ath9k_hw_set_power_awake(struct ath_hw *ah, int setChip)
{
	u32 val;
	int i;

	if (setChip) {
		if ((REG_READ(ah, AR_RTC_STATUS) &
		     AR_RTC_STATUS_M) == AR_RTC_STATUS_SHUTDOWN) {
			if (ath9k_hw_set_reset_reg(ah,
					   ATH9K_RESET_POWER_ON) != true) {
				return false;
			}
			ath9k_hw_init_pll(ah, NULL);
		}
		if (AR_SREV_9100(ah))
			REG_SET_BIT(ah, AR_RTC_RESET,
				    AR_RTC_RESET_EN);

		REG_SET_BIT(ah, AR_RTC_FORCE_WAKE,
			    AR_RTC_FORCE_WAKE_EN);
		udelay(50);

		for (i = POWER_UP_TIME / 50; i > 0; i--) {
			val = REG_READ(ah, AR_RTC_STATUS) & AR_RTC_STATUS_M;
			if (val == AR_RTC_STATUS_ON)
				break;
			udelay(50);
			REG_SET_BIT(ah, AR_RTC_FORCE_WAKE,
				    AR_RTC_FORCE_WAKE_EN);
		}
		if (i == 0) {
			ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
				  "Failed to wakeup in %uus\n",
				  POWER_UP_TIME / 20);
			return false;
		}
	}

	REG_CLR_BIT(ah, AR_STA_ID1, AR_STA_ID1_PWR_SAV);

	return true;
}

bool ath9k_hw_setpower(struct ath_hw *ah, enum ath9k_power_mode mode)
{
	struct ath_common *common = ath9k_hw_common(ah);
	int status = true, setChip = true;
	static const char *modes[] = {
		"AWAKE",
		"FULL-SLEEP",
		"NETWORK SLEEP",
		"UNDEFINED"
	};

	if (ah->power_mode == mode)
		return status;

	ath_print(common, ATH_DBG_RESET, "%s -> %s\n",
		  modes[ah->power_mode], modes[mode]);

	switch (mode) {
	case ATH9K_PM_AWAKE:
		status = ath9k_hw_set_power_awake(ah, setChip);
		break;
	case ATH9K_PM_FULL_SLEEP:
		ath9k_set_power_sleep(ah, setChip);
		ah->chip_fullsleep = true;
		break;
	case ATH9K_PM_NETWORK_SLEEP:
		ath9k_set_power_network_sleep(ah, setChip);
		break;
	default:
		ath_print(common, ATH_DBG_FATAL,
			  "Unknown power mode %u\n", mode);
		return false;
	}
	ah->power_mode = mode;

	return status;
}
EXPORT_SYMBOL(ath9k_hw_setpower);

/*
 * Helper for ASPM support.
 *
 * Disable PLL when in L0s as well as receiver clock when in L1.
 * This power saving option must be enabled through the SerDes.
 *
 * Programming the SerDes must go through the same 288 bit serial shift
 * register as the other analog registers.  Hence the 9 writes.
 */
void ath9k_hw_configpcipowersave(struct ath_hw *ah, int restore, int power_off)
{
	u8 i;
	u32 val;

	if (ah->is_pciexpress != true)
		return;

	/* Do not touch SerDes registers */
	if (ah->config.pcie_powersave_enable == 2)
		return;

	/* Nothing to do on restore for 11N */
	if (!restore) {
		if (AR_SREV_9280_20_OR_LATER(ah)) {
			/*
			 * AR9280 2.0 or later chips use SerDes values from the
			 * initvals.h initialized depending on chipset during
			 * ath9k_hw_init()
			 */
			for (i = 0; i < ah->iniPcieSerdes.ia_rows; i++) {
				REG_WRITE(ah, INI_RA(&ah->iniPcieSerdes, i, 0),
					  INI_RA(&ah->iniPcieSerdes, i, 1));
			}
		} else if (AR_SREV_9280(ah) &&
			   (ah->hw_version.macRev == AR_SREV_REVISION_9280_10)) {
			REG_WRITE(ah, AR_PCIE_SERDES, 0x9248fd00);
			REG_WRITE(ah, AR_PCIE_SERDES, 0x24924924);

			/* RX shut off when elecidle is asserted */
			REG_WRITE(ah, AR_PCIE_SERDES, 0xa8000019);
			REG_WRITE(ah, AR_PCIE_SERDES, 0x13160820);
			REG_WRITE(ah, AR_PCIE_SERDES, 0xe5980560);

			/* Shut off CLKREQ active in L1 */
			if (ah->config.pcie_clock_req)
				REG_WRITE(ah, AR_PCIE_SERDES, 0x401deffc);
			else
				REG_WRITE(ah, AR_PCIE_SERDES, 0x401deffd);

			REG_WRITE(ah, AR_PCIE_SERDES, 0x1aaabe40);
			REG_WRITE(ah, AR_PCIE_SERDES, 0xbe105554);
			REG_WRITE(ah, AR_PCIE_SERDES, 0x00043007);

			/* Load the new settings */
			REG_WRITE(ah, AR_PCIE_SERDES2, 0x00000000);

		} else {
			REG_WRITE(ah, AR_PCIE_SERDES, 0x9248fc00);
			REG_WRITE(ah, AR_PCIE_SERDES, 0x24924924);

			/* RX shut off when elecidle is asserted */
			REG_WRITE(ah, AR_PCIE_SERDES, 0x28000039);
			REG_WRITE(ah, AR_PCIE_SERDES, 0x53160824);
			REG_WRITE(ah, AR_PCIE_SERDES, 0xe5980579);

			/*
			 * Ignore ah->ah_config.pcie_clock_req setting for
			 * pre-AR9280 11n
			 */
			REG_WRITE(ah, AR_PCIE_SERDES, 0x001defff);

			REG_WRITE(ah, AR_PCIE_SERDES, 0x1aaabe40);
			REG_WRITE(ah, AR_PCIE_SERDES, 0xbe105554);
			REG_WRITE(ah, AR_PCIE_SERDES, 0x000e3007);

			/* Load the new settings */
			REG_WRITE(ah, AR_PCIE_SERDES2, 0x00000000);
		}

		udelay(1000);

		/* set bit 19 to allow forcing of pcie core into L1 state */
		REG_SET_BIT(ah, AR_PCIE_PM_CTRL, AR_PCIE_PM_CTRL_ENA);

		/* Several PCIe massages to ensure proper behaviour */
		if (ah->config.pcie_waen) {
			val = ah->config.pcie_waen;
			if (!power_off)
				val &= (~AR_WA_D3_L1_DISABLE);
		} else {
			if (AR_SREV_9285(ah) || AR_SREV_9271(ah) ||
			    AR_SREV_9287(ah)) {
				val = AR9285_WA_DEFAULT;
				if (!power_off)
					val &= (~AR_WA_D3_L1_DISABLE);
			} else if (AR_SREV_9280(ah)) {
				/*
				 * On AR9280 chips bit 22 of 0x4004 needs to be
				 * set otherwise card may disappear.
				 */
				val = AR9280_WA_DEFAULT;
				if (!power_off)
					val &= (~AR_WA_D3_L1_DISABLE);
			} else
				val = AR_WA_DEFAULT;
		}

		REG_WRITE(ah, AR_WA, val);
	}

	if (power_off) {
		/*
		 * Set PCIe workaround bits
		 * bit 14 in WA register (disable L1) should only
		 * be set when device enters D3 and be cleared
		 * when device comes back to D0.
		 */
		if (ah->config.pcie_waen) {
			if (ah->config.pcie_waen & AR_WA_D3_L1_DISABLE)
				REG_SET_BIT(ah, AR_WA, AR_WA_D3_L1_DISABLE);
		} else {
			if (((AR_SREV_9285(ah) || AR_SREV_9271(ah) ||
			      AR_SREV_9287(ah)) &&
			     (AR9285_WA_DEFAULT & AR_WA_D3_L1_DISABLE)) ||
			    (AR_SREV_9280(ah) &&
			     (AR9280_WA_DEFAULT & AR_WA_D3_L1_DISABLE))) {
				REG_SET_BIT(ah, AR_WA, AR_WA_D3_L1_DISABLE);
			}
		}
	}
}
EXPORT_SYMBOL(ath9k_hw_configpcipowersave);

/**********************/
/* Interrupt Handling */
/**********************/

bool ath9k_hw_intrpend(struct ath_hw *ah)
{
	u32 host_isr;

	if (AR_SREV_9100(ah))
		return true;

	host_isr = REG_READ(ah, AR_INTR_ASYNC_CAUSE);
	if ((host_isr & AR_INTR_MAC_IRQ) && (host_isr != AR_INTR_SPURIOUS))
		return true;

	host_isr = REG_READ(ah, AR_INTR_SYNC_CAUSE);
	if ((host_isr & AR_INTR_SYNC_DEFAULT)
	    && (host_isr != AR_INTR_SPURIOUS))
		return true;

	return false;
}
EXPORT_SYMBOL(ath9k_hw_intrpend);

bool ath9k_hw_getisr(struct ath_hw *ah, enum ath9k_int *masked)
{
	u32 isr = 0;
	u32 mask2 = 0;
	struct ath9k_hw_capabilities *pCap = &ah->caps;
	u32 sync_cause = 0;
	bool fatal_int = false;
	struct ath_common *common = ath9k_hw_common(ah);

	if (!AR_SREV_9100(ah)) {
		if (REG_READ(ah, AR_INTR_ASYNC_CAUSE) & AR_INTR_MAC_IRQ) {
			if ((REG_READ(ah, AR_RTC_STATUS) & AR_RTC_STATUS_M)
			    == AR_RTC_STATUS_ON) {
				isr = REG_READ(ah, AR_ISR);
			}
		}

		sync_cause = REG_READ(ah, AR_INTR_SYNC_CAUSE) &
			AR_INTR_SYNC_DEFAULT;

		*masked = 0;

		if (!isr && !sync_cause)
			return false;
	} else {
		*masked = 0;
		isr = REG_READ(ah, AR_ISR);
	}

	if (isr) {
		if (isr & AR_ISR_BCNMISC) {
			u32 isr2;
			isr2 = REG_READ(ah, AR_ISR_S2);
			if (isr2 & AR_ISR_S2_TIM)
				mask2 |= ATH9K_INT_TIM;
			if (isr2 & AR_ISR_S2_DTIM)
				mask2 |= ATH9K_INT_DTIM;
			if (isr2 & AR_ISR_S2_DTIMSYNC)
				mask2 |= ATH9K_INT_DTIMSYNC;
			if (isr2 & (AR_ISR_S2_CABEND))
				mask2 |= ATH9K_INT_CABEND;
			if (isr2 & AR_ISR_S2_GTT)
				mask2 |= ATH9K_INT_GTT;
			if (isr2 & AR_ISR_S2_CST)
				mask2 |= ATH9K_INT_CST;
			if (isr2 & AR_ISR_S2_TSFOOR)
				mask2 |= ATH9K_INT_TSFOOR;
		}

		isr = REG_READ(ah, AR_ISR_RAC);
		if (isr == 0xffffffff) {
			*masked = 0;
			return false;
		}

		*masked = isr & ATH9K_INT_COMMON;

		if (ah->config.rx_intr_mitigation) {
			if (isr & (AR_ISR_RXMINTR | AR_ISR_RXINTM))
				*masked |= ATH9K_INT_RX;
		}

		if (isr & (AR_ISR_RXOK | AR_ISR_RXERR))
			*masked |= ATH9K_INT_RX;
		if (isr &
		    (AR_ISR_TXOK | AR_ISR_TXDESC | AR_ISR_TXERR |
		     AR_ISR_TXEOL)) {
			u32 s0_s, s1_s;

			*masked |= ATH9K_INT_TX;

			s0_s = REG_READ(ah, AR_ISR_S0_S);
			ah->intr_txqs |= MS(s0_s, AR_ISR_S0_QCU_TXOK);
			ah->intr_txqs |= MS(s0_s, AR_ISR_S0_QCU_TXDESC);

			s1_s = REG_READ(ah, AR_ISR_S1_S);
			ah->intr_txqs |= MS(s1_s, AR_ISR_S1_QCU_TXERR);
			ah->intr_txqs |= MS(s1_s, AR_ISR_S1_QCU_TXEOL);
		}

		if (isr & AR_ISR_RXORN) {
			ath_print(common, ATH_DBG_INTERRUPT,
				  "receive FIFO overrun interrupt\n");
		}

		if (!AR_SREV_9100(ah)) {
			if (!(pCap->hw_caps & ATH9K_HW_CAP_AUTOSLEEP)) {
				u32 isr5 = REG_READ(ah, AR_ISR_S5_S);
				if (isr5 & AR_ISR_S5_TIM_TIMER)
					*masked |= ATH9K_INT_TIM_TIMER;
			}
		}

		*masked |= mask2;
	}

	if (AR_SREV_9100(ah))
		return true;

	if (isr & AR_ISR_GENTMR) {
		u32 s5_s;

		s5_s = REG_READ(ah, AR_ISR_S5_S);
		if (isr & AR_ISR_GENTMR) {
			ah->intr_gen_timer_trigger =
				MS(s5_s, AR_ISR_S5_GENTIMER_TRIG);

			ah->intr_gen_timer_thresh =
				MS(s5_s, AR_ISR_S5_GENTIMER_THRESH);

			if (ah->intr_gen_timer_trigger)
				*masked |= ATH9K_INT_GENTIMER;

		}
	}

	if (sync_cause) {
		fatal_int =
			(sync_cause &
			 (AR_INTR_SYNC_HOST1_FATAL | AR_INTR_SYNC_HOST1_PERR))
			? true : false;

		if (fatal_int) {
			if (sync_cause & AR_INTR_SYNC_HOST1_FATAL) {
				ath_print(common, ATH_DBG_ANY,
					  "received PCI FATAL interrupt\n");
			}
			if (sync_cause & AR_INTR_SYNC_HOST1_PERR) {
				ath_print(common, ATH_DBG_ANY,
					  "received PCI PERR interrupt\n");
			}
			*masked |= ATH9K_INT_FATAL;
		}
		if (sync_cause & AR_INTR_SYNC_RADM_CPL_TIMEOUT) {
			ath_print(common, ATH_DBG_INTERRUPT,
				  "AR_INTR_SYNC_RADM_CPL_TIMEOUT\n");
			REG_WRITE(ah, AR_RC, AR_RC_HOSTIF);
			REG_WRITE(ah, AR_RC, 0);
			*masked |= ATH9K_INT_FATAL;
		}
		if (sync_cause & AR_INTR_SYNC_LOCAL_TIMEOUT) {
			ath_print(common, ATH_DBG_INTERRUPT,
				  "AR_INTR_SYNC_LOCAL_TIMEOUT\n");
		}

		REG_WRITE(ah, AR_INTR_SYNC_CAUSE_CLR, sync_cause);
		(void) REG_READ(ah, AR_INTR_SYNC_CAUSE_CLR);
	}

	return true;
}
EXPORT_SYMBOL(ath9k_hw_getisr);

enum ath9k_int ath9k_hw_set_interrupts(struct ath_hw *ah, enum ath9k_int ints)
{
	u32 omask = ah->mask_reg;
	u32 mask, mask2;
	struct ath9k_hw_capabilities *pCap = &ah->caps;
	struct ath_common *common = ath9k_hw_common(ah);

	ath_print(common, ATH_DBG_INTERRUPT, "0x%x => 0x%x\n", omask, ints);

	if (omask & ATH9K_INT_GLOBAL) {
		ath_print(common, ATH_DBG_INTERRUPT, "disable IER\n");
		REG_WRITE(ah, AR_IER, AR_IER_DISABLE);
		(void) REG_READ(ah, AR_IER);
		if (!AR_SREV_9100(ah)) {
			REG_WRITE(ah, AR_INTR_ASYNC_ENABLE, 0);
			(void) REG_READ(ah, AR_INTR_ASYNC_ENABLE);

			REG_WRITE(ah, AR_INTR_SYNC_ENABLE, 0);
			(void) REG_READ(ah, AR_INTR_SYNC_ENABLE);
		}
	}

	mask = ints & ATH9K_INT_COMMON;
	mask2 = 0;

	if (ints & ATH9K_INT_TX) {
		if (ah->txok_interrupt_mask)
			mask |= AR_IMR_TXOK;
		if (ah->txdesc_interrupt_mask)
			mask |= AR_IMR_TXDESC;
		if (ah->txerr_interrupt_mask)
			mask |= AR_IMR_TXERR;
		if (ah->txeol_interrupt_mask)
			mask |= AR_IMR_TXEOL;
	}
	if (ints & ATH9K_INT_RX) {
		mask |= AR_IMR_RXERR;
		if (ah->config.rx_intr_mitigation)
			mask |= AR_IMR_RXMINTR | AR_IMR_RXINTM;
		else
			mask |= AR_IMR_RXOK | AR_IMR_RXDESC;
		if (!(pCap->hw_caps & ATH9K_HW_CAP_AUTOSLEEP))
			mask |= AR_IMR_GENTMR;
	}

	if (ints & (ATH9K_INT_BMISC)) {
		mask |= AR_IMR_BCNMISC;
		if (ints & ATH9K_INT_TIM)
			mask2 |= AR_IMR_S2_TIM;
		if (ints & ATH9K_INT_DTIM)
			mask2 |= AR_IMR_S2_DTIM;
		if (ints & ATH9K_INT_DTIMSYNC)
			mask2 |= AR_IMR_S2_DTIMSYNC;
		if (ints & ATH9K_INT_CABEND)
			mask2 |= AR_IMR_S2_CABEND;
		if (ints & ATH9K_INT_TSFOOR)
			mask2 |= AR_IMR_S2_TSFOOR;
	}

	if (ints & (ATH9K_INT_GTT | ATH9K_INT_CST)) {
		mask |= AR_IMR_BCNMISC;
		if (ints & ATH9K_INT_GTT)
			mask2 |= AR_IMR_S2_GTT;
		if (ints & ATH9K_INT_CST)
			mask2 |= AR_IMR_S2_CST;
	}

	ath_print(common, ATH_DBG_INTERRUPT, "new IMR 0x%x\n", mask);
	REG_WRITE(ah, AR_IMR, mask);
	mask = REG_READ(ah, AR_IMR_S2) & ~(AR_IMR_S2_TIM |
					   AR_IMR_S2_DTIM |
					   AR_IMR_S2_DTIMSYNC |
					   AR_IMR_S2_CABEND |
					   AR_IMR_S2_CABTO |
					   AR_IMR_S2_TSFOOR |
					   AR_IMR_S2_GTT | AR_IMR_S2_CST);
	REG_WRITE(ah, AR_IMR_S2, mask | mask2);
	ah->mask_reg = ints;

	if (!(pCap->hw_caps & ATH9K_HW_CAP_AUTOSLEEP)) {
		if (ints & ATH9K_INT_TIM_TIMER)
			REG_SET_BIT(ah, AR_IMR_S5, AR_IMR_S5_TIM_TIMER);
		else
			REG_CLR_BIT(ah, AR_IMR_S5, AR_IMR_S5_TIM_TIMER);
	}

	if (ints & ATH9K_INT_GLOBAL) {
		ath_print(common, ATH_DBG_INTERRUPT, "enable IER\n");
		REG_WRITE(ah, AR_IER, AR_IER_ENABLE);
		if (!AR_SREV_9100(ah)) {
			REG_WRITE(ah, AR_INTR_ASYNC_ENABLE,
				  AR_INTR_MAC_IRQ);
			REG_WRITE(ah, AR_INTR_ASYNC_MASK, AR_INTR_MAC_IRQ);


			REG_WRITE(ah, AR_INTR_SYNC_ENABLE,
				  AR_INTR_SYNC_DEFAULT);
			REG_WRITE(ah, AR_INTR_SYNC_MASK,
				  AR_INTR_SYNC_DEFAULT);
		}
		ath_print(common, ATH_DBG_INTERRUPT, "AR_IMR 0x%x IER 0x%x\n",
			  REG_READ(ah, AR_IMR), REG_READ(ah, AR_IER));
	}

	return omask;
}
EXPORT_SYMBOL(ath9k_hw_set_interrupts);

/*******************/
/* Beacon Handling */
/*******************/

void ath9k_hw_beaconinit(struct ath_hw *ah, u32 next_beacon, u32 beacon_period)
{
	int flags = 0;

	ah->beacon_interval = beacon_period;

	switch (ah->opmode) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_MONITOR:
		REG_WRITE(ah, AR_NEXT_TBTT_TIMER, TU_TO_USEC(next_beacon));
		REG_WRITE(ah, AR_NEXT_DMA_BEACON_ALERT, 0xffff);
		REG_WRITE(ah, AR_NEXT_SWBA, 0x7ffff);
		flags |= AR_TBTT_TIMER_EN;
		break;
	case NL80211_IFTYPE_ADHOC:
	case NL80211_IFTYPE_MESH_POINT:
		REG_SET_BIT(ah, AR_TXCFG,
			    AR_TXCFG_ADHOC_BEACON_ATIM_TX_POLICY);
		REG_WRITE(ah, AR_NEXT_NDP_TIMER,
			  TU_TO_USEC(next_beacon +
				     (ah->atim_window ? ah->
				      atim_window : 1)));
		flags |= AR_NDP_TIMER_EN;
	case NL80211_IFTYPE_AP:
		REG_WRITE(ah, AR_NEXT_TBTT_TIMER, TU_TO_USEC(next_beacon));
		REG_WRITE(ah, AR_NEXT_DMA_BEACON_ALERT,
			  TU_TO_USEC(next_beacon -
				     ah->config.
				     dma_beacon_response_time));
		REG_WRITE(ah, AR_NEXT_SWBA,
			  TU_TO_USEC(next_beacon -
				     ah->config.
				     sw_beacon_response_time));
		flags |=
			AR_TBTT_TIMER_EN | AR_DBA_TIMER_EN | AR_SWBA_TIMER_EN;
		break;
	default:
		ath_print(ath9k_hw_common(ah), ATH_DBG_BEACON,
			  "%s: unsupported opmode: %d\n",
			  __func__, ah->opmode);
		return;
		break;
	}

	REG_WRITE(ah, AR_BEACON_PERIOD, TU_TO_USEC(beacon_period));
	REG_WRITE(ah, AR_DMA_BEACON_PERIOD, TU_TO_USEC(beacon_period));
	REG_WRITE(ah, AR_SWBA_PERIOD, TU_TO_USEC(beacon_period));
	REG_WRITE(ah, AR_NDP_PERIOD, TU_TO_USEC(beacon_period));

	beacon_period &= ~ATH9K_BEACON_ENA;
	if (beacon_period & ATH9K_BEACON_RESET_TSF) {
		ath9k_hw_reset_tsf(ah);
	}

	REG_SET_BIT(ah, AR_TIMER_MODE, flags);
}
EXPORT_SYMBOL(ath9k_hw_beaconinit);

void ath9k_hw_set_sta_beacon_timers(struct ath_hw *ah,
				    const struct ath9k_beacon_state *bs)
{
	u32 nextTbtt, beaconintval, dtimperiod, beacontimeout;
	struct ath9k_hw_capabilities *pCap = &ah->caps;
	struct ath_common *common = ath9k_hw_common(ah);

	REG_WRITE(ah, AR_NEXT_TBTT_TIMER, TU_TO_USEC(bs->bs_nexttbtt));

	REG_WRITE(ah, AR_BEACON_PERIOD,
		  TU_TO_USEC(bs->bs_intval & ATH9K_BEACON_PERIOD));
	REG_WRITE(ah, AR_DMA_BEACON_PERIOD,
		  TU_TO_USEC(bs->bs_intval & ATH9K_BEACON_PERIOD));

	REG_RMW_FIELD(ah, AR_RSSI_THR,
		      AR_RSSI_THR_BM_THR, bs->bs_bmissthreshold);

	beaconintval = bs->bs_intval & ATH9K_BEACON_PERIOD;

	if (bs->bs_sleepduration > beaconintval)
		beaconintval = bs->bs_sleepduration;

	dtimperiod = bs->bs_dtimperiod;
	if (bs->bs_sleepduration > dtimperiod)
		dtimperiod = bs->bs_sleepduration;

	if (beaconintval == dtimperiod)
		nextTbtt = bs->bs_nextdtim;
	else
		nextTbtt = bs->bs_nexttbtt;

	ath_print(common, ATH_DBG_BEACON, "next DTIM %d\n", bs->bs_nextdtim);
	ath_print(common, ATH_DBG_BEACON, "next beacon %d\n", nextTbtt);
	ath_print(common, ATH_DBG_BEACON, "beacon period %d\n", beaconintval);
	ath_print(common, ATH_DBG_BEACON, "DTIM period %d\n", dtimperiod);

	REG_WRITE(ah, AR_NEXT_DTIM,
		  TU_TO_USEC(bs->bs_nextdtim - SLEEP_SLOP));
	REG_WRITE(ah, AR_NEXT_TIM, TU_TO_USEC(nextTbtt - SLEEP_SLOP));

	REG_WRITE(ah, AR_SLEEP1,
		  SM((CAB_TIMEOUT_VAL << 3), AR_SLEEP1_CAB_TIMEOUT)
		  | AR_SLEEP1_ASSUME_DTIM);

	if (pCap->hw_caps & ATH9K_HW_CAP_AUTOSLEEP)
		beacontimeout = (BEACON_TIMEOUT_VAL << 3);
	else
		beacontimeout = MIN_BEACON_TIMEOUT_VAL;

	REG_WRITE(ah, AR_SLEEP2,
		  SM(beacontimeout, AR_SLEEP2_BEACON_TIMEOUT));

	REG_WRITE(ah, AR_TIM_PERIOD, TU_TO_USEC(beaconintval));
	REG_WRITE(ah, AR_DTIM_PERIOD, TU_TO_USEC(dtimperiod));

	REG_SET_BIT(ah, AR_TIMER_MODE,
		    AR_TBTT_TIMER_EN | AR_TIM_TIMER_EN |
		    AR_DTIM_TIMER_EN);

	/* TSF Out of Range Threshold */
	REG_WRITE(ah, AR_TSFOOR_THRESHOLD, bs->bs_tsfoor_threshold);
}
EXPORT_SYMBOL(ath9k_hw_set_sta_beacon_timers);

/*******************/
/* HW Capabilities */
/*******************/

int ath9k_hw_fill_cap_info(struct ath_hw *ah)
{
	struct ath9k_hw_capabilities *pCap = &ah->caps;
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	struct ath_common *common = ath9k_hw_common(ah);
	struct ath_btcoex_hw *btcoex_hw = &ah->btcoex_hw;

	u16 capField = 0, eeval;

	eeval = ah->eep_ops->get_eeprom(ah, EEP_REG_0);
	regulatory->current_rd = eeval;

	eeval = ah->eep_ops->get_eeprom(ah, EEP_REG_1);
	if (AR_SREV_9285_10_OR_LATER(ah))
		eeval |= AR9285_RDEXT_DEFAULT;
	regulatory->current_rd_ext = eeval;

	capField = ah->eep_ops->get_eeprom(ah, EEP_OP_CAP);

	if (ah->opmode != NL80211_IFTYPE_AP &&
	    ah->hw_version.subvendorid == AR_SUBVENDOR_ID_NEW_A) {
		if (regulatory->current_rd == 0x64 ||
		    regulatory->current_rd == 0x65)
			regulatory->current_rd += 5;
		else if (regulatory->current_rd == 0x41)
			regulatory->current_rd = 0x43;
		ath_print(common, ATH_DBG_REGULATORY,
			  "regdomain mapped to 0x%x\n", regulatory->current_rd);
	}

	eeval = ah->eep_ops->get_eeprom(ah, EEP_OP_MODE);
	if ((eeval & (AR5416_OPFLAGS_11G | AR5416_OPFLAGS_11A)) == 0) {
		ath_print(common, ATH_DBG_FATAL,
			  "no band has been marked as supported in EEPROM.\n");
		return -EINVAL;
	}

	bitmap_zero(pCap->wireless_modes, ATH9K_MODE_MAX);

	if (eeval & AR5416_OPFLAGS_11A) {
		set_bit(ATH9K_MODE_11A, pCap->wireless_modes);
		if (ah->config.ht_enable) {
			if (!(eeval & AR5416_OPFLAGS_N_5G_HT20))
				set_bit(ATH9K_MODE_11NA_HT20,
					pCap->wireless_modes);
			if (!(eeval & AR5416_OPFLAGS_N_5G_HT40)) {
				set_bit(ATH9K_MODE_11NA_HT40PLUS,
					pCap->wireless_modes);
				set_bit(ATH9K_MODE_11NA_HT40MINUS,
					pCap->wireless_modes);
			}
		}
	}

	if (eeval & AR5416_OPFLAGS_11G) {
		set_bit(ATH9K_MODE_11G, pCap->wireless_modes);
		if (ah->config.ht_enable) {
			if (!(eeval & AR5416_OPFLAGS_N_2G_HT20))
				set_bit(ATH9K_MODE_11NG_HT20,
					pCap->wireless_modes);
			if (!(eeval & AR5416_OPFLAGS_N_2G_HT40)) {
				set_bit(ATH9K_MODE_11NG_HT40PLUS,
					pCap->wireless_modes);
				set_bit(ATH9K_MODE_11NG_HT40MINUS,
					pCap->wireless_modes);
			}
		}
	}

	pCap->tx_chainmask = ah->eep_ops->get_eeprom(ah, EEP_TX_MASK);
	/*
	 * For AR9271 we will temporarilly uses the rx chainmax as read from
	 * the EEPROM.
	 */
	if ((ah->hw_version.devid == AR5416_DEVID_PCI) &&
	    !(eeval & AR5416_OPFLAGS_11A) &&
	    !(AR_SREV_9271(ah)))
		/* CB71: GPIO 0 is pulled down to indicate 3 rx chains */
		pCap->rx_chainmask = ath9k_hw_gpio_get(ah, 0) ? 0x5 : 0x7;
	else
		/* Use rx_chainmask from EEPROM. */
		pCap->rx_chainmask = ah->eep_ops->get_eeprom(ah, EEP_RX_MASK);

	if (!(AR_SREV_9280(ah) && (ah->hw_version.macRev == 0)))
		ah->misc_mode |= AR_PCU_MIC_NEW_LOC_ENA;

	pCap->low_2ghz_chan = 2312;
	pCap->high_2ghz_chan = 2732;

	pCap->low_5ghz_chan = 4920;
	pCap->high_5ghz_chan = 6100;

	pCap->hw_caps &= ~ATH9K_HW_CAP_CIPHER_CKIP;
	pCap->hw_caps |= ATH9K_HW_CAP_CIPHER_TKIP;
	pCap->hw_caps |= ATH9K_HW_CAP_CIPHER_AESCCM;

	pCap->hw_caps &= ~ATH9K_HW_CAP_MIC_CKIP;
	pCap->hw_caps |= ATH9K_HW_CAP_MIC_TKIP;
	pCap->hw_caps |= ATH9K_HW_CAP_MIC_AESCCM;

	if (ah->config.ht_enable)
		pCap->hw_caps |= ATH9K_HW_CAP_HT;
	else
		pCap->hw_caps &= ~ATH9K_HW_CAP_HT;

	pCap->hw_caps |= ATH9K_HW_CAP_GTT;
	pCap->hw_caps |= ATH9K_HW_CAP_VEOL;
	pCap->hw_caps |= ATH9K_HW_CAP_BSSIDMASK;
	pCap->hw_caps &= ~ATH9K_HW_CAP_MCAST_KEYSEARCH;

	if (capField & AR_EEPROM_EEPCAP_MAXQCU)
		pCap->total_queues =
			MS(capField, AR_EEPROM_EEPCAP_MAXQCU);
	else
		pCap->total_queues = ATH9K_NUM_TX_QUEUES;

	if (capField & AR_EEPROM_EEPCAP_KC_ENTRIES)
		pCap->keycache_size =
			1 << MS(capField, AR_EEPROM_EEPCAP_KC_ENTRIES);
	else
		pCap->keycache_size = AR_KEYTABLE_SIZE;

	pCap->hw_caps |= ATH9K_HW_CAP_FASTCC;

	if (AR_SREV_9285(ah) || AR_SREV_9271(ah))
		pCap->tx_triglevel_max = MAX_TX_FIFO_THRESHOLD >> 1;
	else
		pCap->tx_triglevel_max = MAX_TX_FIFO_THRESHOLD;

	if (AR_SREV_9285_10_OR_LATER(ah))
		pCap->num_gpio_pins = AR9285_NUM_GPIO;
	else if (AR_SREV_9280_10_OR_LATER(ah))
		pCap->num_gpio_pins = AR928X_NUM_GPIO;
	else
		pCap->num_gpio_pins = AR_NUM_GPIO;

	if (AR_SREV_9160_10_OR_LATER(ah) || AR_SREV_9100(ah)) {
		pCap->hw_caps |= ATH9K_HW_CAP_CST;
		pCap->rts_aggr_limit = ATH_AMPDU_LIMIT_MAX;
	} else {
		pCap->rts_aggr_limit = (8 * 1024);
	}

	pCap->hw_caps |= ATH9K_HW_CAP_ENHANCEDPM;

#if defined(CONFIG_RFKILL) || defined(CONFIG_RFKILL_MODULE)
	ah->rfsilent = ah->eep_ops->get_eeprom(ah, EEP_RF_SILENT);
	if (ah->rfsilent & EEP_RFSILENT_ENABLED) {
		ah->rfkill_gpio =
			MS(ah->rfsilent, EEP_RFSILENT_GPIO_SEL);
		ah->rfkill_polarity =
			MS(ah->rfsilent, EEP_RFSILENT_POLARITY);

		pCap->hw_caps |= ATH9K_HW_CAP_RFSILENT;
	}
#endif

	pCap->hw_caps &= ~ATH9K_HW_CAP_AUTOSLEEP;

	if (AR_SREV_9280(ah) || AR_SREV_9285(ah))
		pCap->hw_caps &= ~ATH9K_HW_CAP_4KB_SPLITTRANS;
	else
		pCap->hw_caps |= ATH9K_HW_CAP_4KB_SPLITTRANS;

	if (regulatory->current_rd_ext & (1 << REG_EXT_JAPAN_MIDBAND)) {
		pCap->reg_cap =
			AR_EEPROM_EEREGCAP_EN_KK_NEW_11A |
			AR_EEPROM_EEREGCAP_EN_KK_U1_EVEN |
			AR_EEPROM_EEREGCAP_EN_KK_U2 |
			AR_EEPROM_EEREGCAP_EN_KK_MIDBAND;
	} else {
		pCap->reg_cap =
			AR_EEPROM_EEREGCAP_EN_KK_NEW_11A |
			AR_EEPROM_EEREGCAP_EN_KK_U1_EVEN;
	}

	/* Advertise midband for AR5416 with FCC midband set in eeprom */
	if (regulatory->current_rd_ext & (1 << REG_EXT_FCC_MIDBAND) &&
	    AR_SREV_5416(ah))
		pCap->reg_cap |= AR_EEPROM_EEREGCAP_EN_FCC_MIDBAND;

	pCap->num_antcfg_5ghz =
		ah->eep_ops->get_num_ant_config(ah, ATH9K_HAL_FREQ_BAND_5GHZ);
	pCap->num_antcfg_2ghz =
		ah->eep_ops->get_num_ant_config(ah, ATH9K_HAL_FREQ_BAND_2GHZ);

	if (AR_SREV_9280_10_OR_LATER(ah) &&
	    ath9k_hw_btcoex_supported(ah)) {
		btcoex_hw->btactive_gpio = ATH_BTACTIVE_GPIO;
		btcoex_hw->wlanactive_gpio = ATH_WLANACTIVE_GPIO;

		if (AR_SREV_9285(ah)) {
			btcoex_hw->scheme = ATH_BTCOEX_CFG_3WIRE;
			btcoex_hw->btpriority_gpio = ATH_BTPRIORITY_GPIO;
		} else {
			btcoex_hw->scheme = ATH_BTCOEX_CFG_2WIRE;
		}
	} else {
		btcoex_hw->scheme = ATH_BTCOEX_CFG_NONE;
	}

	return 0;
}

bool ath9k_hw_getcapability(struct ath_hw *ah, enum ath9k_capability_type type,
			    u32 capability, u32 *result)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	switch (type) {
	case ATH9K_CAP_CIPHER:
		switch (capability) {
		case ATH9K_CIPHER_AES_CCM:
		case ATH9K_CIPHER_AES_OCB:
		case ATH9K_CIPHER_TKIP:
		case ATH9K_CIPHER_WEP:
		case ATH9K_CIPHER_MIC:
		case ATH9K_CIPHER_CLR:
			return true;
		default:
			return false;
		}
	case ATH9K_CAP_TKIP_MIC:
		switch (capability) {
		case 0:
			return true;
		case 1:
			return (ah->sta_id1_defaults &
				AR_STA_ID1_CRPT_MIC_ENABLE) ? true :
			false;
		}
	case ATH9K_CAP_TKIP_SPLIT:
		return (ah->misc_mode & AR_PCU_MIC_NEW_LOC_ENA) ?
			false : true;
	case ATH9K_CAP_DIVERSITY:
		return (REG_READ(ah, AR_PHY_CCK_DETECT) &
			AR_PHY_CCK_DETECT_BB_ENABLE_ANT_FAST_DIV) ?
			true : false;
	case ATH9K_CAP_MCAST_KEYSRCH:
		switch (capability) {
		case 0:
			return true;
		case 1:
			if (REG_READ(ah, AR_STA_ID1) & AR_STA_ID1_ADHOC) {
				return false;
			} else {
				return (ah->sta_id1_defaults &
					AR_STA_ID1_MCAST_KSRCH) ? true :
					false;
			}
		}
		return false;
	case ATH9K_CAP_TXPOW:
		switch (capability) {
		case 0:
			return 0;
		case 1:
			*result = regulatory->power_limit;
			return 0;
		case 2:
			*result = regulatory->max_power_level;
			return 0;
		case 3:
			*result = regulatory->tp_scale;
			return 0;
		}
		return false;
	case ATH9K_CAP_DS:
		return (AR_SREV_9280_20_OR_LATER(ah) &&
			(ah->eep_ops->get_eeprom(ah, EEP_RC_CHAIN_MASK) == 1))
			? false : true;
	default:
		return false;
	}
}
EXPORT_SYMBOL(ath9k_hw_getcapability);

bool ath9k_hw_setcapability(struct ath_hw *ah, enum ath9k_capability_type type,
			    u32 capability, u32 setting, int *status)
{
	u32 v;

	switch (type) {
	case ATH9K_CAP_TKIP_MIC:
		if (setting)
			ah->sta_id1_defaults |=
				AR_STA_ID1_CRPT_MIC_ENABLE;
		else
			ah->sta_id1_defaults &=
				~AR_STA_ID1_CRPT_MIC_ENABLE;
		return true;
	case ATH9K_CAP_DIVERSITY:
		v = REG_READ(ah, AR_PHY_CCK_DETECT);
		if (setting)
			v |= AR_PHY_CCK_DETECT_BB_ENABLE_ANT_FAST_DIV;
		else
			v &= ~AR_PHY_CCK_DETECT_BB_ENABLE_ANT_FAST_DIV;
		REG_WRITE(ah, AR_PHY_CCK_DETECT, v);
		return true;
	case ATH9K_CAP_MCAST_KEYSRCH:
		if (setting)
			ah->sta_id1_defaults |= AR_STA_ID1_MCAST_KSRCH;
		else
			ah->sta_id1_defaults &= ~AR_STA_ID1_MCAST_KSRCH;
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL(ath9k_hw_setcapability);

/****************************/
/* GPIO / RFKILL / Antennae */
/****************************/

static void ath9k_hw_gpio_cfg_output_mux(struct ath_hw *ah,
					 u32 gpio, u32 type)
{
	int addr;
	u32 gpio_shift, tmp;

	if (gpio > 11)
		addr = AR_GPIO_OUTPUT_MUX3;
	else if (gpio > 5)
		addr = AR_GPIO_OUTPUT_MUX2;
	else
		addr = AR_GPIO_OUTPUT_MUX1;

	gpio_shift = (gpio % 6) * 5;

	if (AR_SREV_9280_20_OR_LATER(ah)
	    || (addr != AR_GPIO_OUTPUT_MUX1)) {
		REG_RMW(ah, addr, (type << gpio_shift),
			(0x1f << gpio_shift));
	} else {
		tmp = REG_READ(ah, addr);
		tmp = ((tmp & 0x1F0) << 1) | (tmp & ~0x1F0);
		tmp &= ~(0x1f << gpio_shift);
		tmp |= (type << gpio_shift);
		REG_WRITE(ah, addr, tmp);
	}
}

void ath9k_hw_cfg_gpio_input(struct ath_hw *ah, u32 gpio)
{
	u32 gpio_shift;

	BUG_ON(gpio >= ah->caps.num_gpio_pins);

	gpio_shift = gpio << 1;

	REG_RMW(ah,
		AR_GPIO_OE_OUT,
		(AR_GPIO_OE_OUT_DRV_NO << gpio_shift),
		(AR_GPIO_OE_OUT_DRV << gpio_shift));
}
EXPORT_SYMBOL(ath9k_hw_cfg_gpio_input);

u32 ath9k_hw_gpio_get(struct ath_hw *ah, u32 gpio)
{
#define MS_REG_READ(x, y) \
	(MS(REG_READ(ah, AR_GPIO_IN_OUT), x##_GPIO_IN_VAL) & (AR_GPIO_BIT(y)))

	if (gpio >= ah->caps.num_gpio_pins)
		return 0xffffffff;

	if (AR_SREV_9287_10_OR_LATER(ah))
		return MS_REG_READ(AR9287, gpio) != 0;
	else if (AR_SREV_9285_10_OR_LATER(ah))
		return MS_REG_READ(AR9285, gpio) != 0;
	else if (AR_SREV_9280_10_OR_LATER(ah))
		return MS_REG_READ(AR928X, gpio) != 0;
	else
		return MS_REG_READ(AR, gpio) != 0;
}
EXPORT_SYMBOL(ath9k_hw_gpio_get);

void ath9k_hw_cfg_output(struct ath_hw *ah, u32 gpio,
			 u32 ah_signal_type)
{
	u32 gpio_shift;

	ath9k_hw_gpio_cfg_output_mux(ah, gpio, ah_signal_type);

	gpio_shift = 2 * gpio;

	REG_RMW(ah,
		AR_GPIO_OE_OUT,
		(AR_GPIO_OE_OUT_DRV_ALL << gpio_shift),
		(AR_GPIO_OE_OUT_DRV << gpio_shift));
}
EXPORT_SYMBOL(ath9k_hw_cfg_output);

void ath9k_hw_set_gpio(struct ath_hw *ah, u32 gpio, u32 val)
{
	REG_RMW(ah, AR_GPIO_IN_OUT, ((val & 1) << gpio),
		AR_GPIO_BIT(gpio));
}
EXPORT_SYMBOL(ath9k_hw_set_gpio);

u32 ath9k_hw_getdefantenna(struct ath_hw *ah)
{
	return REG_READ(ah, AR_DEF_ANTENNA) & 0x7;
}
EXPORT_SYMBOL(ath9k_hw_getdefantenna);

void ath9k_hw_setantenna(struct ath_hw *ah, u32 antenna)
{
	REG_WRITE(ah, AR_DEF_ANTENNA, (antenna & 0x7));
}
EXPORT_SYMBOL(ath9k_hw_setantenna);

/*********************/
/* General Operation */
/*********************/

u32 ath9k_hw_getrxfilter(struct ath_hw *ah)
{
	u32 bits = REG_READ(ah, AR_RX_FILTER);
	u32 phybits = REG_READ(ah, AR_PHY_ERR);

	if (phybits & AR_PHY_ERR_RADAR)
		bits |= ATH9K_RX_FILTER_PHYRADAR;
	if (phybits & (AR_PHY_ERR_OFDM_TIMING | AR_PHY_ERR_CCK_TIMING))
		bits |= ATH9K_RX_FILTER_PHYERR;

	return bits;
}
EXPORT_SYMBOL(ath9k_hw_getrxfilter);

void ath9k_hw_setrxfilter(struct ath_hw *ah, u32 bits)
{
	u32 phybits;

	REG_WRITE(ah, AR_RX_FILTER, bits);

	phybits = 0;
	if (bits & ATH9K_RX_FILTER_PHYRADAR)
		phybits |= AR_PHY_ERR_RADAR;
	if (bits & ATH9K_RX_FILTER_PHYERR)
		phybits |= AR_PHY_ERR_OFDM_TIMING | AR_PHY_ERR_CCK_TIMING;
	REG_WRITE(ah, AR_PHY_ERR, phybits);

	if (phybits)
		REG_WRITE(ah, AR_RXCFG,
			  REG_READ(ah, AR_RXCFG) | AR_RXCFG_ZLFDMA);
	else
		REG_WRITE(ah, AR_RXCFG,
			  REG_READ(ah, AR_RXCFG) & ~AR_RXCFG_ZLFDMA);
}
EXPORT_SYMBOL(ath9k_hw_setrxfilter);

bool ath9k_hw_phy_disable(struct ath_hw *ah)
{
	if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_WARM))
		return false;

	ath9k_hw_init_pll(ah, NULL);
	return true;
}
EXPORT_SYMBOL(ath9k_hw_phy_disable);

bool ath9k_hw_disable(struct ath_hw *ah)
{
	if (!ath9k_hw_setpower(ah, ATH9K_PM_AWAKE))
		return false;

	if (!ath9k_hw_set_reset_reg(ah, ATH9K_RESET_COLD))
		return false;

	ath9k_hw_init_pll(ah, NULL);
	return true;
}
EXPORT_SYMBOL(ath9k_hw_disable);

void ath9k_hw_set_txpowerlimit(struct ath_hw *ah, u32 limit)
{
	struct ath_regulatory *regulatory = ath9k_hw_regulatory(ah);
	struct ath9k_channel *chan = ah->curchan;
	struct ieee80211_channel *channel = chan->chan;

	regulatory->power_limit = min(limit, (u32) MAX_RATE_POWER);

	ah->eep_ops->set_txpower(ah, chan,
				 ath9k_regd_get_ctl(regulatory, chan),
				 channel->max_antenna_gain * 2,
				 channel->max_power * 2,
				 min((u32) MAX_RATE_POWER,
				 (u32) regulatory->power_limit));
}
EXPORT_SYMBOL(ath9k_hw_set_txpowerlimit);

void ath9k_hw_setmac(struct ath_hw *ah, const u8 *mac)
{
	memcpy(ath9k_hw_common(ah)->macaddr, mac, ETH_ALEN);
}
EXPORT_SYMBOL(ath9k_hw_setmac);

void ath9k_hw_setopmode(struct ath_hw *ah)
{
	ath9k_hw_set_operating_mode(ah, ah->opmode);
}
EXPORT_SYMBOL(ath9k_hw_setopmode);

void ath9k_hw_setmcastfilter(struct ath_hw *ah, u32 filter0, u32 filter1)
{
	REG_WRITE(ah, AR_MCAST_FIL0, filter0);
	REG_WRITE(ah, AR_MCAST_FIL1, filter1);
}
EXPORT_SYMBOL(ath9k_hw_setmcastfilter);

void ath9k_hw_write_associd(struct ath_hw *ah)
{
	struct ath_common *common = ath9k_hw_common(ah);

	REG_WRITE(ah, AR_BSS_ID0, get_unaligned_le32(common->curbssid));
	REG_WRITE(ah, AR_BSS_ID1, get_unaligned_le16(common->curbssid + 4) |
		  ((common->curaid & 0x3fff) << AR_BSS_ID1_AID_S));
}
EXPORT_SYMBOL(ath9k_hw_write_associd);

u64 ath9k_hw_gettsf64(struct ath_hw *ah)
{
	u64 tsf;

	tsf = REG_READ(ah, AR_TSF_U32);
	tsf = (tsf << 32) | REG_READ(ah, AR_TSF_L32);

	return tsf;
}
EXPORT_SYMBOL(ath9k_hw_gettsf64);

void ath9k_hw_settsf64(struct ath_hw *ah, u64 tsf64)
{
	REG_WRITE(ah, AR_TSF_L32, tsf64 & 0xffffffff);
	REG_WRITE(ah, AR_TSF_U32, (tsf64 >> 32) & 0xffffffff);
}
EXPORT_SYMBOL(ath9k_hw_settsf64);

void ath9k_hw_reset_tsf(struct ath_hw *ah)
{
	if (!ath9k_hw_wait(ah, AR_SLP32_MODE, AR_SLP32_TSF_WRITE_STATUS, 0,
			   AH_TSF_WRITE_TIMEOUT))
		ath_print(ath9k_hw_common(ah), ATH_DBG_RESET,
			  "AR_SLP32_TSF_WRITE_STATUS limit exceeded\n");

	REG_WRITE(ah, AR_RESET_TSF, AR_RESET_TSF_ONCE);
}
EXPORT_SYMBOL(ath9k_hw_reset_tsf);

void ath9k_hw_set_tsfadjust(struct ath_hw *ah, u32 setting)
{
	if (setting)
		ah->misc_mode |= AR_PCU_TX_ADD_TSF;
	else
		ah->misc_mode &= ~AR_PCU_TX_ADD_TSF;
}
EXPORT_SYMBOL(ath9k_hw_set_tsfadjust);

/*
 *  Extend 15-bit time stamp from rx descriptor to
 *  a full 64-bit TSF using the current h/w TSF.
*/
u64 ath9k_hw_extend_tsf(struct ath_hw *ah, u32 rstamp)
{
	u64 tsf;

	tsf = ath9k_hw_gettsf64(ah);
	if ((tsf & 0x7fff) < rstamp)
		tsf -= 0x8000;
	return (tsf & ~0x7fff) | rstamp;
}
EXPORT_SYMBOL(ath9k_hw_extend_tsf);

void ath9k_hw_set11nmac2040(struct ath_hw *ah)
{
	struct ieee80211_conf *conf = &ath9k_hw_common(ah)->hw->conf;
	u32 macmode;

	if (conf_is_ht40(conf) && !ah->config.cwm_ignore_extcca)
		macmode = AR_2040_JOINED_RX_CLEAR;
	else
		macmode = 0;

	REG_WRITE(ah, AR_2040_MODE, macmode);
}

/* HW Generic timers configuration */

static const struct ath_gen_timer_configuration gen_tmr_configuration[] =
{
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP_TIMER, AR_NDP_PERIOD, AR_TIMER_MODE, 0x0080},
	{AR_NEXT_NDP2_TIMER, AR_NDP2_PERIOD, AR_NDP2_TIMER_MODE, 0x0001},
	{AR_NEXT_NDP2_TIMER + 1*4, AR_NDP2_PERIOD + 1*4,
				AR_NDP2_TIMER_MODE, 0x0002},
	{AR_NEXT_NDP2_TIMER + 2*4, AR_NDP2_PERIOD + 2*4,
				AR_NDP2_TIMER_MODE, 0x0004},
	{AR_NEXT_NDP2_TIMER + 3*4, AR_NDP2_PERIOD + 3*4,
				AR_NDP2_TIMER_MODE, 0x0008},
	{AR_NEXT_NDP2_TIMER + 4*4, AR_NDP2_PERIOD + 4*4,
				AR_NDP2_TIMER_MODE, 0x0010},
	{AR_NEXT_NDP2_TIMER + 5*4, AR_NDP2_PERIOD + 5*4,
				AR_NDP2_TIMER_MODE, 0x0020},
	{AR_NEXT_NDP2_TIMER + 6*4, AR_NDP2_PERIOD + 6*4,
				AR_NDP2_TIMER_MODE, 0x0040},
	{AR_NEXT_NDP2_TIMER + 7*4, AR_NDP2_PERIOD + 7*4,
				AR_NDP2_TIMER_MODE, 0x0080}
};

/* HW generic timer primitives */

/* compute and clear index of rightmost 1 */
static u32 rightmost_index(struct ath_gen_timer_table *timer_table, u32 *mask)
{
	u32 b;

	b = *mask;
	b &= (0-b);
	*mask &= ~b;
	b *= debruijn32;
	b >>= 27;

	return timer_table->gen_timer_index[b];
}

u32 ath9k_hw_gettsf32(struct ath_hw *ah)
{
	return REG_READ(ah, AR_TSF_L32);
}
EXPORT_SYMBOL(ath9k_hw_gettsf32);

struct ath_gen_timer *ath_gen_timer_alloc(struct ath_hw *ah,
					  void (*trigger)(void *),
					  void (*overflow)(void *),
					  void *arg,
					  u8 timer_index)
{
	struct ath_gen_timer_table *timer_table = &ah->hw_gen_timers;
	struct ath_gen_timer *timer;

	timer = kzalloc(sizeof(struct ath_gen_timer), GFP_KERNEL);

	if (timer == NULL) {
		ath_print(ath9k_hw_common(ah), ATH_DBG_FATAL,
			  "Failed to allocate memory"
			  "for hw timer[%d]\n", timer_index);
		return NULL;
	}

	/* allocate a hardware generic timer slot */
	timer_table->timers[timer_index] = timer;
	timer->index = timer_index;
	timer->trigger = trigger;
	timer->overflow = overflow;
	timer->arg = arg;

	return timer;
}
EXPORT_SYMBOL(ath_gen_timer_alloc);

void ath9k_hw_gen_timer_start(struct ath_hw *ah,
			      struct ath_gen_timer *timer,
			      u32 timer_next,
			      u32 timer_period)
{
	struct ath_gen_timer_table *timer_table = &ah->hw_gen_timers;
	u32 tsf;

	BUG_ON(!timer_period);

	set_bit(timer->index, &timer_table->timer_mask.timer_bits);

	tsf = ath9k_hw_gettsf32(ah);

	ath_print(ath9k_hw_common(ah), ATH_DBG_HWTIMER,
		  "curent tsf %x period %x"
		  "timer_next %x\n", tsf, timer_period, timer_next);

	/*
	 * Pull timer_next forward if the current TSF already passed it
	 * because of software latency
	 */
	if (timer_next < tsf)
		timer_next = tsf + timer_period;

	/*
	 * Program generic timer registers
	 */
	REG_WRITE(ah, gen_tmr_configuration[timer->index].next_addr,
		 timer_next);
	REG_WRITE(ah, gen_tmr_configuration[timer->index].period_addr,
		  timer_period);
	REG_SET_BIT(ah, gen_tmr_configuration[timer->index].mode_addr,
		    gen_tmr_configuration[timer->index].mode_mask);

	/* Enable both trigger and thresh interrupt masks */
	REG_SET_BIT(ah, AR_IMR_S5,
		(SM(AR_GENTMR_BIT(timer->index), AR_IMR_S5_GENTIMER_THRESH) |
		SM(AR_GENTMR_BIT(timer->index), AR_IMR_S5_GENTIMER_TRIG)));
}
EXPORT_SYMBOL(ath9k_hw_gen_timer_start);

void ath9k_hw_gen_timer_stop(struct ath_hw *ah, struct ath_gen_timer *timer)
{
	struct ath_gen_timer_table *timer_table = &ah->hw_gen_timers;

	if ((timer->index < AR_FIRST_NDP_TIMER) ||
		(timer->index >= ATH_MAX_GEN_TIMER)) {
		return;
	}

	/* Clear generic timer enable bits. */
	REG_CLR_BIT(ah, gen_tmr_configuration[timer->index].mode_addr,
			gen_tmr_configuration[timer->index].mode_mask);

	/* Disable both trigger and thresh interrupt masks */
	REG_CLR_BIT(ah, AR_IMR_S5,
		(SM(AR_GENTMR_BIT(timer->index), AR_IMR_S5_GENTIMER_THRESH) |
		SM(AR_GENTMR_BIT(timer->index), AR_IMR_S5_GENTIMER_TRIG)));

	clear_bit(timer->index, &timer_table->timer_mask.timer_bits);
}
EXPORT_SYMBOL(ath9k_hw_gen_timer_stop);

void ath_gen_timer_free(struct ath_hw *ah, struct ath_gen_timer *timer)
{
	struct ath_gen_timer_table *timer_table = &ah->hw_gen_timers;

	/* free the hardware generic timer slot */
	timer_table->timers[timer->index] = NULL;
	kfree(timer);
}
EXPORT_SYMBOL(ath_gen_timer_free);

/*
 * Generic Timer Interrupts handling
 */
void ath_gen_timer_isr(struct ath_hw *ah)
{
	struct ath_gen_timer_table *timer_table = &ah->hw_gen_timers;
	struct ath_gen_timer *timer;
	struct ath_common *common = ath9k_hw_common(ah);
	u32 trigger_mask, thresh_mask, index;

	/* get hardware generic timer interrupt status */
	trigger_mask = ah->intr_gen_timer_trigger;
	thresh_mask = ah->intr_gen_timer_thresh;
	trigger_mask &= timer_table->timer_mask.val;
	thresh_mask &= timer_table->timer_mask.val;

	trigger_mask &= ~thresh_mask;

	while (thresh_mask) {
		index = rightmost_index(timer_table, &thresh_mask);
		timer = timer_table->timers[index];
		BUG_ON(!timer);
		ath_print(common, ATH_DBG_HWTIMER,
			  "TSF overflow for Gen timer %d\n", index);
		timer->overflow(timer->arg);
	}

	while (trigger_mask) {
		index = rightmost_index(timer_table, &trigger_mask);
		timer = timer_table->timers[index];
		BUG_ON(!timer);
		ath_print(common, ATH_DBG_HWTIMER,
			  "Gen timer[%d] trigger\n", index);
		timer->trigger(timer->arg);
	}
}
EXPORT_SYMBOL(ath_gen_timer_isr);

static struct {
	u32 version;
	const char * name;
} ath_mac_bb_names[] = {
	/* Devices with external radios */
	{ AR_SREV_VERSION_5416_PCI,	"5416" },
	{ AR_SREV_VERSION_5416_PCIE,	"5418" },
	{ AR_SREV_VERSION_9100,		"9100" },
	{ AR_SREV_VERSION_9160,		"9160" },
	/* Single-chip solutions */
	{ AR_SREV_VERSION_9280,		"9280" },
	{ AR_SREV_VERSION_9285,		"9285" },
	{ AR_SREV_VERSION_9287,         "9287" },
	{ AR_SREV_VERSION_9271,         "9271" },
};

/* For devices with external radios */
static struct {
	u16 version;
	const char * name;
} ath_rf_names[] = {
	{ 0,				"5133" },
	{ AR_RAD5133_SREV_MAJOR,	"5133" },
	{ AR_RAD5122_SREV_MAJOR,	"5122" },
	{ AR_RAD2133_SREV_MAJOR,	"2133" },
	{ AR_RAD2122_SREV_MAJOR,	"2122" }
};

/*
 * Return the MAC/BB name. "????" is returned if the MAC/BB is unknown.
 */
static const char *ath9k_hw_mac_bb_name(u32 mac_bb_version)
{
	int i;

	for (i=0; i<ARRAY_SIZE(ath_mac_bb_names); i++) {
		if (ath_mac_bb_names[i].version == mac_bb_version) {
			return ath_mac_bb_names[i].name;
		}
	}

	return "????";
}

/*
 * Return the RF name. "????" is returned if the RF is unknown.
 * Used for devices with external radios.
 */
static const char *ath9k_hw_rf_name(u16 rf_version)
{
	int i;

	for (i=0; i<ARRAY_SIZE(ath_rf_names); i++) {
		if (ath_rf_names[i].version == rf_version) {
			return ath_rf_names[i].name;
		}
	}

	return "????";
}

void ath9k_hw_name(struct ath_hw *ah, char *hw_name, size_t len)
{
	int used;

	/* chipsets >= AR9280 are single-chip */
	if (AR_SREV_9280_10_OR_LATER(ah)) {
		used = snprintf(hw_name, len,
			       "Atheros AR%s Rev:%x",
			       ath9k_hw_mac_bb_name(ah->hw_version.macVersion),
			       ah->hw_version.macRev);
	}
	else {
		used = snprintf(hw_name, len,
			       "Atheros AR%s MAC/BB Rev:%x AR%s RF Rev:%x",
			       ath9k_hw_mac_bb_name(ah->hw_version.macVersion),
			       ah->hw_version.macRev,
			       ath9k_hw_rf_name((ah->hw_version.analog5GhzRev &
						AR_RADIO_SREV_MAJOR)),
			       ah->hw_version.phyRev);
	}

	hw_name[used] = '\0';
}
EXPORT_SYMBOL(ath9k_hw_name);

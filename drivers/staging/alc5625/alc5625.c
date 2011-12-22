/*
 * alc5625.c -- ALC5625 ALSA SoC Audio driver
 *
 * Copyright (C) 2011 Insignal Co., Ltd.
 *
 * Author: Pan<pan@insginal.co.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/pm.h>
#include <linux/i2c.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/initval.h>
#include <sound/tlv.h>

#include "alc5625.h"

struct alc5625_priv {
	unsigned int stereo_sysclk;
	unsigned int voice_sysclk;
	enum snd_soc_control_type control_type;
	void *control_data;
	struct snd_soc_codec *codec;
	struct regmap *regmap;
};

struct alc5625_init_reg {
	u8 reg_index;
	u16 reg_value;
};

static struct alc5625_init_reg alc5625_init_list[] = {

	{ALC5625_HP_OUT_VOL,		0x9090}, /* default is -12db */
	{ALC5625_SPK_OUT_VOL,		0x8080}, /* default is 0db */
	{ALC5625_DAC_AND_MIC_CTRL,	0xee03}, /* DAC to hpmixer */
	{ALC5625_OUTPUT_MIXER_CTRL,	0x0748}, /* all output from hpmixer */
	{ALC5625_MIC_CTRL,		0x0500}, /* mic boost 20db */
	{ALC5625_ADC_REC_MIXER,		0x3f3f}, /* record source from mic1 */
	{ALC5625_GEN_CTRL_REG1,		0x0c0a}, /* speaker vdd ratio is 1 */

	/* gain 15db of ADC by default */
	{ALC5625_ADC_REC_GAIN,		0xd5d5},

	/* Audio Record settings */
	{ALC5625_LINE_IN_VOL,		0xff1f},
	{ALC5625_PD_CTRL_STAT,		0x00c0},
	{ALC5625_PWR_MANAG_ADD3,	0x80c2},
};

#define ALC5625_INIT_REG_NUM ARRAY_SIZE(alc5625_init_list)

/*
 * bit[0] for linein playback switch
 * bit[1] phone
 * bit[2] mic1
 * bit[3] mic2
 * bit[4] vopcm
 *
 */
#define HPL_MIXER 0x80
#define HPR_MIXER 0x82
static unsigned int reg80, reg82;

/*
 * bit[0][1][2] use for aec control
 * bit[3] for none
 * bit[4] for SPKL pga
 * bit[5] for SPKR pga
 * bit[6] for hpl pga
 * bit[7] for hpr pga
 * bit[8] for dump dsp
 */
#define virtual_reg_FOR_MISC_FUNC 0x84
static unsigned int reg84;

static const u16 alc5625_reg[] = {
	0x59b4, 0x8080, 0x9090, 0x8080,	/* reg00-reg06 */
	0xc800, 0xff1f, 0x1010, 0x0808,	/* reg08-reg0e */
	0xe0ef, 0xd5d5, 0x3f3f, 0x0000,	/* reg10-reg16 */
	0xe010, 0x0000, 0x0748, 0x2007,	/* reg18-reg1e */
	0x0000, 0x0500, 0x00c0, 0x00c0,	/* reg20-reg26 */
	0x0000, 0x0000, 0x0000, 0x0000,	/* reg28-reg2e */
	0x0000, 0x0000, 0x0000, 0x0000,	/* reg30-reg36 */
	0x0000, 0x0000, 0x0000, 0x80c2,	/* reg38-reg3e */
	0x0c0a, 0x0000, 0x0000, 0x0000,	/* reg40-reg46 */
	0x0029, 0x0000, 0xbe3e, 0x3e3e,	/* reg48-reg4e */
	0x0000, 0x0000, 0x803a, 0x0000,	/* reg50-reg56 */
	0x0000, 0x0009, 0x0000, 0x3000,	/* reg58-reg5e */
	0x3075, 0x1010, 0x3110, 0x0000,	/* reg60-reg66 */
	0x0553, 0x0000, 0x0000, 0x0000,	/* reg68-reg6e */
	0x0000, 0x0000, 0x0000, 0x0000,	/* reg70-reg76 */
	0x0000, 0x0000, 0x0000, 0x0000,	/* reg78-reg7e */
};

struct voice_dsp_reg vodsp_aec_init_value[] = {
	{0x232c, 0x0025},
	{0x230b, 0x0001},
	{0x2308, 0x007f},
	{0x23f8, 0x4003},
	{0x2301, 0x0002},
	{0x2328, 0x0001},
	{0x2304, 0x00fa},
	{0x2305, 0x0500},
	{0x2306, 0x4000},
	{0x230d, 0x0900},
	{0x230e, 0x0280},
	{0x2312, 0x00b1},
	{0x2314, 0xc000},
	{0x2316, 0x0041},
	{0x2317, 0x2200},
	{0x2318, 0x0c00},
	{0x231d, 0x0050},
	{0x231f, 0x4000},
	{0x2330, 0x0008},
	{0x2335, 0x000a},
	{0x2336, 0x0004},
	{0x2337, 0x5000},
	{0x233a, 0x0300},
	{0x233b, 0x0030},
	{0x2341, 0x0008},
	{0x2343, 0x0800},
	{0x2352, 0x7fff},
	{0x237f, 0x0400},
	{0x23a7, 0x2800},
	{0x22ce, 0x0400},
	{0x22d3, 0x1500},
	{0x22d4, 0x2800},
	{0x22d5, 0x3000},
	{0x2399, 0x2800},
	{0x230c, 0x0000}, /* to enable VODSP AEC function */
};

#define SET_VODSP_REG_INIT_NUM ARRAY_SIZE(vodsp_aec_init_value)

static inline unsigned int alc5625_read_reg_cache(struct snd_soc_codec *codec,
							unsigned int reg)
{
	u16 *cache = codec->reg_cache;

	if (reg > 0x7e)
		return 0;
	return cache[reg / 2];
}

static unsigned int alc5625_read_hw_reg(struct snd_soc_codec *codec,
					unsigned int reg)
{
	unsigned int value = 0x0;

	if (regmap_read(codec->control_data, reg, &value) < 0) {
		printk(KERN_DEBUG "%s failed\n", __func__);
		return -EIO;
	}
	return value;
}


static unsigned int alc5625_read(struct snd_soc_codec *codec, unsigned int reg)
{
	if ((reg == 0x80) || (reg == 0x82) || (reg == 0x84))
		return (reg == 0x80) ? reg80 :
			((reg == 0x82) ? reg82 : reg84);

	return alc5625_read_hw_reg(codec, reg);
}

static inline void alc5625_write_reg_cache(struct snd_soc_codec *codec,
						unsigned int reg,
						unsigned int value)
{
	u16 *cache = codec->reg_cache;
	if (reg > 0x7E)
		return;
	cache[reg / 2] = value;
}

static int alc5625_write(struct snd_soc_codec *codec, unsigned int reg,
						unsigned int value)
{
	unsigned int *regvalue = NULL;

	if ((reg == 0x80) || (reg == 0x82) || (reg == 0x84)) {
		regvalue = ((reg == 0x80) ? &reg80 :
				((reg == 0x82) ? &reg82 : &reg84));
		*regvalue = value;
		return 0;
	}
	alc5625_write_reg_cache(codec, reg, value);

	if (!regmap_write(codec->control_data, reg, value)) {
		return 0;
	} else {
		printk(KERN_ERR "alc5625_write fail\n");
		return -EIO;
	}
}

#define alc5625_write_mask(c, reg, value, mask) snd_soc_update_bits(c,\
						reg, mask, value)

#define alc5625_reset(c) alc5625_write(c, ALC5625_RESET, 0)

/* read/write dsp reg */
static int alc5625_wait_vodsp_i2c_done(struct snd_soc_codec *codec)
{
	unsigned int checkcount = 0;
	unsigned int vodsp_data;

	vodsp_data = alc5625_read(codec, ALC5625_VODSP_REG_CMD);
	while (vodsp_data & VODSP_BUSY) {
		if (checkcount > 10)
			return -EBUSY;
		vodsp_data = alc5625_read(codec, ALC5625_VODSP_REG_CMD);
		checkcount++;
	}
	return 0;
}

static int alc5625_write_vodsp_reg(struct snd_soc_codec *codec,
	unsigned int vodspreg, unsigned int value)
{
	if (alc5625_wait_vodsp_i2c_done(codec))
		return -EBUSY;

	alc5625_write(codec, ALC5625_VODSP_REG_ADDR, vodspreg);
	alc5625_write(codec, ALC5625_VODSP_REG_DATA, value);
	alc5625_write(codec, ALC5625_VODSP_REG_CMD,
				VODSP_WRITE_ENABLE | VODSP_CMD_MW);
	mdelay(10);
	return 0;

}

static unsigned int alc5625_read_vodsp_reg(struct snd_soc_codec *codec,
						unsigned int vodspreg)
{
	unsigned int ndata_h, ndata_l;
	unsigned int value;

	if (alc5625_wait_vodsp_i2c_done(codec))
		return -EBUSY;

	alc5625_write(codec, ALC5625_VODSP_REG_ADDR, vodspreg);
	alc5625_write(codec, ALC5625_VODSP_REG_CMD,
				VODSP_READ_ENABLE | VODSP_CMD_MR);

	if (alc5625_wait_vodsp_i2c_done(codec))
		return -EBUSY;

	alc5625_write(codec, ALC5625_VODSP_REG_ADDR, 0x26);
	alc5625_write(codec, ALC5625_VODSP_REG_CMD,
				VODSP_READ_ENABLE | VODSP_CMD_RR);

	if (alc5625_wait_vodsp_i2c_done(codec))
		return -EBUSY;

	ndata_h = alc5625_read(codec, ALC5625_VODSP_REG_DATA);
	alc5625_write(codec, ALC5625_VODSP_REG_ADDR, 0x25);
	alc5625_write(codec, ALC5625_VODSP_REG_CMD,
				VODSP_READ_ENABLE | VODSP_CMD_RR);

	if (alc5625_wait_vodsp_i2c_done(codec))
		return -EBUSY;

	ndata_l = alc5625_read(codec, ALC5625_VODSP_REG_DATA);
	value = ((ndata_h & 0xff) << 8) | (ndata_l & 0xff);

	return value;
}

static int alc5625_reg_init(struct snd_soc_codec *codec)
{
	int i;

	for (i = 0; i < ALC5625_INIT_REG_NUM; i++)
		alc5625_write(codec, alc5625_init_list[i].reg_index,
				alc5625_init_list[i].reg_value);

	return 0;
}

static const char *const alc5625_aec_path_sel[] = {
	"aec func disable", "aec func for pcm in/out",
	"aec func for iis in/out", "aec func for analog in/out"
};		/* 0 */
static const char *const alc5625_spk_out_sel[] = {
	"Class AB", "Class D"
};		/* 1 */
static const char *const alc5625_spk_l_source_sel[] = {
	"LPRN", "LPRP", "LPLN", "MM"
};		/* 2 */
static const char *const alc5625_spkmux_source_sel[] = {
	"VMID", "HP Mixer", "SPK Mixer", "Mono Mixer"
};		/* 3 */
static const char *const alc5625_hplmux_source_sel[] = {
	"VMID", "HPL Mixer"
};		/* 4 */
static const char *const alc5625_hprmux_source_sel[] = {
	"VMID", "HPR Mixer"
};		/* 5 */
static const char *const alc5625_auxmux_source_sel[] = {
	"VMID", "HP Mixer", "SPK Mixer", "Mono Mixer"
};		/* 6 */
static const char *const alc5625_spkamp_ratio_sel[] = {
	"2.25 Vdd", "2.00 Vdd", "1.75 Vdd",
	"1.50 Vdd", "1.25 Vdd", "1.00 Vdd"
};		/* 7 */
static const char *const alc5625_mic1_boost_sel[] = {
	"Bypass", "+20db", "+30db", "+40db"
};		/* 8 */
static const char *const alc5625_mic2_boost_sel[] = {
	"Bypass", "+20db", "+30db", "+40db"
};		/* 9 */
static const char *const alc5625_dmic_boost_sel[] = {
	"Bypass", "+6db", "+12db", "+18db",
	"+24db", "+30db", "+36db", "+42db"
};		/* 10 */
static const char *const alc5625_adcr_func_sel[] = {
	"Stereo ADC", "Voice ADC",
	"VoDSP Interface", "PDM Slave Interface"
};		/* 11 */

static const struct soc_enum alc5625_enum[] = {
	SOC_ENUM_SINGLE(virtual_reg_FOR_MISC_FUNC, 0, 4,
			alc5625_aec_path_sel),			/* 0 */
	SOC_ENUM_SINGLE(ALC5625_OUTPUT_MIXER_CTRL, 13, 2,
			alc5625_spk_out_sel),			/* 1 */
	SOC_ENUM_SINGLE(ALC5625_OUTPUT_MIXER_CTRL, 14, 4,
			alc5625_spk_l_source_sel),		/* 2 */
	SOC_ENUM_SINGLE(ALC5625_OUTPUT_MIXER_CTRL, 10, 4,
			alc5625_spkmux_source_sel),		/* 3 */
	SOC_ENUM_SINGLE(ALC5625_OUTPUT_MIXER_CTRL, 9, 2,
			alc5625_hplmux_source_sel),		/* 4 */
	SOC_ENUM_SINGLE(ALC5625_OUTPUT_MIXER_CTRL, 8, 2,
			alc5625_hprmux_source_sel),		/* 5 */
	SOC_ENUM_SINGLE(ALC5625_OUTPUT_MIXER_CTRL, 6, 4,
			alc5625_auxmux_source_sel),		/* 6 */
	SOC_ENUM_SINGLE(ALC5625_GEN_CTRL_REG1, 1, 6,
			alc5625_spkamp_ratio_sel),		/* 7 */
	SOC_ENUM_SINGLE(ALC5625_MIC_CTRL, 10, 4,
			alc5625_mic1_boost_sel),		/* 8 */
	SOC_ENUM_SINGLE(ALC5625_MIC_CTRL, 8, 4,
			alc5625_mic2_boost_sel),		/* 9 */
	SOC_ENUM_SINGLE(ALC5625_DMIC_CTRL, 0, 8,
			alc5625_dmic_boost_sel),		/* 10 */
	SOC_ENUM_SINGLE(ALC5625_DAC_ADC_VODAC_FUN_SEL, 4, 4,
			alc5625_adcr_func_sel),			/* 11 */
};

/* function: Enable the Voice PCM interface Path */
static int config_pcm_voice_path(struct snd_soc_codec *codec,
					unsigned int enable_voice_path,
					unsigned int mode)
{
	if (enable_voice_path) {
		/* Power on DAC reference */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					PWR_DAC_REF | PWR_VOICE_DF2SE,
					PWR_DAC_REF | PWR_VOICE_DF2SE);
		/* Power on Voice DAC/ADC */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD2,
					PWR_VOICE_CLOCK,
					PWR_VOICE_CLOCK);
		/* routing voice to HPMixer */
		alc5625_write_mask(codec, ALC5625_VOICE_DAC_OUT_VOL, 0,
					M_V_DAC_TO_HP_MIXER);

		switch (mode) {
		case PCM_SLAVE_MODE_B:
			/*
			 * 8kHz sampling rate,16 bits PCM mode and Slave mode,
			 * PCM mode is B,MCLK=24.576MHz from Oscillator.
			 * CSR PSKEY_PCM_CONFIG32 (HEX) = 0x08C00000,
			 * PSKEY_FORMAT=0x0060
			 *
			 * Set LRCK voice select divide 32
			 * set voice blck select divide 6 and 8
			 * voice filter clock divide 3 and 16
			 * the register 0x64 value's should is 0x5524
			 */
			alc5625_write(codec, ALC5625_VOICE_DAC_PCMCLK_CTRL1,
						0x5524);

			break;

		case PCM_SLAVE_MODE_A:
			/*
			 * 8kHz sampling rate,16 bits PCM and Slave mode,
			 * PCM mode is A,MCLK=24.576MHz from Oscillator.
			 * CSR PSKEY_PCM_CONFIG32 (HEX) = 0x08C00004,
			 * PSKEY_FORMAT=0x0060
			 *
			 * Enable GPIO 1,3,4,5 to voice interface
			 * Set I2S to Slave mode
			 * Voice I2S SYSCLK Source select Main SYSCLK
			 * Set voice i2s VBCLK Polarity to Invert
			 * Set Data length to 16 bit
			 * set Data Fomrat to PCM mode A
			 * the register 0x36 value's should is 0xC082
			 */
			alc5625_write(codec, ALC5625_EXTEND_SDP_CTRL, 0xC082);

			/*
			 * Set LRCK voice select divide 64
			 * set voice blck select divide 6 and 8
			 * voice filter clock divide 3 and 16
			 * the register 0x64 value's should is 0x5524
			 */
			alc5625_write(codec, ALC5625_VOICE_DAC_PCMCLK_CTRL1,
						0x5524);

			break;

		case PCM_MASTER_MODE_B:
			/*
			 * 8kHz sampling rate,16 bits PCM and Master mode,
			 * PCM mode is B,Clock from PLL OUT
			 * CSR PSKEY_PCM_CONFIG32 (HEX) = 0x08000002,
			 * PSKEY_FORMAT=0x0060
			 * Enable GPIO 1,3,4,5 to voice interface
			 * Set I2S to master mode
			 * Set voice i2s VBCLK Polarity to Invert
			 * Set Data length to 16 bit
			 * set Data Fomrat to PCM mode B
			 * the register 0x36 value's should is 0x8083
			 */
			alc5625_write(codec, ALC5625_EXTEND_SDP_CTRL, 0x8083);

			/*
			 * Set LRCK voice select divide 64
			 * set voice blck select divide 6 and 8
			 * voice filter clock divide 3 and 16
			 * the register 0x64 value's should is 0x5524
			 */
			alc5625_write(codec, ALC5625_VOICE_DAC_PCMCLK_CTRL1,
						0x5524);
			break;

		default:
			/* do nothing */
			break;
		}
	} else {
		/* Power down Voice Different to sing-end power */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1, 0,
						PWR_VOICE_DF2SE);
		/* Power down Voice DAC/ADC */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD2, 0,
						PWR_VOICE_CLOCK);
		/* Disable Voice PCM interface */
		alc5625_write_mask(codec, ALC5625_EXTEND_SDP_CTRL, 0,
						EXT_I2S_FUNC_ENABLE);
	}

	return 0;
}

static int init_vodsp_aec(struct snd_soc_codec *codec)
{
	int i;
	int ret = 0;

	/* Disable LDO power */
	alc5625_write_mask(codec, ALC5625_LDO_CTRL, 0, LDO_ENABLE);
	mdelay(20);
	alc5625_write_mask(codec, ALC5625_VODSP_CTL,
				VODSP_NO_PD_MODE_ENA, VODSP_NO_PD_MODE_ENA);
	/* Enable LDO power and set output voltage to 1.2V */
	alc5625_write_mask(codec, ALC5625_LDO_CTRL,
				LDO_ENABLE | LDO_OUT_VOL_CTRL_1_20V,
				LDO_ENABLE | LDO_OUT_VOL_CTRL_MASK);
	mdelay(20);
	/* Enable power of VODSP I2C interface */
	alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
				PWR_VODSP_INTERFACE | PWR_I2C_FOR_VODSP,
				PWR_VODSP_INTERFACE | PWR_I2C_FOR_VODSP);
	mdelay(1);
	/* Reset VODSP */
	alc5625_write_mask(codec, ALC5625_VODSP_CTL,
				0, VODSP_NO_RST_MODE_ENA);
	mdelay(1);
	/* Set VODSP to non-reset status */
	alc5625_write_mask(codec, ALC5625_VODSP_CTL,
				VODSP_NO_RST_MODE_ENA, VODSP_NO_RST_MODE_ENA);
	mdelay(20);

	/*initize AEC paramter*/
	for (i = 0; i < SET_VODSP_REG_INIT_NUM; i++) {
		ret = alc5625_write_vodsp_reg(codec,
				vodsp_aec_init_value[i].index,
				vodsp_aec_init_value[i].val);
		if (ret)
			return -EIO;
	}

	schedule_timeout_uninterruptible(msecs_to_jiffies(10));

	return 0;
}

/*
 * Enable/Disable the VODSP interface Path
 *
 * For system clock only support specific clock, realtek suggests customer to
 * use 24.576Mhz or 22.5792Mhz clock for MCLK (MCLK=48k*512 or 44.1k*512Mhz)
 */
static int set_vodsp_aec_path(struct snd_soc_codec *codec, unsigned int mode)
{
	switch (mode) {
	case PCM_IN_PCM_OUT:
		/* set PCM format */
		config_pcm_voice_path(codec, 1, PCM_MASTER_MODE_B);
		/* set AEC path */
		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT,
					0x0300, 0x0300);
		alc5625_write_mask(codec, ALC5625_VODSP_PDM_CTL,
					VODSP_RXDP_PWR |
					VODSP_RXDP_S_SEL_VOICE |
					VOICE_PCM_S_SEL_AEC_TXDP,
					VODSP_RXDP_PWR |
					VODSP_RXDP_S_SEL_MASK |
					VOICE_PCM_S_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_DAC_ADC_VODAC_FUN_SEL,
					ADCR_FUNC_SEL_PDM |
					VODAC_SOUR_SEL_VODSP_TXDC,
					ADCR_FUNC_SEL_MASK |
					VODAC_SOUR_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_VODSP_CTL,
					VODSP_LRCK_SEL_8K,
					VODSP_LRCK_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT,
					0x0000, 0x0300);

		/* Set input&output path and power
		 * Power on related bit
		 *
		 * I2S DAI Enable | spk amp enable |
		 * Dac2Mixer pwr on | MICBIAS1 Enable |
		 * MICBIAS2 Enable | Main Bias Pwr |
		 * DAC ref voltage pwr on
		 */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0x0c8f, 0x0c8f);

		/* Pwr on Pll1 | over temperature sensor pwr on |
		 * pwr voice DAC on | Left and Right ADC on |
		 * Spk mixer pwr on | ADC mixer left/right pwr on
		 */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD2,
					0xa4cb, 0xa4cb);

		/* power spk left/right vol | pwr vodsp interface |
		 * power on microphone1 boost
		 */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
				0x3302, 0xf302);

		/* Mute DAC to hpmixer */
		alc5625_write(codec, ALC5625_DAC_AND_MIC_CTRL, 0xee0f);

		/* Set Mic1 to differential mode */
		alc5625_write(codec, ALC5625_MIC_VOL, 0x8808);

		/* Mic boost 0db */
		alc5625_write(codec, ALC5625_MIC_CTRL, 0x0000);

		/* ADC_Mixer_R boost 10.5 db */
		alc5625_write(codec, ALC5625_ADC_REC_GAIN, 0xcbd3);

		/* Mic1->ADCMixer_R */
		alc5625_write(codec, ALC5625_ADC_REC_MIXER, 0x7f3f);

		/* VoDAC to speakerMixer,0db */
		alc5625_write(codec, ALC5625_VOICE_DAC_OUT_VOL, 0xa010);

		/* Speaker source from speakermixer */
		alc5625_write(codec, ALC5625_OUTPUT_MIXER_CTRL, 0x8808);

		/* Unmute speaker */
		alc5625_write_mask(codec, ALC5625_SPK_OUT_VOL, 0x0000, 0x8080);

		break;

	case ANALOG_IN_ANALOG_OUT:
		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT, 0x0300, 0x0300);
		alc5625_write_mask(codec, ALC5625_VODSP_PDM_CTL,
					VODSP_RXDP_PWR |
					VODSP_RXDP_S_SEL_ADCL |
					VOICE_PCM_S_SEL_AEC_TXDP,
					VODSP_RXDP_PWR | VODSP_RXDP_S_SEL_MASK |
					VOICE_PCM_S_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_DAC_ADC_VODAC_FUN_SEL,
					ADCR_FUNC_SEL_PDM |
					VODAC_SOUR_SEL_VODSP_TXDC |
					DAC_FUNC_SEL_VODSP_TXDP|
					ADCL_FUNC_SEL_VODSP,
					ADCR_FUNC_SEL_MASK |
					VODAC_SOUR_SEL_MASK |
					DAC_FUNC_SEL_MASK |
					ADCL_FUNC_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_VODSP_CTL,
					VODSP_LRCK_SEL_16K,
					VODSP_LRCK_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT, 0x0000, 0x0300);

		/* Set input&output path and power */
		/* Power on related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0xcc8f, 0xcc8f);

		/* Power on related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD2,
				0xa7cf, 0xa7cf);

		/* Power on related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
				0xf312, 0xf312);

		/* Set Mic1 to differential mode */
		alc5625_write(codec, ALC5625_MIC_VOL, 0x8808);

		/* Set phone in to differential mode */
		alc5625_write(codec, ALC5625_PHONEIN_VOL, 0xe800);

		/* Mic boost 0db */
		alc5625_write(codec, ALC5625_MIC_CTRL, 0x0000);

		/* Mic1->ADCMixer_R,phone in-->ADCMixer_L */
		alc5625_write(codec, ALC5625_ADC_REC_MIXER, 0x773f);

		/* ADC_Mixer_R boost 10.5 db */
		alc5625_write(codec, ALC5625_ADC_REC_GAIN, 0xCBD3);

		/* Speaker from spkmixer,monoOut from monoMixer */
		alc5625_write(codec, ALC5625_OUTPUT_MIXER_CTRL, 0x88c8);

		/* Unmute VoDAC to spkmixer */
		alc5625_write(codec, ALC5625_VOICE_DAC_OUT_VOL, 0xA010);

		/* Unmute DAC to monoMixer */
		alc5625_write(codec, ALC5625_DAC_AND_MIC_CTRL, 0xee0e);
		alc5625_write(codec, ALC5625_STEREO_DAC_CLK_CTRL2, 0x2222);
		alc5625_write(codec, ALC5625_VOICE_DAC_PCMCLK_CTRL1, 0x3122);

		/* Unmute speaker */
		alc5625_write_mask(codec, ALC5625_SPK_OUT_VOL, 0x0000, 0x8080);

		/* Unmute auxout */
		alc5625_write_mask(codec, ALC5625_AUX_OUT_VOL, 0x0000, 0x8080);
		break;

	case DAC_IN_ADC_OUT:
		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT, 0x0300, 0x0300);
		alc5625_write_mask(codec, ALC5625_DAC_ADC_VODAC_FUN_SEL,
					ADCR_FUNC_SEL_PDM |
					DAC_FUNC_SEL_VODSP_TXDC,
					ADCR_FUNC_SEL_MASK |
					DAC_FUNC_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_VODSP_PDM_CTL,
					VODSP_SRC1_PWR |
					VODSP_SRC2_PWR |
					VODSP_RXDP_PWR |
					VODSP_RXDP_S_SEL_SRC1 |
					REC_S_SEL_SRC2,
					VODSP_SRC1_PWR |
					VODSP_SRC2_PWR |
					VODSP_RXDP_PWR |
					VODSP_RXDP_S_SEL_MASK |
					REC_S_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_VODSP_CTL,
					VODSP_LRCK_SEL_16K,
					VODSP_LRCK_SEL_MASK);
		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT, 0x0000, 0x0300);

		/* Set input&output path and power */
		/* Power on related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0xcc0f, 0xcc0f);

		/* Power on related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD2,
				0xa7cb, 0xa7cb);

		/* Power on related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
				0x3302, 0x3302);

		/* Set Mic1 to differential mode */
		alc5625_write(codec, ALC5625_MIC_VOL, 0x8808);

		/*Mic boost 0db */
		alc5625_write(codec, ALC5625_MIC_CTRL, 0x0000);

		/*Mic1->ADCMixer_R */
		alc5625_write(codec, ALC5625_ADC_REC_MIXER, 0x7f3f);

		/*ADC_Mixer_R boost 10.5 db */
		alc5625_write(codec, ALC5625_ADC_REC_GAIN, 0xCBD3);

		/* Speaker out from spkMixer */
		alc5625_write(codec, ALC5625_OUTPUT_MIXER_CTRL, 0x8808);

		/* Unmute DAC to spkMixer */
		alc5625_write(codec, ALC5625_DAC_AND_MIC_CTRL, 0xee0d);
		alc5625_write(codec, ALC5625_STEREO_DAC_CLK_CTRL1, 0x3075);
		alc5625_write(codec, ALC5625_STEREO_DAC_CLK_CTRL2, 0x1010);

		/* Unmute speaker */
		alc5625_write_mask(codec, ALC5625_SPK_OUT_VOL, 0x0000, 0x8080);

		break;

	case VODSP_AEC_DISABLE:
	default:
		/* Mute speaker out */
		alc5625_write_mask(codec, ALC5625_SPK_OUT_VOL, 0x8080, 0x8080);

		/* Mute auxout */
		alc5625_write_mask(codec, ALC5625_AUX_OUT_VOL, 0x8080, 0x8080);

		/* Mic boost 20db by default */
		alc5625_write(codec, ALC5625_MIC_CTRL, 0x0500);

		/* Record from Mic1 by default */
		alc5625_write(codec, ALC5625_ADC_REC_MIXER, 0x3f3f);

		/* ADC_Mixer_R boost 15 db by default */
		alc5625_write(codec, ALC5625_ADC_REC_GAIN, 0xD5D5);

		/* All output from HPmixer by default */
		alc5625_write(codec, ALC5625_OUTPUT_MIXER_CTRL, 0x0748);

		/* DAC to HPmixer by default */
		alc5625_write(codec, ALC5625_DAC_AND_MIC_CTRL, 0xee03);

		/* Mute VoDAC to mixer by default */
		alc5625_write(codec, ALC5625_VOICE_DAC_OUT_VOL, 0xe010);

		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT, 0x0000, 0x0300);

		/* Set stereo DAC&Voice DAC&Stereo ADC function
		 * select to default
		 */
		alc5625_write(codec, ALC5625_DAC_ADC_VODAC_FUN_SEL, 0);

		/* Set VODSP&PDM Control to default */
		alc5625_write(codec, ALC5625_VODSP_PDM_CTL, 0);

		alc5625_write_mask(codec, ALC5625_PD_CTRL_STAT, 0x0000, 0x0300);

		/* Power down related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
					0x0000, 0xf312);

		/* Power down related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0x0000, 0xcc8d);

		/* Power down related bit */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD2,
				0x0000, 0x07cf);
		break;
	}
	return 0;
}

static int enable_vodsp_aec(struct snd_soc_codec *codec,
				unsigned int enable_vodspAEC,
				unsigned int aec_mode)
{
	int ret = 0;

	if (enable_vodspAEC != 0) {
		/* enable power of VODSP I2C interface & VODSP interface */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
					PWR_VODSP_INTERFACE |
					PWR_I2C_FOR_VODSP,
					PWR_VODSP_INTERFACE |
					PWR_I2C_FOR_VODSP);
		/* enable power of VODSP I2S interface */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					PWR_I2S_INTERFACE,
					PWR_I2S_INTERFACE);
		/* select input/output of VODSP AEC */
		set_vodsp_aec_path(codec, aec_mode);
	} else {
		/* disable VODSP AEC path */
		set_vodsp_aec_path(codec, VODSP_AEC_DISABLE);
		/* set VODSP AEC to power down mode */
		alc5625_write_mask(codec, ALC5625_VODSP_CTL, 0,
					VODSP_NO_PD_MODE_ENA);
		/* disable power of VODSP I2C interface & VODSP interface */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3, 0,
					PWR_VODSP_INTERFACE |
					PWR_I2C_FOR_VODSP);
	}

	return ret;
}

static void alc5625_aec_config(struct snd_soc_codec *codec, unsigned int mode)
{
	if (mode == VODSP_AEC_DISABLE) {
		enable_vodsp_aec(codec, 0, mode);
		/* disable LDO power */
		alc5625_write_mask(codec, ALC5625_LDO_CTRL, 0, LDO_ENABLE);
	} else {
		init_vodsp_aec(codec);
		enable_vodsp_aec(codec, 1, mode);
	}
}

/* function:disable alc5625's function */
static int alc5625_func_aec_disable(struct snd_soc_codec *codec, int mode)
{
	switch (mode) {
	case ALC5625_AEC_PCM_IN_OUT:
	case ALC5625_AEC_IIS_IN_OUT:
	case ALC5625_AEC_ANALOG_IN_OUT:
		/* disable AEC function and path */
		alc5625_aec_config(codec, VODSP_AEC_DISABLE);
		break;
	default:
		break;
	}
	return 0;
}

static int alc5625_get_dsp_mode(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
	/* cause we choose bit[0][1] to store the mode type */
	int mode = (alc5625_read(codec, virtual_reg_FOR_MISC_FUNC)) & 0x03;

	ucontrol->value.integer.value[0] = mode;
	return 0;
}

static int alc5625_set_dsp_mode(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
	u16 virtual_reg = alc5625_read(codec, virtual_reg_FOR_MISC_FUNC);
	int alc5625_mode = (virtual_reg) & 0x03;

	if (alc5625_mode == ucontrol->value.integer.value[0])
		return 0;

	switch (ucontrol->value.integer.value[0]) {
	case ALC5625_AEC_PCM_IN_OUT:
		/* enable AEC PCM in/out function and path */
		alc5625_aec_config(codec, PCM_IN_PCM_OUT);
		break;

	case ALC5625_AEC_IIS_IN_OUT:
		/* enable AEC IIS in/out function and path */
		alc5625_aec_config(codec, DAC_IN_ADC_OUT);
		break;

	case ALC5625_AEC_ANALOG_IN_OUT:
		/* enable AEC analog in/out function and path */
		alc5625_aec_config(codec, ANALOG_IN_ANALOG_OUT);
		break;

	case ALC5625_AEC_DISABLE:
		/* disable previous select function */
		alc5625_func_aec_disable(codec, alc5625_mode);
		break;

	default:
		break;
	}

	virtual_reg &= 0xfffc;
	virtual_reg |= (ucontrol->value.integer.value[0]);
	alc5625_write(codec, virtual_reg_FOR_MISC_FUNC, virtual_reg);

	return 0;
}

static int alc5625_dump_dsp_reg(struct snd_soc_codec *codec)
{
	int i;

	alc5625_write_mask(codec, ALC5625_VODSP_CTL,
				VODSP_NO_PD_MODE_ENA,
				VODSP_NO_PD_MODE_ENA);
	for (i = 0; i < SET_VODSP_REG_INIT_NUM; i++)
		alc5625_read_vodsp_reg(codec,
				vodsp_aec_init_value[i].index);

	return 0;
}

static int alc5625_dump_dsp_put(struct snd_kcontrol *kcontrol,
				struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_codec *codec = snd_kcontrol_chip(kcontrol);
	int mode = alc5625_read(codec, virtual_reg_FOR_MISC_FUNC);

	mode &= ~(0x01 << 8);
	mode |= (ucontrol->value.integer.value[0] << 8);
	alc5625_write(codec, virtual_reg_FOR_MISC_FUNC, mode);
	alc5625_dump_dsp_reg(codec);

	return 0;
}

static const struct snd_kcontrol_new alc5625_snd_ctrls[] = {
	SOC_ENUM_EXT("alc5625 aec mode sel", alc5625_enum[0],
			alc5625_get_dsp_mode, alc5625_set_dsp_mode),
	SOC_ENUM("SPK Amp Type", alc5625_enum[1]),
	SOC_ENUM("Left SPK Source", alc5625_enum[2]),
	SOC_ENUM("SPK Amp Ratio", alc5625_enum[7]),
	SOC_ENUM("Mic1 Boost", alc5625_enum[8]),
	SOC_ENUM("Mic2 Boost", alc5625_enum[9]),
	SOC_ENUM("Dmic Boost", alc5625_enum[10]),
	SOC_ENUM("ADCR Func", alc5625_enum[11]),
	SOC_DOUBLE("PCM Playback Volume", ALC5625_STEREO_DAC_VOL, 8, 0, 63, 1),
	SOC_DOUBLE("LineIn Playback Volume", ALC5625_LINE_IN_VOL, 8, 0, 31, 1),
	SOC_SINGLE("Phone Playback Volume", ALC5625_PHONEIN_VOL, 8, 31, 1),
	SOC_SINGLE("Mic1 Playback Volume", ALC5625_MIC_VOL, 8, 31, 1),
	SOC_SINGLE("Mic2 Playback Volume", ALC5625_MIC_VOL, 0, 31, 1),
	SOC_DOUBLE("PCM Capture Volume", ALC5625_ADC_REC_GAIN, 8, 0, 31, 1),
	SOC_DOUBLE("SPKOUT Playback Volume", ALC5625_SPK_OUT_VOL, 8, 0, 31, 1),
	SOC_DOUBLE("SPKOUT Playback Switch", ALC5625_SPK_OUT_VOL, 15, 7, 1, 1),
	SOC_DOUBLE("HPOUT Playback Volume", ALC5625_HP_OUT_VOL, 8, 0, 31, 1),
	SOC_DOUBLE("HPOUT Playback Switch", ALC5625_HP_OUT_VOL, 15, 7, 1, 1),
	SOC_DOUBLE("AUXOUT Playback Volume", ALC5625_AUX_OUT_VOL, 8, 0, 31, 1),
	SOC_DOUBLE("AUXOUT Playback Switch", ALC5625_AUX_OUT_VOL, 15, 7, 1, 1),
	SOC_DOUBLE("ADC Record Gain", ALC5625_ADC_REC_GAIN, 8, 0, 31, 0),
	SOC_SINGLE_EXT("VoDSP Dump", virtual_reg_FOR_MISC_FUNC, 8, 1, 0,
			snd_soc_get_volsw, alc5625_dump_dsp_put),
};

static void hp_depop_mode2(struct snd_soc_codec *codec)
{
	alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
				PWR_SOFTGEN_EN,
				PWR_SOFTGEN_EN);
	alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
				PWR_HP_R_OUT_VOL | PWR_HP_L_OUT_VOL,
				PWR_HP_R_OUT_VOL | PWR_HP_L_OUT_VOL);
	alc5625_write(codec, ALC5625_MISC_CTRL, HP_DEPOP_MODE2_EN);
	schedule_timeout_uninterruptible(msecs_to_jiffies(500));

	alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
				PWR_HP_OUT_AMP | PWR_HP_OUT_ENH_AMP,
				PWR_HP_OUT_AMP | PWR_HP_OUT_ENH_AMP);

}

/* enable depop function for mute/unmute */
static void hp_mute_unmute_depop(struct snd_soc_codec *codec, int mute)
{
	if (mute) {
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					PWR_SOFTGEN_EN,
					PWR_SOFTGEN_EN);
		alc5625_write(codec, ALC5625_MISC_CTRL,
					M_UM_DEPOP_EN | HP_R_M_UM_DEPOP_EN |
					HP_L_M_UM_DEPOP_EN);
		/* Mute headphone right/left channel */
		alc5625_write_mask(codec, ALC5625_HP_OUT_VOL,
					ALC_L_MUTE|ALC_R_MUTE,
					ALC_L_MUTE|ALC_R_MUTE);
		mdelay(50);
	} else {
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					PWR_SOFTGEN_EN,
					PWR_SOFTGEN_EN);
		alc5625_write(codec, ALC5625_MISC_CTRL,
					M_UM_DEPOP_EN | HP_R_M_UM_DEPOP_EN |
					HP_L_M_UM_DEPOP_EN);
		/* unMute headphone right/left channel */
		alc5625_write_mask(codec, ALC5625_HP_OUT_VOL, 0,
					ALC_L_MUTE|ALC_R_MUTE);
		mdelay(50);
	}
}

/*
 * _DAPM_ Controls
 */
/* Left ADC Rec mixer */
static const struct snd_kcontrol_new alc5625_ctrl_adc_l[] = {
	SOC_DAPM_SINGLE("Mic1 Capture Switch",
			ALC5625_ADC_REC_MIXER, 14, 1, 1),
	SOC_DAPM_SINGLE("Mic2 Capture Switch",
			ALC5625_ADC_REC_MIXER, 13, 1, 1),
	SOC_DAPM_SINGLE("LineIn Capture Switch",
			ALC5625_ADC_REC_MIXER, 12, 1, 1),
	SOC_DAPM_SINGLE("Phone Capture Switch",
			ALC5625_ADC_REC_MIXER, 11, 1, 1),
	SOC_DAPM_SINGLE("HP Mixer Capture Switch",
			ALC5625_ADC_REC_MIXER, 10, 1, 1),
	SOC_DAPM_SINGLE("SPK Mixer Capture Switch",
			ALC5625_ADC_REC_MIXER, 9, 1, 1),
	SOC_DAPM_SINGLE("MoNo Mixer Capture Switch",
			ALC5625_ADC_REC_MIXER, 8, 1, 1),
};

/* Left ADC Rec mixer */
static const struct snd_kcontrol_new alc5625_ctrl_adc_r[] = {
	SOC_DAPM_SINGLE("Mic1 Capture Switch",
			ALC5625_ADC_REC_MIXER, 6, 1, 1),
	SOC_DAPM_SINGLE("Mic2 Capture Switch",
			ALC5625_ADC_REC_MIXER, 5, 1, 1),
	SOC_DAPM_SINGLE("LineIn Capture Switch",
			ALC5625_ADC_REC_MIXER, 4, 1, 1),
	SOC_DAPM_SINGLE("Phone Capture Switch",
			ALC5625_ADC_REC_MIXER, 3, 1, 1),
	SOC_DAPM_SINGLE("HP Mixer Capture Switch",
			ALC5625_ADC_REC_MIXER, 2, 1, 1),
	SOC_DAPM_SINGLE("SPK Mixer Capture Switch",
			ALC5625_ADC_REC_MIXER, 1, 1, 1),
	SOC_DAPM_SINGLE("MoNo Mixer Capture Switch",
			ALC5625_ADC_REC_MIXER, 0, 1, 1),
};

/* Left hpmixer mixer */
static const struct snd_kcontrol_new alc5625_ctrl_hp_l[] = {
	SOC_DAPM_SINGLE("ADC Playback Switch",
			ALC5625_ADC_REC_GAIN, 15, 1, 1),
	SOC_DAPM_SINGLE("LineIn Playback Switch",
			HPL_MIXER, 0, 1, 0),
	SOC_DAPM_SINGLE("Phone Playback Switch",
			HPL_MIXER, 1, 1, 0),
	SOC_DAPM_SINGLE("Mic1 Playback Switch",
			HPL_MIXER, 2, 1, 0),
	SOC_DAPM_SINGLE("Mic2 Playback Switch",
			HPL_MIXER, 3, 1, 0),
	SOC_DAPM_SINGLE("Voice DAC Playback Switch",
			HPL_MIXER, 4, 1, 0),
	SOC_DAPM_SINGLE("HIFI DAC Playback Switch",
			ALC5625_DAC_AND_MIC_CTRL, 3, 1, 1),
};

/* Right hpmixer mixer */
static const struct snd_kcontrol_new alc5625_ctrl_hp_r[] = {
	SOC_DAPM_SINGLE("ADC Playback Switch",
			ALC5625_ADC_REC_GAIN, 7, 1, 1),
	SOC_DAPM_SINGLE("LineIn Playback Switch",
			HPR_MIXER, 0, 1, 0),
	SOC_DAPM_SINGLE("Phone Playback Switch",
			HPR_MIXER, 1, 1, 0),
	SOC_DAPM_SINGLE("Mic1 Playback Switch",
			HPR_MIXER, 2, 1, 0),
	SOC_DAPM_SINGLE("Mic2 Playback Switch",
			HPR_MIXER, 3, 1, 0),
	SOC_DAPM_SINGLE("Voice DAC Playback Switch",
			HPR_MIXER, 4, 1, 0),
	SOC_DAPM_SINGLE("HIFI DAC Playback Switch",
			ALC5625_DAC_AND_MIC_CTRL, 2, 1, 1),
};

/* mono mixer */
static const struct snd_kcontrol_new alc5625_ctrl_mono[] = {
	SOC_DAPM_SINGLE("ADCL Playback Switch",
		ALC5625_ADC_REC_GAIN, 14, 1, 1),
	SOC_DAPM_SINGLE("ADCR Playback Switch",
		ALC5625_ADC_REC_GAIN, 6, 1, 1),
	SOC_DAPM_SINGLE("Line Mixer Playback Switch",
		ALC5625_LINE_IN_VOL, 13, 1, 1),
	SOC_DAPM_SINGLE("Mic1 Playback Switch",
		ALC5625_DAC_AND_MIC_CTRL, 13, 1, 1),
	SOC_DAPM_SINGLE("Mic2 Playback Switch",
		ALC5625_DAC_AND_MIC_CTRL, 9, 1, 1),
	SOC_DAPM_SINGLE("DAC Mixer Playback Switch",
		ALC5625_DAC_AND_MIC_CTRL, 0, 1, 1),
	SOC_DAPM_SINGLE("Voice DAC Playback Switch",
		ALC5625_VOICE_DAC_OUT_VOL, 13, 1, 1),
};

/* speaker mixer */
static const struct snd_kcontrol_new alc5625_ctrl_spk[] = {
	SOC_DAPM_SINGLE("Line Mixer Playback Switch",
		ALC5625_LINE_IN_VOL, 14, 1, 1),
	SOC_DAPM_SINGLE("Phone Playback Switch",
		ALC5625_PHONEIN_VOL, 14, 1, 1),
	SOC_DAPM_SINGLE("Mic1 Playback Switch",
		ALC5625_DAC_AND_MIC_CTRL, 14, 1, 1),
	SOC_DAPM_SINGLE("Mic2 Playback Switch",
		ALC5625_DAC_AND_MIC_CTRL, 10, 1, 1),
	SOC_DAPM_SINGLE("DAC Mixer Playback Switch",
		ALC5625_DAC_AND_MIC_CTRL, 1, 1, 1),
	SOC_DAPM_SINGLE("Voice DAC Playback Switch",
		ALC5625_VOICE_DAC_OUT_VOL, 14, 1, 1),
};

static int mixer_event(struct snd_soc_dapm_widget *w,
			struct snd_kcontrol *k, int event)
{
	struct snd_soc_codec *codec = w->codec;
	unsigned int l, r;

	l = alc5625_read(codec, HPL_MIXER);
	r = alc5625_read(codec, HPR_MIXER);

	/* Mute/Unmute vol output to hp mixer */
	if ((l & 0x1) || (r & 0x1))
		alc5625_write_mask(codec, ALC5625_LINE_IN_VOL,
					0x0000, 0x8000);
	else
		alc5625_write_mask(codec, ALC5625_LINE_IN_VOL,
					0x8000, 0x8000);

	/* Mute/Unmute phone input to hp mixer */
	if ((l & 0x2) || (r & 0x2))
		alc5625_write_mask(codec, ALC5625_PHONEIN_VOL,
					0x0000, 0x8000);
	else
		alc5625_write_mask(codec, ALC5625_PHONEIN_VOL,
					0x8000, 0x8000);

	/* Mute/Unmute Mic1 vol output to hp mixer */
	if ((l & 0x4) || (r & 0x4))
		alc5625_write_mask(codec, ALC5625_DAC_AND_MIC_CTRL,
					0x0000, 0x8000);
	else
		alc5625_write_mask(codec, ALC5625_DAC_AND_MIC_CTRL,
					0x8000, 0x8000);

	/* Mute/Unmute Mic2 vol output to hp mixer */
	if ((l & 0x8) || (r & 0x8))
		alc5625_write_mask(codec, ALC5625_DAC_AND_MIC_CTRL,
					0x0000, 0x0800);
	else
		alc5625_write_mask(codec, ALC5625_DAC_AND_MIC_CTRL,
					0x0800, 0x0800);

	/* Mute/Unmute voice DAC vol to hp mixer */
	if ((l & 0x10) || (r & 0x10))
		alc5625_write_mask(codec, ALC5625_VOICE_DAC_OUT_VOL,
					0x0000, 0x8000);
	else
		alc5625_write_mask(codec, ALC5625_VOICE_DAC_OUT_VOL,
					0x8000, 0x8000);

	return 0;
}

/*
 *	bit[0][1] use for aec control
 *	bit[2][3] for ADCR func
 *	bit[4] for SPKL pga
 *	bit[5] for SPKR pga
 *	bit[6] for hpl pga
 *	bit[7] for hpr pga
 */
static int spk_pga_event(struct snd_soc_dapm_widget *w,
				struct snd_kcontrol *k,
				int event)
{
	struct snd_soc_codec *codec = w->codec;
	int reg;

	reg = alc5625_read(codec, virtual_reg_FOR_MISC_FUNC) & (0x3 << 4);
	if (reg && (reg >> 4) != 0x3)
		return 0;

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
					0x3000, 0x3000);
		alc5625_write_mask(codec, ALC5625_SPK_OUT_VOL,
					0x0000, 0x8080);
		/* power on spk amp */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0x0400, 0x0400);
		break;
	case SND_SOC_DAPM_POST_PMD:
		/* power off spk amp */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0x0000, 0x0400);
		alc5625_write_mask(codec, ALC5625_SPK_OUT_VOL,
					0x8080, 0x8080);
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
					0x0000, 0x3000);
		break;
	default:
		return 0;
	}
	return 0;
}

static int hp_pga_event(struct snd_soc_dapm_widget *w,
			struct snd_kcontrol *k, int event)
{
	struct snd_soc_codec *codec = w->codec;
	int reg;

	reg = alc5625_read(codec, virtual_reg_FOR_MISC_FUNC) & (0x3 << 6);
	if (reg && (reg >> 6) != 0x3)
		return 0;

	switch (event) {
	case SND_SOC_DAPM_POST_PMD:
		printk(KERN_DEBUG "ALC5625: Powering down.\n");
		hp_mute_unmute_depop(codec, 1); /* mute hp */
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0x0000, 0x0300);
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD3,
					0x0000, 0x0c00);
		break;

	case SND_SOC_DAPM_POST_PMU:
		printk(KERN_DEBUG "ALC5625: Powering on.\n");
		hp_depop_mode2(codec);
		hp_mute_unmute_depop(codec, 0); /* unmute hp */
		break;

	default:
		return 0;
	}

	return 0;
}

static int aux_pga_event(struct snd_soc_dapm_widget *w,
			struct snd_kcontrol *k, int event)
{
	return 0;
}

/* SPKOUT Mux */
static const struct snd_kcontrol_new alc5625_ctrl_spkmux =
	SOC_DAPM_ENUM("Route", alc5625_enum[3]);

/* HPLOUT MUX */
static const struct snd_kcontrol_new alc5625_ctrl_hplmux =
	SOC_DAPM_ENUM("Route", alc5625_enum[4]);

/* HPROUT MUX */
static const struct snd_kcontrol_new alc5625_ctrl_hprmux =
	SOC_DAPM_ENUM("Route", alc5625_enum[5]);
/* AUXOUT MUX */
static const struct snd_kcontrol_new alc5625_ctrl_auxmux =
	SOC_DAPM_ENUM("Route", alc5625_enum[6]);

static const struct snd_soc_dapm_widget alc5625_dapm_widgets[] = {
	SND_SOC_DAPM_INPUT("Left LineIn"),
	SND_SOC_DAPM_INPUT("Right LineIn"),
	SND_SOC_DAPM_INPUT("Phone"),
	SND_SOC_DAPM_INPUT("Mic1"),
	SND_SOC_DAPM_INPUT("Mic2"),

	SND_SOC_DAPM_PGA("Mic1 Boost",
				ALC5625_PWR_MANAG_ADD3, 1, 0, NULL, 0),
	SND_SOC_DAPM_PGA("Mic2 Boost",
				ALC5625_PWR_MANAG_ADD3, 0, 0, NULL, 0),

	SND_SOC_DAPM_DAC("Left DAC", "Left HiFi Playback DAC",
				ALC5625_PWR_MANAG_ADD2, 9, 0),
	SND_SOC_DAPM_DAC("Right DAC", "Right HiFi Playback DAC",
				ALC5625_PWR_MANAG_ADD2, 8, 0),
	SND_SOC_DAPM_DAC("Voice DAC", "Voice Playback DAC",
				ALC5625_PWR_MANAG_ADD2, 10, 0),
	SND_SOC_DAPM_PGA("Left LineIn PGA",
				ALC5625_PWR_MANAG_ADD3,
				7, 0, NULL, 0),
	SND_SOC_DAPM_PGA("Right LineIn PGA",
				ALC5625_PWR_MANAG_ADD3, 6, 0, NULL, 0),
	SND_SOC_DAPM_PGA("Phone PGA",
				ALC5625_PWR_MANAG_ADD3, 5, 0, NULL, 0),
	SND_SOC_DAPM_PGA("Mic1 PGA",
				ALC5625_PWR_MANAG_ADD3, 3, 0, NULL, 0),
	SND_SOC_DAPM_PGA("Mic2 PGA",
				ALC5625_PWR_MANAG_ADD3, 2, 0, NULL, 0),
	SND_SOC_DAPM_PGA("VoDAC PGA",
				ALC5625_PWR_MANAG_ADD1, 7, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("Left Rec Mixer",
				ALC5625_PWR_MANAG_ADD2, 1, 0,
				&alc5625_ctrl_adc_l[0],
				ARRAY_SIZE(alc5625_ctrl_adc_l)),
	SND_SOC_DAPM_MIXER("Right Rec Mixer",
			ALC5625_PWR_MANAG_ADD2, 0, 0,
			&alc5625_ctrl_adc_r[0],
			ARRAY_SIZE(alc5625_ctrl_adc_r)),
	SND_SOC_DAPM_MIXER_E("Left HP Mixer",
				ALC5625_PWR_MANAG_ADD2, 5, 0,
				&alc5625_ctrl_hp_l[0],
				ARRAY_SIZE(alc5625_ctrl_hp_l),
				mixer_event, SND_SOC_DAPM_POST_REG),
	SND_SOC_DAPM_MIXER_E("Right HP Mixer",
				ALC5625_PWR_MANAG_ADD2, 4, 0,
				&alc5625_ctrl_hp_r[0],
				ARRAY_SIZE(alc5625_ctrl_hp_r),
				mixer_event, SND_SOC_DAPM_POST_REG),
	SND_SOC_DAPM_MIXER("MoNo Mixer",
				ALC5625_PWR_MANAG_ADD2, 2, 0,
				&alc5625_ctrl_mono[0],
				ARRAY_SIZE(alc5625_ctrl_mono)),
	SND_SOC_DAPM_MIXER("SPK Mixer",
				ALC5625_PWR_MANAG_ADD2, 3, 0,
				&alc5625_ctrl_spk[0],
				ARRAY_SIZE(alc5625_ctrl_spk)),
	SND_SOC_DAPM_MIXER("HP Mixer",
				SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("DAC Mixer",
				SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("Line Mixer",
				SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MUX("SPKOUT Mux",
				SND_SOC_NOPM, 0, 0,
				&alc5625_ctrl_spkmux),
	SND_SOC_DAPM_MUX("HPLOUT Mux",
				SND_SOC_NOPM, 0, 0,
				&alc5625_ctrl_hplmux),
	SND_SOC_DAPM_MUX("HPROUT Mux",
				SND_SOC_NOPM, 0, 0,
				&alc5625_ctrl_hprmux),
	SND_SOC_DAPM_MUX("AUXOUT Mux",
				SND_SOC_NOPM, 0, 0,
				&alc5625_ctrl_auxmux),
	SND_SOC_DAPM_PGA_E("SPKL Out PGA",
				virtual_reg_FOR_MISC_FUNC, 4, 0,
				NULL, 0, spk_pga_event,
				SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_PGA_E("SPKR Out PGA",
				virtual_reg_FOR_MISC_FUNC, 5, 0,
				NULL, 0, spk_pga_event,
				SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_POST_PMD),
	SND_SOC_DAPM_PGA_E("HPL Out PGA",
				virtual_reg_FOR_MISC_FUNC, 6, 0,
				NULL, 0, hp_pga_event,
				SND_SOC_DAPM_POST_PMD | SND_SOC_DAPM_POST_PMU),
	SND_SOC_DAPM_PGA_E("HPR Out PGA",
				virtual_reg_FOR_MISC_FUNC, 7, 0,
				NULL, 0, hp_pga_event,
				SND_SOC_DAPM_POST_PMD | SND_SOC_DAPM_POST_PMU),
	SND_SOC_DAPM_PGA_E("AUX Out PGA",
				ALC5625_PWR_MANAG_ADD3, 14, 0,
				NULL, 0, aux_pga_event,
				SND_SOC_DAPM_PRE_PMD | SND_SOC_DAPM_POST_PMU),
	SND_SOC_DAPM_ADC("Left ADC", "Left ADC HiFi Capture",
				ALC5625_PWR_MANAG_ADD2, 7, 0),
	SND_SOC_DAPM_ADC("Right ADC", "Right ADC HiFi Capture",
				ALC5625_PWR_MANAG_ADD2, 6, 0),
	SND_SOC_DAPM_OUTPUT("SPKL"),
	SND_SOC_DAPM_OUTPUT("SPKR"),
	SND_SOC_DAPM_OUTPUT("HPL"),
	SND_SOC_DAPM_OUTPUT("HPR"),
	SND_SOC_DAPM_OUTPUT("AUX"),
	SND_SOC_DAPM_MICBIAS("Mic1 Bias",
				ALC5625_PWR_MANAG_ADD1, 3, 0),
	SND_SOC_DAPM_MICBIAS("Mic2 Bias",
				ALC5625_PWR_MANAG_ADD1, 2, 0),
};

static const struct snd_soc_dapm_route audio_map[] = {

	/* Input PGA */
	{"Left LineIn PGA", NULL, "Left LineIn"},
	{"Right LineIn PGA", NULL, "Right LineIn"},
	{"Phone PGA", NULL, "Phone"},
	{"Mic1 Boost", NULL, "Mic1"},
	{"Mic2 Boost", NULL, "Mic2"},
	{"Mic1 PGA", NULL, "Mic1"},
	{"Mic2 PGA", NULL, "Mic2"},
	{"VoDAC PGA", NULL, "Voice DAC"},

	/* Left ADC mixer */
	{"Left Rec Mixer", "LineIn Capture Switch", "Left LineIn"},
	{"Left Rec Mixer", "Phone Capture Switch", "Phone"},
	{"Left Rec Mixer", "Mic1 Capture Switch", "Mic1 Boost"},
	{"Left Rec Mixer", "Mic2 Capture Switch", "Mic2 Boost"},
	{"Left Rec Mixer", "HP Mixer Capture Switch", "Left HP Mixer"},
	{"Left Rec Mixer", "SPK Mixer Capture Switch", "SPK Mixer"},
	{"Left Rec Mixer", "MoNo Mixer Capture Switch", "MoNo Mixer"},

	/* Right ADC Mixer */
	{"Right Rec Mixer", "LineIn Capture Switch", "Right LineIn"},
	{"Right Rec Mixer", "Phone Capture Switch", "Phone"},
	{"Right Rec Mixer", "Mic1 Capture Switch", "Mic1 Boost"},
	{"Right Rec Mixer", "Mic2 Capture Switch", "Mic2 Boost"},
	{"Right Rec Mixer", "HP Mixer Capture Switch", "Right HP Mixer"},
	{"Right Rec Mixer", "SPK Mixer Capture Switch", "SPK Mixer"},
	{"Right Rec Mixer", "MoNo Mixer Capture Switch", "MoNo Mixer"},

	/* HPL mixer */
	{"Left HP Mixer", "ADC Playback Switch", "Left Rec Mixer"},
	{"Left HP Mixer", "LineIn Playback Switch", "Left LineIn PGA"},
	{"Left HP Mixer", "Phone Playback Switch", "Phone PGA"},
	{"Left HP Mixer", "Mic1 Playback Switch", "Mic1 PGA"},
	{"Left HP Mixer", "Mic2 Playback Switch", "Mic2 PGA"},
	{"Left HP Mixer", "HIFI DAC Playback Switch", "Left DAC"},
	{"Left HP Mixer", "Voice DAC Playback Switch", "VoDAC PGA"},

	/* HPR mixer */
	{"Right HP Mixer", "ADC Playback Switch", "Right Rec Mixer"},
	{"Right HP Mixer", "LineIn Playback Switch", "Right LineIn PGA"},
	{"Right HP Mixer", "HIFI DAC Playback Switch", "Right DAC"},
	{"Right HP Mixer", "Phone Playback Switch", "Phone PGA"},
	{"Right HP Mixer", "Mic1 Playback Switch", "Mic1 PGA"},
	{"Right HP Mixer", "Mic2 Playback Switch", "Mic2 PGA"},
	{"Right HP Mixer", "Voice DAC Playback Switch", "VoDAC PGA"},

	/* DAC Mixer */
	{"DAC Mixer", NULL, "Left DAC"},
	{"DAC Mixer", NULL, "Right DAC"},

	/* line mixer */
	{"Line Mixer", NULL, "Left LineIn PGA"},
	{"Line Mixer", NULL, "Right LineIn PGA"},

	/* spk mixer */
	{"SPK Mixer", "Line Mixer Playback Switch", "Line Mixer"},
	{"SPK Mixer", "Phone Playback Switch", "Phone PGA"},
	{"SPK Mixer", "Mic1 Playback Switch", "Mic1 PGA"},
	{"SPK Mixer", "Mic2 Playback Switch", "Mic2 PGA"},
	{"SPK Mixer", "DAC Mixer Playback Switch", "DAC Mixer"},
	{"SPK Mixer", "Voice DAC Playback Switch", "VoDAC PGA"},

	/* mono mixer */
	{"MoNo Mixer", "Line Mixer Playback Switch", "Line Mixer"},
	{"MoNo Mixer", "ADCL Playback Switch", "Left Rec Mixer"},
	{"MoNo Mixer", "ADCR Playback Switch", "Right Rec Mixer"},
	{"MoNo Mixer", "Mic1 Playback Switch", "Mic1 PGA"},
	{"MoNo Mixer", "Mic2 Playback Switch", "Mic2 PGA"},
	{"MoNo Mixer", "DAC Mixer Playback Switch", "DAC Mixer"},
	{"MoNo Mixer", "Voice DAC Playback Switch", "VoDAC PGA"},

	/* hp mixer */
	{"HP Mixer", NULL, "Left HP Mixer"},
	{"HP Mixer", NULL, "Right HP Mixer"},

	/* spkout mux */
	{"SPKOUT Mux", "HP Mixer", "HP Mixer"},
	{"SPKOUT Mux", "SPK Mixer", "SPK Mixer"},
	{"SPKOUT Mux", "Mono Mixer", "MoNo Mixer"},

	/* hpl out mux */
	{"HPLOUT Mux", "HPL Mixer", "Left HP Mixer"},

	/* hpr out mux */
	{"HPROUT Mux", "HPR Mixer", "Right HP Mixer"},

	/* aux out mux */
	{"AUXOUT Mux", "HP Mixer", "HP Mixer"},
	{"AUXOUT Mux", "SPK Mixer", "SPK Mixer"},
	{"SPKOUT Mux", "Mono Mixer", "MoNo Mixer"},

	/* spkl out pga */
	{"SPKL Out PGA", NULL, "SPKOUT Mux"},

	/* spkr out pga */
	{"SPKR Out PGA", NULL, "SPKOUT Mux"},

	/* hpl out pga */
	{"HPL Out PGA", NULL, "HPLOUT Mux"},

	/* hpr out pga */
	{"HPR Out PGA", NULL, "HPROUT Mux"},

	/* aux out pga */
	{"AUX Out PGA", NULL, "AUXOUT Mux"},

	/* left adc */
	{"Left ADC", NULL, "Left Rec Mixer"},

	/* right adc */
	{"Right ADC", NULL, "Right Rec Mixer"},

	/* output */
	{"SPKL", NULL, "SPKL Out PGA"},
	{"SPKR", NULL, "SPKR Out PGA"},
	{"HPL", NULL, "HPL Out PGA"},
	{"HPR", NULL, "HPR Out PGA"},
	{"AUX", NULL, "AUX Out PGA"},
};

static int alc5625_add_widgets(struct snd_soc_codec *codec)
{
	struct snd_soc_dapm_context *dapm = &codec->dapm;
	int ret;

	ret = snd_soc_dapm_new_controls(dapm, alc5625_dapm_widgets,
					ARRAY_SIZE(alc5625_dapm_widgets));
	if (ret)
		return ret;

	ret = snd_soc_dapm_add_routes(dapm, audio_map, ARRAY_SIZE(audio_map));
	if (ret)
		return ret;

	return 0;
}

struct _pll_div {
	u32 pll_in;
	u32 pll_out;
	u16 regvalue;
};

/*
 * watch out!
 * our codec support you to select different source as pll input,
 * but if you use both of the I2S audio interface and pcm interface
 * instantially. The two DAI must have the same pll setting params,
 * so you have to offer the same pll input, and set our codec's sysclk
 * the same one, we suggest 24576000.
 */
static const struct _pll_div codec_master_pll1_div[] = {
	{ 2048000,   8192000, 0x0ea0},
	{ 3686400,   8192000, 0x4e27},
	{12000000,   8192000, 0x456b},
	{13000000,   8192000, 0x495f},
	{13100000,   8192000, 0x0320},
	{ 2048000,  11289600, 0xf637},
	{ 3686400,  11289600, 0x2f22},
	{12000000,  11289600, 0x3e2f},
	{13000000,  11289600, 0x4d5b},
	{13100000,  11289600, 0x363b},
	{ 2048000,  16384000, 0x1ea0},
	{ 3686400,  16384000, 0x9e27},
	{12000000,  16384000, 0x452b},
	{13000000,  16384000, 0x542f},
	{13100000,  16384000, 0x03a0},
	{ 2048000,  16934400, 0xe625},
	{ 3686400,  16934400, 0x9126},
	{12000000,  16934400, 0x4d2c},
	{13000000,  16934400, 0x742f},
	{13100000,  16934400, 0x3c27},
	{ 2048000,  22579200, 0x2aa0},
	{ 3686400,  22579200, 0x2f20},
	{12000000,  22579200, 0x7e2f},
	{13000000,  22579200, 0x742f},
	{13100000,  22579200, 0x3c27},
	{ 2048000,  24576000, 0x2ea0},
	{ 3686400,  24576000, 0xee27},
	{12000000,  24576000, 0x2915},
	{13000000,  24576000, 0x772e},
	{13100000,  24576000, 0x0d20},
	{26000000,  24576000, 0x2027},
	{26000000,  22579200, 0x392f},
	{24576000,  22579200, 0x0921},
	{24576000,  24576000, 0x02a0},
};

static const struct _pll_div codec_bclk_pll1_div[] = {
	{ 256000,  4096000, 0x3ea0},
	{ 352800,  5644800, 0x3ea0},
	{ 512000,  8192000, 0x3ea0},
	{ 705600, 11289600, 0x3ea0},
	{1024000, 16384000, 0x3ea0},
	{1411200, 22579200, 0x3ea0},
	{1536000, 24576000, 0x3ea0},
	{2048000, 16384000, 0x1ea0},
	{2822400, 22579200, 0x1ea0},
	{3072000, 24576000, 0x1ea0},
	{ 705600, 11289600, 0x3ea0},
	{ 705600,  8467200, 0x3ab0},
};

static const struct _pll_div codec_vbclk_pll1_div[] = {
	{ 256000,  4096000, 0x3ea0},
	{ 352800,  5644800, 0x3ea0},
	{ 512000,  8192000, 0x3ea0},
	{ 705600, 11289600, 0x3ea0},
	{1024000, 16384000, 0x3ea0},
	{1411200, 22579200, 0x3ea0},
	{1536000, 24576000, 0x3ea0},
	{2048000, 16384000, 0x1ea0},
	{2822400, 22579200, 0x1ea0},
	{3072000, 24576000, 0x1ea0},
	{ 705600, 11289600, 0x3ea0},
	{ 705600,  8467200, 0x3ab0},
};

struct _coeff_div_stereo {
	unsigned int mclk;
	unsigned int rate;
	unsigned int reg60;
	unsigned int reg62;
};

struct _coeff_div_voice {
	unsigned int mclk;
	unsigned int rate;
	unsigned int reg64;
};

static const struct _coeff_div_stereo coeff_div_stereo[] = {
	/*
	 * bclk is config to 32fs, if codec is choose to
	 * be slave mode , input bclk should be 32*fs
	 */
	{24576000, 48000, 0x3174, 0x1010},
	{12288000, 48000, 0x1174, 0x0000},
	{18432000, 48000, 0x2174, 0x1111},
	{36864000, 48000, 0x2274, 0x2020},
	{49152000, 48000, 0xf074, 0x3030},
	{24576000, 48000, 0x3172, 0x1010},
	{24576000,  8000, 0xB274, 0x2424},
	{24576000, 16000, 0xB174, 0x2222},
	{24576000, 32000, 0xB074, 0x2121},
	{22579200, 11025, 0X3374, 0x1414},
	{22579200, 22050, 0X3274, 0x1212},
	{22579200, 44100, 0X3174, 0x1010},
	{0, 0, 0, 0},
};

static const struct _coeff_div_voice coeff_div_voice[] = {
	/*
	 * bclk is config to 32fs, if codec is choose to be slave mode,
	 * input bclk should be 32*fs
	 */
	{24576000, 16000, 0x2622},
	{24576000,  8000, 0x2824},
	{0, 0, 0},
};

static int get_coeff(unsigned int mclk, unsigned int rate, int mode)
{
	int i;

	if (!mode) {
		for (i = 0; i < ARRAY_SIZE(coeff_div_stereo); i++) {
			if ((coeff_div_stereo[i].rate == rate) &&
				(coeff_div_stereo[i].mclk == mclk))
				return i;
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(coeff_div_voice); i++) {
			if ((coeff_div_voice[i].rate == rate) &&
				(coeff_div_voice[i].mclk == mclk))
				return i;
		}
	}

	return -EINVAL;
	printk(KERN_ERR "can't find a matched mclk and rate in %s\n",
			(mode ? "coeff_div_voice[]" : "coeff_div_audio[]"));
}

static int alc5625_codec_set_dai_pll(struct snd_soc_dai *codec_dai,
					int pll_id, int source,
					unsigned int freq_in,
					unsigned int freq_out)
{
	int i;
	int pll_src_regval = 0;
	struct snd_soc_codec *codec = codec_dai->codec;
	const struct _pll_div *codec_pll_div = NULL;
	int pll_div_count = 0;

	if (pll_id < ALC5625_PLL1_FROM_MCLK || pll_id > ALC5625_PLL1_FROM_VBCLK)
		return -EINVAL;

	if (!freq_in || !freq_out)
		return 0;

	switch (pll_id) {
	case ALC5625_PLL1_FROM_MCLK:
		codec_pll_div = codec_master_pll1_div;
		pll_div_count = ARRAY_SIZE(codec_master_pll1_div);
		break;
	case ALC5625_PLL1_FROM_BCLK:
		codec_pll_div = codec_bclk_pll1_div;
		pll_div_count = ARRAY_SIZE(codec_bclk_pll1_div);
		pll_src_regval = 0x2000;
		break;
	case ALC5625_PLL1_FROM_VBCLK:
		codec_pll_div = codec_vbclk_pll1_div;
		pll_div_count = ARRAY_SIZE(codec_vbclk_pll1_div);
		pll_src_regval = 0x3000;
	default:
		return -EINVAL;
	}

	for (i = 0; i < pll_div_count; i++)
		if ((freq_in == codec_pll_div[i].pll_in) &&
				(freq_out == codec_pll_div[i].pll_out)) {
			alc5625_write(codec,
					ALC5625_GEN_CTRL_REG2,
					pll_src_regval);

			/* set pll code */
			alc5625_write(codec,
					ALC5625_PLL_CTRL,
					codec_pll_div[i].regvalue);

			/* enable pll power */
			alc5625_write_mask(codec,
					ALC5625_PWR_MANAG_ADD2,
					0x8000, 0x8000);

			alc5625_write_mask(codec,
					ALC5625_GEN_CTRL_REG1,
					0x8000, 0x8000);

			return 0;
		}

	return -EINVAL;
}

static int alc5625_hifi_codec_set_dai_sysclk(struct snd_soc_dai *codec_dai,
						int clk_id, unsigned int freq,
						int dir)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct alc5625_priv *alc5625 = snd_soc_codec_get_drvdata(codec);

	if ((freq >= (256 * 8000)) && (freq <= (512 * 48000))) {
		alc5625->stereo_sysclk = freq;
		return 0;
	}

	printk(KERN_ERR "unsupported sysclk freq %u for audio i2s\n", freq);
	alc5625->stereo_sysclk = DEFAULT_SYSCLK;

	return 0;
}

static int alc5625_voice_codec_set_dai_sysclk(struct snd_soc_dai *codec_dai,
						int clk_id, unsigned int freq,
						int dir)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	struct alc5625_priv *alc5625 = snd_soc_codec_get_drvdata(codec);

	if ((freq >= (256 * 8000)) && (freq <= (512 * 48000))) {
		alc5625->voice_sysclk = freq;
		return 0;
	}

	printk(KERN_ERR "unsupported sysclk freq %u for voice pcm\n", freq);
	alc5625->voice_sysclk = DEFAULT_SYSCLK;

	return 0;
}

static int alc5625_hifi_pcm_hw_params(struct snd_pcm_substream *substream,
					struct snd_pcm_hw_params *params,
					struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct alc5625_priv *alc5625 = snd_soc_codec_get_drvdata(codec);
	unsigned int iface;

	int rate = params_rate(params);
	int coeff = get_coeff(alc5625->stereo_sysclk, rate, 0);

	iface = alc5625_read(codec, ALC5625_MAIN_SDP_CTRL) & 0xfff3;

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
		/* Nothing to be done */
		break;
	case SNDRV_PCM_FORMAT_S20_3LE:
		iface |= 0x0004;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		iface |= 0x0008;
		break;
	case SNDRV_PCM_FORMAT_S8:
		iface |= 0x000c;
	}

	alc5625_write(codec, ALC5625_MAIN_SDP_CTRL, iface);

	/* power i2s and dac ref */
	alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
				0xc801, 0xc801);
	if (coeff >= 0) {
		alc5625_write(codec, ALC5625_STEREO_DAC_CLK_CTRL1,
					coeff_div_stereo[coeff].reg60);
		alc5625_write(codec, ALC5625_STEREO_DAC_CLK_CTRL2,
					coeff_div_stereo[coeff].reg62);
	}

	return 0;
}

static int alc5625_voice_pcm_hw_params(struct snd_pcm_substream *substream,
		struct snd_pcm_hw_params *params,
		struct snd_soc_dai *dai)
{
	struct snd_soc_codec *codec = dai->codec;
	struct alc5625_priv *alc5625 = snd_soc_codec_get_drvdata(codec);
	unsigned int iface;
	int rate = params_rate(params);
	int coeff = get_coeff(alc5625->voice_sysclk, rate, 1);

	iface = alc5625_read(codec, ALC5625_EXTEND_SDP_CTRL) & 0xfff3;
	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
		/* Nothing to be done */
		break;
	case SNDRV_PCM_FORMAT_S20_3LE:
		iface |= 0x0004;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		iface |= 0x0008;
		break;
	case SNDRV_PCM_FORMAT_S8:
		iface |= 0x000c;
	}

	/* power i2s and dac ref */
	alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
				0x0801, 0x0801);
	alc5625_write(codec, ALC5625_EXTEND_SDP_CTRL, iface);
	if (coeff >= 0)
		alc5625_write(codec, ALC5625_VOICE_DAC_PCMCLK_CTRL1,
					coeff_div_voice[coeff].reg64);

	return 0;
}

static int alc5625_hifi_codec_set_dai_fmt(struct snd_soc_dai *codec_dai,
						unsigned int fmt)
{

	struct snd_soc_codec *codec = codec_dai->codec;
	u16 iface = 0;

	/* set master/slave interface */
	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM:
		iface = 0x0000;
		break;
	case SND_SOC_DAIFMT_CBS_CFS:
		iface = 0x8000;
		break;
	default:
		return -EINVAL;
	}

	/* interface format */
	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		/* Nothing to be done */
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		iface |= 0x0001;
		break;
	case SND_SOC_DAIFMT_DSP_A:
		iface |= 0x0002;
		break;
	case SND_SOC_DAIFMT_DSP_B:
		iface |= 0x0003;
		break;
	default:
		return -EINVAL;
	}

	/* clock inversion */
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
		/* Nothing to be done */
		break;
	case SND_SOC_DAIFMT_IB_NF:
		iface |= 0x0080;
		break;
	default:
		return -EINVAL;
	}

	alc5625_write(codec, ALC5625_MAIN_SDP_CTRL, iface);
	return 0;
}

static int alc5625_voice_codec_set_dai_fmt(struct snd_soc_dai *codec_dai,
						unsigned int fmt)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	int iface;

	/*set slave/master mode*/
	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM:
		iface = 0x0000;
		break;
	case SND_SOC_DAIFMT_CBS_CFS:
		iface = 0x4000;
		break;
	default:
		return -EINVAL;
	}

	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		/* Nothing to be done */
		break;
	case SND_SOC_DAIFMT_LEFT_J:
		iface |= 0x0001;
		break;
	case SND_SOC_DAIFMT_DSP_A:
		iface |= 0x0002;
		break;
	case SND_SOC_DAIFMT_DSP_B:
		iface |= 0x0003;
		break;
	default:
		return -EINVAL;
	}

	/*clock inversion*/
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
		/* Nothing to be done */
		break;
	case SND_SOC_DAIFMT_IB_NF:
		iface |= 0x0080;
		break;
	default:
		return -EINVAL;
	}

	iface |= 0x8000; /* enable vopcm */
	alc5625_write(codec, ALC5625_EXTEND_SDP_CTRL, iface);
	return 0;
}

static int alc5625_hifi_codec_mute(struct snd_soc_dai *dai, int mute)
{
	struct snd_soc_codec *codec = dai->codec;

	if (mute)
		alc5625_write_mask(codec, ALC5625_STEREO_DAC_VOL,
					0x8080, 0x8080);
	else
		alc5625_write_mask(codec, ALC5625_STEREO_DAC_VOL,
					0x0000, 0x8080);
	return 0;
}

static int alc5625_voice_codec_mute(struct snd_soc_dai *dai, int mute)
{
	struct snd_soc_codec *codec = dai->codec;

	if (mute)
		alc5625_write_mask(codec, ALC5625_VOICE_DAC_OUT_VOL,
					0x1000, 0x1000);
	else
		alc5625_write_mask(codec, ALC5625_VOICE_DAC_OUT_VOL,
					0x0000, 0x1000);
	return 0;
}

static int alc5625_set_bias_level(struct snd_soc_codec *codec,
		enum snd_soc_bias_level level)
{
	switch (level) {
	case SND_SOC_BIAS_ON:
		break;
	case SND_SOC_BIAS_PREPARE:
		alc5625_write(codec, ALC5625_PD_CTRL_STAT, 0x0000);
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD2,
					0x2000, 0x2000);
		alc5625_write_mask(codec, ALC5625_PWR_MANAG_ADD1,
					0x000e, 0x000e);
		break;
	case SND_SOC_BIAS_STANDBY:
		break;
	case SND_SOC_BIAS_OFF:
		alc5625_write_mask(codec,
			ALC5625_HP_OUT_VOL, 0x8080, 0x8080); /* mute hp */
		alc5625_write_mask(codec, ALC5625_SPK_OUT_VOL,
				0x8080, 0x8080); /* mute spk */
		alc5625_write(codec, ALC5625_PWR_MANAG_ADD3,
				0x0000); /* power off all bit */
		alc5625_write(codec, ALC5625_PWR_MANAG_ADD1,
				0x0000); /* power off all bit */
		alc5625_write(codec, ALC5625_PWR_MANAG_ADD2,
				0x0000); /* power off all bit */
		break;
	}
	codec->dapm.bias_level = level;
	return 0;
}


#define ALC5625_STEREO_RATES	SNDRV_PCM_RATE_8000_48000

#define ALC5626_VOICE_RATES	(SNDRV_PCM_RATE_16000 | SNDRV_PCM_RATE_8000)

#define ALC5625_FORMATS (SNDRV_PCM_FMTBIT_S16_LE |\
			SNDRV_PCM_FMTBIT_S20_3LE |\
			SNDRV_PCM_FMTBIT_S24_LE |\
			SNDRV_PCM_FMTBIT_S8)

static struct snd_soc_dai_ops alc5625_dai_ops_hifi = {

	.hw_params	= alc5625_hifi_pcm_hw_params,
	.set_fmt	= alc5625_hifi_codec_set_dai_fmt,
	.set_pll	= alc5625_codec_set_dai_pll,
	.set_sysclk	= alc5625_hifi_codec_set_dai_sysclk,
	.digital_mute	= alc5625_hifi_codec_mute,
};

static struct snd_soc_dai_ops alc5625_dai_ops_voice = {

	.hw_params	= alc5625_voice_pcm_hw_params,
	.set_fmt	= alc5625_voice_codec_set_dai_fmt,
	.set_pll	= alc5625_codec_set_dai_pll,
	.set_sysclk	= alc5625_voice_codec_set_dai_sysclk,
	.digital_mute	= alc5625_voice_codec_mute,
};

static struct snd_soc_dai_driver alc5625_dai[] = {
	{
		.name = "alc5625-aif1",
		.playback = {
			.stream_name = "HiFi Playback",
			.channels_min = 2,
			.channels_max = 2,
			.rates = ALC5625_STEREO_RATES,
			.formats = ALC5625_FORMATS,
		},
		.capture = {
			.stream_name = "HiFi Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = ALC5625_STEREO_RATES,
			.formats = ALC5625_FORMATS,
		},
		.ops = &alc5625_dai_ops_hifi,
	},

	/* voice codec dai */
	{
		.name = "ALC5625 Voice",
		.id = 1,
		.playback = {
			.stream_name = "Voice Playback",
			.channels_min = 1,
			.channels_max = 1,
			.rates = ALC5626_VOICE_RATES,
			.formats = ALC5625_FORMATS,
		},
		.capture = {
			.stream_name = "Voice Capture",
			.channels_min = 1,
			.channels_max = 1,
			.rates = ALC5626_VOICE_RATES,
			.formats = ALC5625_FORMATS,
		},

		.ops = &alc5625_dai_ops_voice,

	},
};

static void alc5625_work(struct work_struct *work)
{
	struct snd_soc_codec *codec =
		container_of(work, struct snd_soc_codec,\
			dapm.delayed_work.work);
	alc5625_set_bias_level(codec, codec->dapm.bias_level);
}


static int alc5625_codec_init(struct snd_soc_codec *codec)
{

	int ret = 0;

	codec->read = alc5625_read;
	codec->write = alc5625_write;
	codec->hw_write = (hw_write_t)i2c_master_send;
	codec->num_dai = 2;
	codec->reg_cache = kmemdup(alc5625_reg, sizeof(alc5625_reg),
					GFP_KERNEL);
	if (codec->reg_cache == NULL)
		return -ENOMEM;

	alc5625_reset(codec);

	alc5625_write(codec, ALC5625_PD_CTRL_STAT, 0);
	alc5625_write(codec, ALC5625_PWR_MANAG_ADD1, PWR_MAIN_BIAS);
	alc5625_write(codec, ALC5625_PWR_MANAG_ADD2, PWR_MIXER_VREF);
	alc5625_reg_init(codec);
	alc5625_set_bias_level(codec, SND_SOC_BIAS_PREPARE);
	codec->dapm.bias_level = SND_SOC_BIAS_STANDBY;
	schedule_delayed_work(&codec->dapm.delayed_work, msecs_to_jiffies(80));

	ret = snd_soc_add_codec_controls(codec, alc5625_snd_ctrls,
					ARRAY_SIZE(alc5625_snd_ctrls));
	if (ret)
		return ret;
	alc5625_add_widgets(codec);
	if (ret)
		return ret;

	return 0;
}

#ifdef CONFIG_PM
static int alc5625_suspend(struct snd_soc_codec *codec)
{
	alc5625_set_bias_level(codec, SND_SOC_BIAS_OFF);

	return 0;
}

static int alc5625_resume(struct snd_soc_codec *codec)
{
	alc5625_reset(codec);
	alc5625_write(codec, ALC5625_PD_CTRL_STAT, 0);
	alc5625_write(codec, ALC5625_PWR_MANAG_ADD1, PWR_MAIN_BIAS);
	alc5625_write(codec, ALC5625_PWR_MANAG_ADD2, PWR_MIXER_VREF);
	alc5625_reg_init(codec);

	/* charge alc5625 caps */
	if (codec->dapm.suspend_bias_level == SND_SOC_BIAS_ON) {
		alc5625_set_bias_level(codec, SND_SOC_BIAS_PREPARE);
		codec->dapm.bias_level = SND_SOC_BIAS_ON;
		schedule_delayed_work(&codec->dapm.delayed_work,
				msecs_to_jiffies(100));
	}

	return 0;
}
#else
#define alc5625_suspend NULL
#define alc5625_resume NULL
#endif

static int alc5625_probe(struct snd_soc_codec *codec)
{
	struct alc5625_priv *alc5625 = snd_soc_codec_get_drvdata(codec);
	int ret;

	codec->control_data = alc5625->regmap;
	ret = snd_soc_codec_set_cache_io(codec, 8, 16, alc5625->control_type);
	if (ret < 0) {
		dev_err(codec->dev, "Failed to set cache I/O: %d\n", ret);
		return ret;
	}

	mutex_init(&codec->mutex);
	INIT_DELAYED_WORK(&codec->dapm.delayed_work, alc5625_work);

	ret = alc5625_codec_init(codec);

	return ret;
}

static int run_delayed_work(struct delayed_work *dwork)
{
	int ret;

	/* cancel any work waiting to be queued. */
	ret = cancel_delayed_work(dwork);

	/* if there was any work waiting then we run it now and
	 * wait for it's completion */
	if (ret) {
		schedule_delayed_work(dwork, 0);
		flush_scheduled_work();
	}
	return ret;
}

static int alc5625_remove(struct snd_soc_codec *codec)
{
	if (codec->control_data)
		alc5625_set_bias_level(codec, SND_SOC_BIAS_OFF);
	run_delayed_work(&codec->dapm.delayed_work);
	return 0;
}

static struct snd_soc_codec_driver soc_codec_dev_alc5625 = {
	.probe			= alc5625_probe,
	.remove			= alc5625_remove,
	.suspend		= alc5625_suspend,
	.resume			= alc5625_resume,
	.read			= alc5625_read,
	.write			= alc5625_write,
	.set_bias_level		= alc5625_set_bias_level,
	.reg_cache_size		= ARRAY_SIZE(alc5625_reg)*2,
	.reg_cache_default	= alc5625_reg,
	.reg_word_size		= 2,
};

static const struct regmap_config alc5625_i2c_regmap_config = {
	.val_bits = 16,
	.reg_bits = 8,
};


#if defined(CONFIG_I2C) || defined(CONFIG_I2C_MODULE)
static int alc5625_i2c_probe(struct i2c_client *i2c,
		const struct i2c_device_id *id)
{
	struct alc5625_priv *alc5625;
	int ret;

	alc5625 = kzalloc(sizeof(struct alc5625_priv), GFP_KERNEL);
	if (alc5625 == NULL)
		return -ENOMEM;

	alc5625->regmap = regmap_init_i2c(i2c, &alc5625_i2c_regmap_config);
	if (IS_ERR(alc5625->regmap)) {
		ret = PTR_ERR(alc5625->regmap);
		goto err_free;
	}

	i2c_set_clientdata(i2c, alc5625);
	alc5625->control_data = i2c;
	alc5625->control_type = SND_SOC_REGMAP;

	ret = snd_soc_register_codec(&i2c->dev, &soc_codec_dev_alc5625,
					alc5625_dai, ARRAY_SIZE(alc5625_dai));

	if (ret < 0)
		goto err_regmap;

	return ret;

err_regmap:
	regmap_exit(alc5625->regmap);
err_free:
	if (ret < 0)
		kfree(alc5625);
	return ret;
}

static int alc5625_i2c_remove(struct i2c_client *client)
{
	struct alc5625_priv *alc5625 = i2c_get_clientdata(client);

	snd_soc_unregister_codec(&client->dev);
	regmap_exit(alc5625->regmap);
	kfree(i2c_get_clientdata(client));
	return 0;
}

static const struct i2c_device_id alc5625_i2c_id[] = {
	{ "alc5625", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, alc5625_i2c_id);

static struct i2c_driver alc5625_i2c_driver = {
	.driver = {
		.name = "alc5625-codec",
		.owner = THIS_MODULE,
	},
	.probe		= alc5625_i2c_probe,
	.remove		= alc5625_i2c_remove,
	.id_table	= alc5625_i2c_id,
};
#endif

static int __init alc5625_modinit(void)
{
	int ret = 0;
#if defined(CONFIG_I2C) || defined(CONFIG_I2C_MODULE)
	ret = i2c_add_driver(&alc5625_i2c_driver);
	if (ret != 0) {
		printk(KERN_ERR "Failed to register ALC5625 I2C driver: %d\n",
				ret);
	}
#endif
	return ret;
}
module_init(alc5625_modinit);

static void __exit alc5625_exit(void)
{
#if defined(CONFIG_I2C) || defined(CONFIG_I2C_MODULE)
	i2c_del_driver(&alc5625_i2c_driver);
#endif
}
module_exit(alc5625_exit);

MODULE_DESCRIPTION("ASoC ALC5625 driver");
MODULE_LICENSE("GPL");

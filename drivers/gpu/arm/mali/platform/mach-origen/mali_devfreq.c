 /*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *	Vikas Sajjan <vikas.sajjan@samsung.com>
 *
 * EXYNOS4 - MALI frequency/voltage scaling support in DEVFREQ framework
 *	This version supports only EXYNOS4412 only.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/io.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/suspend.h>
#include <linux/opp.h>
#include <linux/devfreq.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/module.h>

#include <mach/regs-clock.h>
#include "mali_kernel_common.h"
#include "mali_osk.h"
#include "mali_platform.h"
#include "mali_devfreq.h"
#include <plat/map-s5p.h>

/* dvfs status */
struct mali_dvfs_status maliDvfsStatus;

#define MAX_MALI_DVFS_STEPS 4
#define MALI_DVFS_STEPS 4

int mali_dvfs_control;

struct mali_dvfs_threshold_tbl {
	unsigned int downthreshold;
	unsigned int upthreshold;
};

struct mali_dvfs_staycount {
	unsigned int staycount;
};

struct mali_dvfs_threshold_tbl mali_dvfs_threshold[MALI_DVFS_STEPS] = {
	{0, 70},
	{50, 70},
	{50, 85},
	{75, 100}
};

struct mali_dvfs_staycount mali_dvfs_staycount[MALI_DVFS_STEPS] = {
	/*step 0*/{1},
	/*step 1*/{1},
	/*step 2*/{1},
	/*step 3*/{1}
};

/* dvfs information */
/* L0 = 440Mhz, 1.025V */
/* L1 = 350Mhz, 0.95V  */
/* L2 = 266Mhz, 0.90V  */
/* L3 = 160Mhz, 0.875V */

int step0_clk = 160;
int step0_vol = 875000;
int step1_clk = 266;
int step1_vol = 900000;
int step0_up = 70;
int step1_down = 50;
int step2_clk = 350;
int step2_vol = 950000;
int step1_up = 70;
int step2_down = 50;
int step3_clk = 440;
int step3_vol = 1025000;
int step2_up = 85;
int step3_down = 75;

struct mali_dvfs_stp {
	int clk;
	int vol;
};

struct mali_dvfs_tbl mali_dvfs_value[MALI_DVFS_STEPS] = {
	{ 160, 1000000, 875000 },
	{ 266, 1000000, 900000 },
	{ 350, 1000000, 950000 },
	{ 440, 1000000, 1025000} };

struct mali_dvfs_stp step[MALI_DVFS_STEPS] = {
	/* step 0 clk */ { 160, 875000 },
	/* step 1 clk */ { 266, 900000 },
	/* step 2 clk */ { 350, 950000 },
	/* step 3 clk */ { 440, 1025000 }
};

int change_dvfs_tableset(int change_clk, int change_step)
{
	if (change_clk < mali_dvfs_value[1].clock) {
		mali_dvfs_value[change_step].clock = mali_dvfs_value[0].clock;
		mali_dvfs_value[change_step].vol = mali_dvfs_value[0].vol;
	} else if (change_clk < mali_dvfs_value[2].clock && change_clk >=
						mali_dvfs_value[1].clock) {
		mali_dvfs_value[change_step].clock = mali_dvfs_value[1].clock;
		mali_dvfs_value[change_step].vol = mali_dvfs_value[1].vol;
	} else if (change_clk < mali_dvfs_value[3].clock && change_clk >=
						mali_dvfs_value[2].clock) {
		mali_dvfs_value[change_step].clock = mali_dvfs_value[2].clock;
		mali_dvfs_value[change_step].vol = mali_dvfs_value[2].vol;
	} else {
		mali_dvfs_value[change_step].clock = mali_dvfs_value[3].clock;
		mali_dvfs_value[change_step].vol = mali_dvfs_value[3].vol;
	}

	if (maliDvfsStatus.currentStep == change_step) {
		/* change the voltage */
		mali_regulator_set_voltage(mali_dvfs_value[change_step].vol,
					mali_dvfs_value[change_step].vol);
		/* change the clock */
		mali_clk_set_rate(mali_dvfs_value[change_step].clock,
					mali_dvfs_value[change_step].freq);
	}

	return mali_dvfs_value[change_step].clock;
}

mali_bool set_mali_dvfs_current_step(unsigned int step)
{
	_mali_osk_lock_wait(mali_dvfs_lock, _MALI_OSK_LOCKMODE_RW);
	maliDvfsStatus.currentStep = step;
	_mali_osk_lock_signal(mali_dvfs_lock, _MALI_OSK_LOCKMODE_RW);
	return MALI_TRUE;
}

static mali_bool set_mali_dvfs_status(u32 step, mali_bool boostup)
{
	u32 validatedStep = step;

	if (mali_regulator_get_usecount() == 0)
		return MALI_FALSE;

	if (boostup) {
		/* change the voltage */
		mali_regulator_set_voltage(mali_dvfs_value[step].vol,
						mali_dvfs_value[step].vol);
		/* change the clock */
		mali_clk_set_rate(mali_dvfs_value[step].clock,
						mali_dvfs_value[step].freq);
	} else {
		/* change the clock */
		mali_clk_set_rate(mali_dvfs_value[step].clock,
						mali_dvfs_value[step].freq);
		/* change the voltage */
		mali_regulator_set_voltage(mali_dvfs_value[step].vol,
						mali_dvfs_value[step].vol);
	}

	set_mali_dvfs_current_step(validatedStep);

	/* for future use */
	maliDvfsStatus.pCurrentDvfs = &mali_dvfs_value[validatedStep];

	return MALI_TRUE;
}

static void mali_platform_waiting(u32 msec)
{
	unsigned int read_val;
	while (1) {
			read_val = _mali_osk_mem_ioread32(
					clk_register_map,
					0x00);
			if ((read_val & 0x8000) == 0x0000)
				break;
			/* 1000 -> 100 : 20101218 */
			_mali_osk_time_ubusydelay(100);
		}
}

static mali_bool change_mali_dvfs_status(u32 step, mali_bool boostup)
{
	if (!set_mali_dvfs_status(step, boostup))
		return MALI_FALSE;

	/* wait until clock and voltage is stablized */
	mali_platform_waiting(MALI_DVFS_WAITING); /* msec */
	return MALI_TRUE;
}

static	unsigned int decideNextStatus(unsigned int mali_dvfs_freq)
{
	static unsigned int level; /* 0:stay, 1:up */
	static int mali_dvfs_clk;

	if (!mali_dvfs_control && level == maliDvfsStatus.currentStep) {
		if (mali_dvfs_freq >
		(int)((mali_dvfs_value[maliDvfsStatus.currentStep].clock *
			mali_dvfs_value[maliDvfsStatus.currentStep].freq))
			&& level < MALI_DVFS_STEPS - 1) {
			level++;
		}
		if (mali_dvfs_freq <
		(int)((mali_dvfs_value[maliDvfsStatus.currentStep].clock *
			mali_dvfs_value[maliDvfsStatus.currentStep].freq))
			&& level > 0) {
			level--;
		}
	} else if (mali_dvfs_control == 999) {
		int i = 0;
		for (i = 0; i < MALI_DVFS_STEPS; i++)
			step[i].clk = mali_dvfs_value[i].clock;
#ifdef EXYNOS4_ASV_ENABLED
		mali_dvfs_table_update();
#endif
		i = 0;
		for (i = 0; i < MALI_DVFS_STEPS; i++)
			mali_dvfs_value[i].clock = step[i].clk;

		mali_dvfs_control = 0;
		level = 0;

		step0_clk = step[0].clk;
		change_dvfs_tableset(step0_clk, 0);

		step1_clk = step[1].clk;
		change_dvfs_tableset(step1_clk, 1);

		step2_clk = step[2].clk;
		change_dvfs_tableset(step2_clk, 2);

		step3_clk = step[3].clk;
		change_dvfs_tableset(step3_clk, 3);

	} else if (mali_dvfs_control != mali_dvfs_clk && mali_dvfs_control
			!= 999) {
		if (mali_dvfs_control < mali_dvfs_value[1].clock
						&& mali_dvfs_control > 0) {
			int i = 0;
			for (i = 0; i < MALI_DVFS_STEPS; i++)
				step[i].clk = mali_dvfs_value[0].clock;
		} else if (mali_dvfs_control < mali_dvfs_value[2].clock
			&& mali_dvfs_control >= mali_dvfs_value[1].clock) {
			int i = 0;
			for (i = 0; i < MALI_DVFS_STEPS; i++)
				step[i].clk = mali_dvfs_value[1].clock;
		} else if (mali_dvfs_control < mali_dvfs_value[3].clock
			&& mali_dvfs_control >= mali_dvfs_value[2].clock) {
			int i = 0;
			for (i = 0; i < MALI_DVFS_STEPS; i++)
				step[i].clk = mali_dvfs_value[2].clock;
		} else {
			int i = 0;
			for (i = 0; i < MALI_DVFS_STEPS; i++)
				step[i].clk  = mali_dvfs_value[3].clock;
		}

		step0_clk = step[0].clk;
		change_dvfs_tableset(step0_clk, 0);
		step1_clk = step[1].clk;
		change_dvfs_tableset(step1_clk, 1);
		step2_clk = step[2].clk;
		change_dvfs_tableset(step2_clk, 2);
		step3_clk = step[3].clk;
		change_dvfs_tableset(step3_clk, 3);
		level = maliDvfsStatus.currentStep;
	}

	mali_dvfs_clk = mali_dvfs_control;
	return level;
}

static unsigned int get_mali_dvfs_status(void)
{
	return maliDvfsStatus.currentStep;
}

static mali_bool mali_dvfs_status(u32 mali_dvfs_freq)
{
	unsigned int nextStatus = 0;
	unsigned int curStatus = 0;
	mali_bool boostup = MALI_FALSE;
	static int stay_count;
#ifdef EXYNOS4_ASV_ENABLED
	static mali_bool asv_applied = MALI_FALSE;
#endif
#ifdef EXYNOS4_ASV_ENABLED
	if (asv_applied == MALI_FALSE) {
		mali_dvfs_table_update();
		change_mali_dvfs_status(1, 0);
		asv_applied = MALI_TRUE;
		return MALI_TRUE;
	}
#endif
	/* decide next step */
	curStatus = get_mali_dvfs_status();
	nextStatus = decideNextStatus(mali_dvfs_freq);

	/* if next status is same with current status, don't change anything */
	if ((curStatus != nextStatus && stay_count == 0)) {
		/* check if boost up or not */
		if (nextStatus > maliDvfsStatus.currentStep)
			boostup = 1;
		/* change mali dvfs status */
		if (!change_mali_dvfs_status(nextStatus, boostup))
			return MALI_FALSE;
		stay_count =
		mali_dvfs_staycount[maliDvfsStatus.currentStep].staycount;
	} else {
		if (stay_count > 0)
			stay_count--;
	}
	return MALI_TRUE;
}

mali_bool init_mali_dvfs_status(int step)
{
	set_mali_dvfs_current_step(step);
	return MALI_TRUE;
}

void deinit_mali_dvfs_status(void)
{
	if (clk_register_map) {
		_mali_osk_mem_unmapioregion(CLK_DIV_STAT_G3D,
							0x20,
							clk_register_map);
		clk_register_map = 0;
	}
}

void mali_default_step_set(int step, mali_bool boostup)
{
	mali_clk_set_rate(mali_dvfs_value[step].clock,
				mali_dvfs_value[step].freq);
	if (maliDvfsStatus.currentStep == 1)
		set_mali_dvfs_status(step, boostup);
}

void mali_gpu_utilization_handler(u32 mali_dvfs_freq)
{
	int change_clk = 0;
	int change_step = 0;

	/* dvfs table change when clock was changed */
	if (step0_clk != mali_dvfs_value[0].clock) {
		MALI_PRINT(("::: step0_clk change to %d Mhz\n", step0_clk));
		change_clk = step0_clk;
		change_step = 0;
		step0_clk = change_dvfs_tableset(change_clk, change_step);
	}
	if (step1_clk != mali_dvfs_value[1].clock) {
		MALI_PRINT(("::: step1_clk change to %d Mhz\n", step1_clk));
		change_clk = step1_clk;
		change_step = 1;
		step1_clk = change_dvfs_tableset(change_clk, change_step);
	}
	if (step0_up != mali_dvfs_threshold[0].upthreshold) {
		MALI_PRINT(("::: step0_up change to %d %\n", step0_up));
		mali_dvfs_threshold[0].upthreshold = step0_up;
	}
	if (step1_down != mali_dvfs_threshold[1].downthreshold) {
		MALI_PRINT((":::step1_down change to %d %\n", step1_down));
		mali_dvfs_threshold[1].downthreshold = step1_down;
	}
	if (step2_clk != mali_dvfs_value[2].clock) {
		MALI_PRINT(("::: step2_clk change to %d Mhz\n", step2_clk));
		change_clk = step2_clk;
		change_step = 2;
		step2_clk = change_dvfs_tableset(change_clk, change_step);
	}
	if (step1_up != mali_dvfs_threshold[1].upthreshold) {
		MALI_PRINT((":::step1_up change to %d %\n", step1_up));
		mali_dvfs_threshold[1].upthreshold = step1_up;
	}
	if (step2_down != mali_dvfs_threshold[2].downthreshold) {
		MALI_PRINT((":::step2_down change to %d %\n", step2_down));
		mali_dvfs_threshold[2].downthreshold = step2_down;
	}
	if (step3_clk != mali_dvfs_value[3].clock) {
		MALI_PRINT(("::: step3_clk change to %d Mhz\n", step3_clk));
		change_clk = step3_clk;
		change_step = 3;
		step3_clk = change_dvfs_tableset(change_clk, change_step);
	}
	if (step2_up != mali_dvfs_threshold[2].upthreshold) {
		MALI_PRINT((":::step2_up change to %d %\n", step2_up));
		mali_dvfs_threshold[2].upthreshold = step2_up;
	}
	if (step3_down != mali_dvfs_threshold[3].downthreshold) {
		MALI_PRINT((":::step3_down change to %d %\n", step3_down));
		mali_dvfs_threshold[3].downthreshold = step3_down;
	}
#ifdef DEBUG
	mali_dvfs_value[0].vol = step0_vol;
	mali_dvfs_value[1].vol = step1_vol;
	mali_dvfs_value[2].vol = step2_vol;
	mali_dvfs_value[3].vol = step3_vol;
#endif
	MALI_DEBUG_PRINT(3, ("=== mali_dvfs_work_handler\n"));

	if (!mali_dvfs_status(mali_dvfs_freq))
		MALI_DEBUG_PRINT(1, ("error on mali dvfs status"
					"in mali_dvfs_work_handler"));

}
/** @brief Get MALI current running frequency
 *
 * This function gets the current running frequency of MALI
 *
 * @return frequency in Hz
 */
unsigned long get_mali_platform_cur_freq(void)
{
	unsigned long rate = 0;
	rate  = mali_clk_get_rate();
	return rate;
}

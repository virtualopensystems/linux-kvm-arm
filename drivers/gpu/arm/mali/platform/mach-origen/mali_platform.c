/*
 * Copyright (C) 2010-2012 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms
 * of the GNU General Public License version 2 as published by the Free
 * Software Foundation, and any use by you of this program  is subject
 * to the terms of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be
 * obtained from Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/driver.h>
#include "mali_kernel_common.h"
#include "mali_osk.h"
#include "mali_platform.h"
#include "mali_devfreq.h"
#include "mali_linux_pm.h"

#define MALI_DVFS_ENABLED 1

#define EXTXTALCLK_NAME         "ext_xtal"
#define VPLLSRCCLK_NAME         "vpll_src"
#define FOUTVPLLCLK_NAME        "fout_vpll"
#define SCLVPLLCLK_NAME         "sclk_vpll"
#define GPUMOUT1CLK_NAME        "mout_g3d1"

static struct clk  *ext_xtal_clock;
static struct clk  *vpll_src_clock;
static struct clk  *fout_vpll_clock;
static struct clk  *sclk_vpll_clock;

int  gpu_power_state;
static struct clk *mpll_clock;
static struct clk *mali_parent_clock;
struct regulator *g3d_regulator;
static struct clk *mali_clock;
static unsigned int GPU_MHZ = 1000000;
int mali_gpu_clk = 266;
int mali_gpu_vol = 900000;

mali_io_address clk_register_map;
_mali_osk_lock_t *mali_dvfs_lock;

mali_bool mali_clk_get(mali_bool bis_vpll);

unsigned long mali_clk_get_rate(void)
{
	return clk_get_rate(mali_clock);
}

mali_bool mali_clk_set_rate(unsigned int clk, unsigned int mhz)
{
	unsigned long rate = 0;
	mali_bool bis_vpll = MALI_TRUE;

	_mali_osk_lock_wait(mali_dvfs_lock, _MALI_OSK_LOCKMODE_RW);
	if (mali_clk_get(bis_vpll) == MALI_FALSE)
		return MALI_FALSE;
	rate = (unsigned long)clk * (unsigned long)mhz;
	if (bis_vpll) {
		clk_set_rate(fout_vpll_clock, (unsigned int)clk * GPU_MHZ);
		clk_set_parent(vpll_src_clock, ext_xtal_clock);
		clk_set_parent(sclk_vpll_clock, fout_vpll_clock);
		clk_set_parent(mali_parent_clock, sclk_vpll_clock);
		clk_set_parent(mali_clock, mali_parent_clock);
	} else {
		clk_set_parent(mali_parent_clock, mpll_clock);
		clk_set_parent(mali_clock, mali_parent_clock);
	}

	if (clk_enable(mali_clock) < 0)
		return MALI_FALSE;

	clk_set_rate(mali_clock, rate);
	rate = clk_get_rate(mali_clock);

	if (bis_vpll)
		mali_gpu_clk = (int)(rate / mhz);
	else
		mali_gpu_clk = (int)((rate + 500000) / mhz);

	GPU_MHZ = mhz;

	mali_clk_put(MALI_FALSE);

	_mali_osk_lock_signal(mali_dvfs_lock, _MALI_OSK_LOCKMODE_RW);
	return MALI_TRUE;
}

int mali_regulator_get_usecount(void)
{
	struct regulator_dev *rdev;
	if (g3d_regulator == NULL || g3d_regulator->rdev == NULL)
		return 0;
	rdev = g3d_regulator->rdev;
	return rdev->use_count;
}

void mali_regulator_disable(void)
{
	if (g3d_regulator == NULL)
		return;
	regulator_disable(g3d_regulator);
}

void mali_regulator_enable(void)
{
	if (g3d_regulator == NULL)
		return;
	regulator_enable(g3d_regulator);
}

void mali_regulator_set_voltage(int min_uV, int max_uV)
{
	int voltage;
	if (g3d_regulator == NULL)
		return;
	regulator_set_voltage(g3d_regulator, min_uV, max_uV);
	voltage = regulator_get_voltage(g3d_regulator);
	mali_gpu_vol = voltage;
}

mali_bool mali_clk_get(mali_bool bis_vpll)
{
	if (bis_vpll == MALI_TRUE) {
		if (ext_xtal_clock == NULL) {
			ext_xtal_clock = clk_get(NULL, EXTXTALCLK_NAME);
			if (IS_ERR(ext_xtal_clock))
				return MALI_FALSE;
		}

		if (vpll_src_clock == NULL) {
			vpll_src_clock = clk_get(NULL, VPLLSRCCLK_NAME);
			if (IS_ERR(vpll_src_clock))
				return MALI_FALSE;
		}

		if (fout_vpll_clock == NULL) {
			fout_vpll_clock = clk_get(NULL, FOUTVPLLCLK_NAME);
			if (IS_ERR(fout_vpll_clock))
				return MALI_FALSE;
		}

		if (sclk_vpll_clock == NULL) {
			sclk_vpll_clock = clk_get(NULL, SCLVPLLCLK_NAME);
			if (IS_ERR(sclk_vpll_clock))
				return MALI_FALSE;
		}

		if (mali_parent_clock == NULL) {
			mali_parent_clock = clk_get(NULL, GPUMOUT1CLK_NAME);
			if (IS_ERR(mali_parent_clock))
				return MALI_FALSE;
		} /* mpll */
	} else	{
		if (mpll_clock == NULL) {
			mpll_clock = clk_get(NULL, MPLLCLK_NAME);

			if (IS_ERR(mpll_clock))
				return MALI_FALSE;
		}

		if (mali_parent_clock == NULL) {
			mali_parent_clock = clk_get(NULL, GPUMOUT0CLK_NAME);
			if (IS_ERR(mali_parent_clock))
				return MALI_FALSE;
		}
	}
	/* mali clock get always */
	if (mali_clock == NULL) {
		mali_clock = clk_get(NULL, GPUCLK_NAME);
		if (IS_ERR(mali_clock))
			return MALI_FALSE;
	}
	return MALI_TRUE;
}

void mali_clk_put(mali_bool binc_mali_clock)
{
	if (mali_parent_clock) {
		clk_put(mali_parent_clock);
		mali_parent_clock = 0;
	}
	if (mpll_clock) {
		clk_put(mpll_clock);
		mpll_clock = 0;
	}
	if (sclk_vpll_clock) {
		clk_put(sclk_vpll_clock);
		sclk_vpll_clock = 0;
	}
	if (fout_vpll_clock) {
		clk_put(fout_vpll_clock);
		fout_vpll_clock = 0;
	}
	if (vpll_src_clock) {
		clk_put(vpll_src_clock);
		vpll_src_clock = 0;
	}
	if (ext_xtal_clock) {
		clk_put(ext_xtal_clock);
		ext_xtal_clock = 0;
	}
	if (binc_mali_clock == MALI_TRUE && mali_clock) {
		clk_put(mali_clock);
		mali_clock = 0;
	}
}

static mali_bool init_mali_clock(void)
{
	mali_bool ret = MALI_TRUE;
	unsigned long rate = 0;
	gpu_power_state = 0;

	if (mali_clock != 0)
		return ret; /* already initialized */

	mali_dvfs_lock = _mali_osk_lock_init(
			_MALI_OSK_LOCKFLAG_NONINTERRUPTABLE |
			_MALI_OSK_LOCKFLAG_ONELOCK, 0, 0);
	if (mali_dvfs_lock == NULL)
		return _MALI_OSK_ERR_FAULT;

	if (mali_clk_set_rate(mali_gpu_clk, GPU_MHZ) == MALI_FALSE) {
		ret = MALI_FALSE;
		goto err_clock_get;
	}

	rate = clk_get_rate(mali_clock);

	return MALI_TRUE;

err_clock_get:
	mali_clk_put(MALI_TRUE);
	return ret;
}

static mali_bool deinit_mali_clock(void)
{
	if (mali_clock == 0)
		return MALI_TRUE;

	if (g3d_regulator) {
		regulator_put(g3d_regulator);
		g3d_regulator = NULL;
	}
	mali_clk_put(MALI_TRUE);
	return MALI_TRUE;
}

static _mali_osk_errcode_t disable_mali_clocks(void)
{
	clk_disable(mali_clock);
	MALI_SUCCESS;
}

static _mali_osk_errcode_t enable_mali_clocks(void)
{
	int err;
	err = clk_enable(mali_clock);
	mali_clk_set_rate(mali_gpu_clk, GPU_MHZ);
	MALI_SUCCESS;
}

_mali_osk_errcode_t mali_platform_init(void)
{
#if MALI_DVFS_ENABLED
	MALI_CHECK(init_mali_clock(), _MALI_OSK_ERR_FAULT);
	init_mali_regulator();
	if (!clk_register_map)
		clk_register_map =
		_mali_osk_mem_mapioregion(CLK_DIV_STAT_G3D, 0x20, CLK_DESC);
	if (!init_mali_dvfs_status(MALI_DVFS_DEFAULT_STEP))
		MALI_DEBUG_PRINT(1, ("mali_platform_init failed\n"));
#endif
	MALI_SUCCESS;
}

_mali_osk_errcode_t mali_platform_deinit(void)
{
	deinit_mali_dvfs_status();

	deinit_mali_clock();

	if (clk_register_map) {
		_mali_osk_mem_unmapioregion(CLK_DIV_STAT_G3D,
						0x20,
						clk_register_map);
		clk_register_map = 0;
	}
	deinit_mali_regulator();
	MALI_SUCCESS;
}

_mali_osk_errcode_t mali_platform_power_mode_change(mali_power_mode power_mode)
{
	MALI_SUCCESS;
}

_mali_osk_errcode_t mali_platform_powerdown(u32 cores)
{
	/* power down after state is 0 */
	if (gpu_power_state != 0) {
		gpu_power_state = gpu_power_state & (~cores);
		if (gpu_power_state == 0) {
			MALI_DEBUG_PRINT(3, ("disable clock\n"));
			disable_mali_clocks();
		}
	} else {
	}
	MALI_SUCCESS;
}

_mali_osk_errcode_t mali_platform_powerup(u32 cores)
{
	/* power down after state is 0 */
	if (gpu_power_state == 0) {
		gpu_power_state = gpu_power_state | cores;
		if (gpu_power_state != 0)
			enable_mali_clocks();
	} else {
		gpu_power_state = gpu_power_state | cores;
	}
	MALI_SUCCESS;
}

void set_mali_parent_power_domain(void *dev)
{
	return;
}

mali_bool init_mali_regulator(void)
{
	mali_bool ret;
	g3d_regulator = regulator_get(NULL, "vdd_g3d");
	if (IS_ERR(g3d_regulator)) {
		ret = MALI_FALSE;
		goto err_regulator;
	}

	regulator_enable(g3d_regulator);
	mali_regulator_set_voltage(mali_gpu_vol, mali_gpu_vol);
	return MALI_TRUE;

err_regulator:
	regulator_put(g3d_regulator);
	return ret;
}

mali_bool deinit_mali_regulator(void)
{
	if (g3d_regulator) {
		regulator_put(g3d_regulator);
		g3d_regulator = NULL;
	}

	return MALI_TRUE;
}

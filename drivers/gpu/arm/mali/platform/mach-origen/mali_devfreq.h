/*
 * Copyright (C) 2010-2012 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of
 * the GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms of
 * such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be
 * obtained from Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __MALI_DEVFREQ_H__
#define __MALI_DEVFREQ_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MALI_DVFS_STAY_AFTER_CHANGE 1 /* stay count after clock change */
#define MALI_DVFS_DEFAULT_STEP 0 /* 134Mhz default */
#define GPU_DVFS_UP_THRESHOLD   ((int)((255*65)/100))   /* 60% */
#define GPU_DVFS_DOWN_THRESHOLD ((int)((255*30)/100))   /* 30% */
#define MALI_DVFS_WAITING 10 /* msec */

extern struct regulator *g3d_regulator;
extern mali_io_address clk_register_map;
extern _mali_osk_lock_t *mali_dvfs_lock;

struct mali_dvfs_tbl {
	unsigned int clock;
	unsigned int freq;
	unsigned int vol;
};

struct mali_dvfs_status {
	unsigned int currentStep;
	struct mali_dvfs_tbl *pCurrentDvfs;
};

mali_bool init_mali_dvfs_status(int step);

void deinit_mali_dvfs_status(void);

#ifdef __cplusplus
}
#endif
#endif

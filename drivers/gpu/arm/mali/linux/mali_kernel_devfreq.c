/*
 * Copyright (C) 2010-2011 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and any use by you of this program is subject to the terms of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained from Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/devfreq.h>
#include <linux/platform_device.h>
#include "mali_kernel_devfreq.h"
#include "mali_osk.h"
#include "mali_platform.h"
#include "mali_linux_pm.h"

#define MALI_GPU_UTILIZATION_PERIOD	500

static _mali_osk_lock_t *time_data_lock;

static _mali_osk_atomic_t num_running_cores;

static u64 period_start_time = 0;
static u64 work_start_time = 0;
static u64 accumulated_work_time = 0;
static mali_bool timer_running = MALI_FALSE;

static struct devfreq *mali_devfreq;

static int mali_get_dev_status(struct device *dev,
				struct devfreq_dev_status *stat)
{
	u64 time_now;
	u64 time_period;

	_mali_osk_lock_wait(time_data_lock, _MALI_OSK_LOCKMODE_RW);

	if (accumulated_work_time == 0 && work_start_time == 0)
	{
		/* No work done for this period, report zero usage */
		stat->total_time = 0;
		stat->busy_time = 0;
		stat->current_frequency = get_mali_platform_cur_freq();

		_mali_osk_lock_signal(time_data_lock, _MALI_OSK_LOCKMODE_RW);

		return 0;
	}

	time_now = _mali_osk_time_get_ns();
	time_period = time_now - period_start_time;

	/* If we are currently busy, update working period up to now */
	if (work_start_time != 0)
	{
		accumulated_work_time += (time_now - work_start_time);
		work_start_time = time_now;
	}

	stat->total_time = time_period;
	stat->busy_time = accumulated_work_time;
	stat->current_frequency = get_mali_platform_cur_freq();

	accumulated_work_time = 0;
	/* start a new period */
	period_start_time = time_now;
	_mali_osk_lock_signal(time_data_lock, _MALI_OSK_LOCKMODE_RW);

	return 0;
}

static int mali_set_target_freq(struct device *dev,
				unsigned long *freq,
				u32 flags)
{
	mali_gpu_utilization_handler(*freq);
	return 0;
}

static int mali_get_cur_freq(struct device *dev, unsigned long *freq)
{
	*freq = get_mali_platform_cur_freq();
	return 0;
}

static struct devfreq_dev_profile mali_devfreq_profile = {
	.polling_ms = MALI_GPU_UTILIZATION_PERIOD,
	.initial_freq = 0,
	.target = mali_set_target_freq,
	.get_dev_status = mali_get_dev_status,
	.get_cur_freq = mali_get_cur_freq,
};

_mali_osk_errcode_t mali_utilization_init(void)
{
	/* Register mali devfreq with ondemand governor */
	mali_devfreq = devfreq_add_device(&mali_gpu_device.dev,
					&mali_devfreq_profile,
					&devfreq_simple_ondemand,
					NULL);
	if (NULL == mali_devfreq)
	{
		return _MALI_OSK_ERR_FAULT;
	}

	time_data_lock = _mali_osk_lock_init( 0, 0, 0 );
	if (NULL == time_data_lock)
	{
		return _MALI_OSK_ERR_FAULT;
	}

	_mali_osk_atomic_init(&num_running_cores, 0);

	return _MALI_OSK_ERR_OK;
}

void mali_utilization_suspend(void)
{
	if (timer_running == MALI_TRUE)
	{
		devfreq_suspend_device(mali_devfreq);
		_mali_osk_lock_wait(time_data_lock, _MALI_OSK_LOCKMODE_RW);
		timer_running = MALI_FALSE;
		work_start_time = 0;
		period_start_time = 0;
		accumulated_work_time = 0;
		_mali_osk_lock_signal(time_data_lock, _MALI_OSK_LOCKMODE_RW);
	}
}

void mali_utilization_resume(void)
{
	devfreq_resume_device(mali_devfreq);
}

void mali_utilization_term(void)
{
	devfreq_remove_device(mali_devfreq);
	mali_devfreq = NULL;

	timer_running = MALI_FALSE;

	_mali_osk_atomic_term(&num_running_cores);

	_mali_osk_lock_term(time_data_lock);
}

void mali_utilization_core_start(void)
{
	if (_mali_osk_atomic_inc_return(&num_running_cores) == 1)
	{
		/*
		 * We went from zero cores working, to one core working,
		 * we now consider the entire GPU for being busy
		 */
		_mali_osk_lock_wait(time_data_lock, _MALI_OSK_LOCKMODE_RW);

		work_start_time = _mali_osk_time_get_ns();

		if (timer_running != MALI_TRUE)
		{
			timer_running = MALI_TRUE;
			period_start_time = work_start_time;
		}

		_mali_osk_lock_signal(time_data_lock, _MALI_OSK_LOCKMODE_RW);
	}
}

void mali_utilization_core_end(void)
{
	if (_mali_osk_atomic_dec_return(&num_running_cores) == 0)
	{
		/*
		 * No more cores are working, so accumulate the time we was busy.
		 */
		u64 time_now;

		_mali_osk_lock_wait(time_data_lock, _MALI_OSK_LOCKMODE_RW);

		time_now = _mali_osk_time_get_ns();
		accumulated_work_time += (time_now - work_start_time);
		work_start_time = 0;

		_mali_osk_lock_signal(time_data_lock, _MALI_OSK_LOCKMODE_RW);
	}
}

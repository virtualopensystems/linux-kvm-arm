/*
 * Copyright (C) 2010-2011 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and any use by you of this program is subject to the terms of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained from Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __MALI_KERNEL_DEVFREQ_H__
#define __MALI_KERNEL_DEVFREQ_H__

#include "mali_osk.h"

/**
 * Initialize/start the Mali GPU utilization metrics reporting.
 *
 * @return _MALI_OSK_ERR_OK on success, otherwise failure.
 */
_mali_osk_errcode_t mali_utilization_init(void);

/**
 * Terminate the Mali GPU utilization metrics reporting
 */
void mali_utilization_term(void);

/**
 * Should be called to suspend the utilization monitoring during
 * system suspend or device pm-runtime suspend
 */
void mali_utilization_suspend(void);

/**
 * Should be called to resume the utilization monitoring during
 * system resume or device pm-runtime resume
 */
void mali_utilization_resume(void);

#endif /* __MALI_KERNEL_DEVFREQ_H__ */

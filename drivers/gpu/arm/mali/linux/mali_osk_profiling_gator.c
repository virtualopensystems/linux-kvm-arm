/**
 * Copyright (C) 2012 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, and any use by you of this program is subject to the terms of
 * such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained
 * from Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#define DONT_USE_L2_CACHE_COUNTERS /* These traces can cause lock-ups so disable them. */

#include <linux/module.h>

#include "mali_kernel_common.h"
#include "mali_osk.h"
#include "mali_ukk.h"
#include "mali_osk_profiling.h"
#include "mali_linux_trace.h"

#if defined(USING_MALI400_L2_CACHE) && !defined(DONT_USE_L2_CACHE_COUNTERS)
#include "mali_kernel_l2_cache.h"
#endif /* USING_MALI400_L2_CACHE */

#define COUNTER_DISABLED (-1)

/**
 * Since there are only two physical hardware counters per GPU block, we
 * need to multiplex the range of possible events that can be collected by
 * each counter. This multiplexing is achieved by means of the following
 * table, which holds the event ID that should be collected by each hardware
 * counter.
 *
 * Note that this table should be updated with any change to the above
 * _mali_osk_counter_id enumeration.
 */
s32 _mali_osk_hw_counter_table[] = {
    COUNTER_DISABLED, /* ACTIVITY_VP */
    COUNTER_DISABLED, /* ACTIVITY_FP0 */
    COUNTER_DISABLED, /* ACTIVITY_FP1 */
    COUNTER_DISABLED, /* ACTIVITY_FP2 */
    COUNTER_DISABLED, /* ACTIVITY_FP3 */
    COUNTER_DISABLED, /* COUNTER_L2_C0 */
    COUNTER_DISABLED, /* COUNTER_L2_C1 */
    COUNTER_DISABLED, /* COUNTER_VP_C0 */
    COUNTER_DISABLED, /* COUNTER_VP_C1 */
    COUNTER_DISABLED, /* COUNTER_FP0_C0 */
    COUNTER_DISABLED, /* COUNTER_FP0_C1 */
    COUNTER_DISABLED, /* COUNTER_FP1_C0 */
    COUNTER_DISABLED, /* COUNTER_FP1_C1 */
    COUNTER_DISABLED, /* COUNTER_FP2_C0 */
    COUNTER_DISABLED, /* COUNTER_FP2_C1 */
    COUNTER_DISABLED, /* COUNTER_FP3_C0 */
    COUNTER_DISABLED, /* COUNTER_FP3_C1 */
};

mali_bool _mali_osk_profiling_query_hw_counter(u32 counter_id, u32 *event_id)
{
    /* Check that the counter is in range... */
    if (counter_id >= FIRST_HW_COUNTER && counter_id <= LAST_HW_COUNTER)
    {
        s32 id = _mali_osk_hw_counter_table[counter_id];

        /* ...and enabled */
        if (id != COUNTER_DISABLED)
        {
            /* Update the pointer to the event ID */
            *event_id = (u32)id;

            return MALI_TRUE;
        }
    }

    /* The counter was disabled or out of range */
    return MALI_FALSE;
}

_mali_osk_errcode_t _mali_osk_profiling_init(mali_bool auto_start)
{
    /* Nothing to do */
    return _MALI_OSK_ERR_OK;
}

void _mali_osk_profiling_term(void)
{
    /* Nothing to do */
}

_mali_osk_errcode_t _mali_osk_profiling_start(u32 * limit)
{
    /* Nothing to do */
    return _MALI_OSK_ERR_OK;
}

_mali_osk_errcode_t _mali_osk_profiling_stop(u32 *count)
{
    /* Nothing to do */
    return _MALI_OSK_ERR_OK;
}

u32 _mali_osk_profiling_get_count(void)
{
    return 0;
}

_mali_osk_errcode_t _mali_osk_profiling_get_event(u32 index, u64* timestamp,
    u32* event_id, u32 data[5])
{
    /* Nothing to do */
    return _MALI_OSK_ERR_OK;
}

_mali_osk_errcode_t _mali_osk_profiling_clear(void)
{
    /* Nothing to do */
    return _MALI_OSK_ERR_OK;
}

mali_bool _mali_osk_profiling_is_recording(void)
{
    return MALI_FALSE;
}

mali_bool _mali_osk_profiling_have_recording(void)
{
    return MALI_FALSE;
}

void _mali_osk_profiling_set_default_enable_state(mali_bool enable)
{
    /* Nothing to do */
}

mali_bool _mali_osk_profiling_get_default_enable_state(void)
{
    return MALI_FALSE;
}

_mali_osk_errcode_t _mali_ukk_profiling_start(_mali_uk_profiling_start_s *args)
{
	return _mali_osk_profiling_start(&args->limit);
}

_mali_osk_errcode_t _mali_ukk_profiling_add_event(_mali_uk_profiling_add_event_s *args)
{
	/* Always add process and thread identificator in the first two data elements for events from user space */
	_mali_osk_profiling_add_event(args->event_id, _mali_osk_get_pid(), _mali_osk_get_tid(), args->data[2], args->data[3], args->data[4]);

    return _MALI_OSK_ERR_OK;
}

_mali_osk_errcode_t _mali_ukk_profiling_stop(_mali_uk_profiling_stop_s *args)
{
	return _mali_osk_profiling_stop(&args->count);
}

_mali_osk_errcode_t _mali_ukk_profiling_get_event(_mali_uk_profiling_get_event_s *args)
{
	return _mali_osk_profiling_get_event(args->index, &args->timestamp, &args->event_id, args->data);
}

_mali_osk_errcode_t _mali_ukk_profiling_clear(_mali_uk_profiling_clear_s *args)
{
	return _mali_osk_profiling_clear();
}

_mali_osk_errcode_t _mali_ukk_profiling_get_config(_mali_uk_profiling_get_config_s *args)
{
	return _MALI_OSK_ERR_UNSUPPORTED;
}

/**
 * Called by gator.ko to populate the _mali_osk_hw_counter_table.
 *
 * @param counter_id The counter ID.
 * @param event_id Event ID that the counter should count.
 *
 * @return 1 on success, 0 on failure.
 */
int _mali_profiling_set_event(u32 counter_id, s32 event_id)
{
#if defined(USING_MALI400_L2_CACHE) && !defined(DONT_USE_L2_CACHE_COUNTERS)
    /*
     * The L2 cache counters have special handling in the driver. Since we
     * receive new event IDs for each counter one at a time, we need to know
     * what the L2 counters are currently programmed to read. This way we
     * can supply the current value to the counter we _aren't_ trying to
     * program; mali_kernel_l2_cache_set_perf_counters will dutifully ignore
     * that counter.
     */
    u32 current_src0, current_src1, current_val0, current_val1;

    mali_kernel_l2_cache_get_perf_counters(&current_src0, &current_val0,
        &current_src1, &current_val1);

    if (counter_id == COUNTER_L2_C0)
    {
        mali_kernel_l2_cache_set_perf_counters(event_id, current_src1, 0);

        return 1;
    }
    else if (counter_id == COUNTER_L2_C1)
    {
        mali_kernel_l2_cache_set_perf_counters(current_src0, event_id, 0);

        return 1;
    }
#endif /* USING_MALI400_L2_CACHE */

    /* Check that the counter is in range */
    if (counter_id >= FIRST_HW_COUNTER && counter_id <= LAST_HW_COUNTER)
    {
        /*
         * This does not actually update the hardware with the new event ID;
         * it will query what event ID it should be counting on each frame
         * via _mali_osk_profiling_query_hw_counter.
         */
        _mali_osk_hw_counter_table[counter_id] = event_id;

        return 1;
    }

    return 0;
}

#if defined(USING_MALI400_L2_CACHE) && !defined(DONT_USE_L2_CACHE_COUNTERS)
/**
 * Called by gator.ko to retrieve the L2 cache counter values. The L2 cache
 * counters are unique in that they are polled by gator, rather than being
 * transmitted via the tracepoint mechanism.
 *
 * @param src0 First L2 cache counter ID.
 * @param val0 First L2 cache counter value.
 * @param src1 Second L2 cache counter ID.
 * @param val1 Second L2 cache counter value.
 */
void _mali_profiling_get_counters(u32 *src0, u32 *val0, u32 *src1, u32 *val1)
{
    mali_kernel_l2_cache_get_perf_counters(src0, val0, src1, val1);
}

EXPORT_SYMBOL(_mali_profiling_get_counters);
#endif /* USING_MALI400_L2_CACHE */

EXPORT_SYMBOL(_mali_profiling_set_event);

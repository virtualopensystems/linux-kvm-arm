/**
 * Copyright (C) 2010-2012 ARM Limited. All rights reserved.
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

#if !defined (MALI_LINUX_TRACE_H) || defined (TRACE_HEADER_MULTI_READ)
#define MALI_LINUX_TRACE_H

#include <linux/stringify.h>
#include <linux/tracepoint.h>

#undef  TRACE_SYSTEM
#define TRACE_SYSTEM mali
#define TRACE_SYSTEM_STRING __stringfy(TRACE_SYSTEM)

#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE mali_linux_trace

/**
 * Define the tracepoint used to communicate the status of a GPU. Called
 * when a GPU turns on or turns off.
 *
 * @param event_id The type of the event. This parameter is a bitfield
 *  encoding the type of the event.
 *
 * @param d0 First data parameter.
 * @param d1 Second data parameter.
 * @param d2 Third data parameter.
 * @param d3 Fourth data parameter.
 * @param d4 Fifth data parameter.
 */
TRACE_EVENT(mali_timeline_event,

    TP_PROTO(unsigned int event_id, unsigned int d0, unsigned int d1,
        unsigned int d2, unsigned int d3, unsigned int d4),

    TP_ARGS(event_id, d0, d1, d2, d3, d4),

    TP_STRUCT__entry(
        __field(unsigned int, event_id)
        __field(unsigned int, d0)
        __field(unsigned int, d1)
        __field(unsigned int, d2)
        __field(unsigned int, d3)
        __field(unsigned int, d4)
    ),

    TP_fast_assign(
        __entry->event_id = event_id;
        __entry->d0 = d0;
        __entry->d1 = d1;
        __entry->d2 = d2;
        __entry->d3 = d3;
        __entry->d4 = d4;
    ),

    TP_printk("event=%d", __entry->event_id)
);

/**
 * Define a tracepoint used to regsiter the value of a hardware counter.
 * Hardware counters belonging to the vertex or fragment processor are
 * reported via this tracepoint each frame, whilst L2 cache hardware
 * counters are reported continuously.
 *
 * @param counter_id The counter ID.
 * @param value The value of the counter.
 */
TRACE_EVENT(mali_hw_counter,

    TP_PROTO(unsigned int counter_id, unsigned int value),

    TP_ARGS(counter_id, value),

    TP_STRUCT__entry(
        __field(unsigned int, counter_id)
        __field(unsigned int, value)
    ),

    TP_fast_assign(
        __entry->counter_id = counter_id;
        __entry->value      = value;
    ),

    TP_printk("event %d = %d", __entry->counter_id, __entry->value)
);

/**
 * Define a tracepoint used to register the value of a software counter.
 *
 * @param counter_id The counter ID.
 * @param value The value of the counter.
 */
TRACE_EVENT(mali_sw_counter,

    TP_PROTO(unsigned int counter_id, signed long long value),

    TP_ARGS(counter_id, value),

    TP_STRUCT__entry(
        __field(unsigned int, counter_id)
        __field(signed long long, value)
    ),

    TP_fast_assign(
        __entry->counter_id = counter_id;
        __entry->value      = value;
    ),

    TP_printk("event %d = %lld", __entry->counter_id, __entry->value)
);

#endif /* MALI_LINUX_TRACE_H */

/* This part must exist outside the header guard. */
#include <trace/define_trace.h>

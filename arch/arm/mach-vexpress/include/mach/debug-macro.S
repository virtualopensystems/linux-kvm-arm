/* arch/arm/mach-realview/include/mach/debug-macro.S
 *
 * Debugging macro include header
 *
 *  Copyright (C) 1994-1999 Russell King
 *  Moved from linux/arch/arm/kernel/debug.S by Ben Dooks
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_DEBUG_VEXPRESS_CA9X4_UART
#define DEBUG_LL_PHYS_BASE		0x10000000
#define DEBUG_LL_UART_OFFSET		0x00009000
#endif

#ifdef CONFIG_DEBUG_VEXPRESS_RS1_UART
#define DEBUG_LL_PHYS_BASE		0x1c000000
#define DEBUG_LL_UART_OFFSET		0x00090000
#endif

#define DEBUG_LL_VIRT_BASE		0xf8000000

#ifndef DEBUG_LL_UART_OFFSET
#error "Unknown vexpress UART offset"
#endif

		.macro	addruart,rp,rv,tmp
		mov	\rp, #DEBUG_LL_UART_OFFSET
		orr	\rv, \rp, #DEBUG_LL_VIRT_BASE
		orr	\rp, \rp, #DEBUG_LL_PHYS_BASE
		.endm

#include <asm/hardware/debug-pl01x.S>

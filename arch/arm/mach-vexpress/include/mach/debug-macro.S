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

#include <mach/motherboard.h>
#define DEBUG_LL_UART_OFFSET	V2M_PERIPH_OFFSET(9)

		.macro	addruart,rp,rv,tmp
		mov	\rp, #DEBUG_LL_UART_OFFSET
		orr	\rv, \rp, #0xf8000000	@ virtual base
		orr	\rp, \rp, #V2M_PA_CS7	@ physical base
		.endm

#include <asm/hardware/debug-pl01x.S>

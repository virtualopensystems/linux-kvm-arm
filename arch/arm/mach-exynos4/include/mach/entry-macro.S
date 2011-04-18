/* arch/arm/mach-exynos4/include/mach/entry-macro.S
 *
 * Cloned from arch/arm/mach-realview/include/mach/entry-macro.S
 *
 * Low-level IRQ helper macros for EXYNOS4 platforms
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
*/

#define HAVE_GIC_BASE_OFFSET	1
#include <asm/hardware/entry-macro-gic.S>

		.macro	compute_irqnr, irqnr, tmp
		addne	\irqnr, #32
		.endm

		.macro	disable_fiq
		.endm

		.macro  arch_ret_to_user, tmp1, tmp2
		.endm


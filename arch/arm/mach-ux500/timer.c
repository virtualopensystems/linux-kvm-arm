/*
 * Copyright (C) ST-Ericsson SA 2011
 *
 * License Terms: GNU General Public License v2
 * Author: Mattias Wallin <mattias.wallin@stericsson.com> for ST-Ericsson
 */
#include <linux/io.h>
#include <linux/errno.h>
#include <linux/clksrc-dbx500-prcmu.h>

#include <asm/smp_twd.h>

#include <plat/mtu.h>

#include <mach/setup.h>
#include <mach/hardware.h>

#ifdef CONFIG_ARM_SMP_TWD
static struct resource ux500_twd_resources[] __initdata = {
	{
		.flags	= IORESOURCE_MEM,
	},
	{
		.start	= IRQ_LOCALTIMER,
		.end	= IRQ_LOCALTIMER,
		.flags	= IORESOURCE_IRQ,
	},
};

static void __init ux500_twd_init(void)
{
	int err = twd_timer_register(ux500_twd_resources,
				     ARRAY_SIZE(ux500_twd_resources));
	if (err)
		pr_err("twd_timer_register failed %d\n", err);
}

static void __init ux500_twd_set_base(unsigned long base)
{
	ux500_twd_resources[0].start = base;
	ux500_twd_resources[0].end = base + 0x10;
}
#else
#define ux500_twd_init	NULL
#define ux500_twd_set_base(b)	do { } while(0)
#endif

static void __init ux500_timer_init(void)
{
	void __iomem *prcmu_timer_base;

	if (cpu_is_u5500()) {
		ux500_twd_set_base(U5500_TWD_BASE);
		mtu_base = __io_address(U5500_MTU0_BASE);
		prcmu_timer_base = __io_address(U5500_PRCMU_TIMER_3_BASE);
	} else if (cpu_is_u8500()) {
		ux500_twd_set_base(U8500_TWD_BASE);
		mtu_base = __io_address(U8500_MTU0_BASE);
		prcmu_timer_base = __io_address(U8500_PRCMU_TIMER_4_BASE);
	} else {
		ux500_unknown_soc();
	}

	/*
	 * Here we register the timerblocks active in the system.
	 * Localtimers (twd) is started when both cpu is up and running.
	 * MTU register a clocksource, clockevent and sched_clock.
	 * Since the MTU is located in the VAPE power domain
	 * it will be cleared in sleep which makes it unsuitable.
	 * We however need it as a timer tick (clockevent)
	 * during boot to calibrate delay until twd is started.
	 * RTC-RTT have problems as timer tick during boot since it is
	 * depending on delay which is not yet calibrated. RTC-RTT is in the
	 * always-on powerdomain and is used as clockevent instead of twd when
	 * sleeping.
	 * The PRCMU timer 4(3 for DB5500) register a clocksource and
	 * sched_clock with higher rating then MTU since is always-on.
	 *
	 */

	nmdk_timer_init();
	clksrc_dbx500_prcmu_init(prcmu_timer_base);
	late_time_init = ux500_twd_init;
}

static void ux500_timer_reset(void)
{
	nmdk_clkevt_reset();
	nmdk_clksrc_reset();
}

struct sys_timer ux500_timer = {
	.init		= ux500_timer_init,
	.resume		= ux500_timer_reset,
};

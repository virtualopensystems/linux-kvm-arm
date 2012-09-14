/*
 * Samsung's EXYNOS4 flattened device tree enabled machine
 *
 * Copyright (c) 2010-2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 * Copyright (c) 2010-2011 Linaro Ltd.
 *		www.linaro.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/of_platform.h>
#include <linux/serial_core.h>

#include <linux/platform_data/usb-ehci-s5p.h>
#include <linux/platform_data/usb-exynos.h>

#include <linux/platform_data/s3c-hsotg.h>
#include <linux/pwm_backlight.h>
#include <linux/gpio.h>
#include <linux/fb.h>
#include <linux/lcd.h>

#include <video/samsung_fimd.h>

#include <plat/backlight.h>
#include <plat/gpio-cfg.h>
#include <plat/fb.h>
#include <plat/devs.h>

#include <asm/mach/arch.h>
#include <asm/hardware/gic.h>
#include <mach/map.h>

#include <plat/cpu.h>
#include <plat/regs-serial.h>
#include <plat/usb-phy.h>

#include "common.h"

static struct s5p_ehci_platdata origen_ehci_pdata = {
	.phy_init = s5p_usb_phy_init,
	.phy_exit = s5p_usb_phy_exit,
};

static struct exynos4_ohci_platdata origen_ohci_pdata = {
	.phy_init = s5p_usb_phy_init,
	.phy_exit = s5p_usb_phy_exit,
};

static struct s3c_hsotg_plat origen_hsotg_pdata = {
	.phy_init = s5p_usb_phy_init,
	.phy_exit = s5p_usb_phy_exit,
};

/* LCD Backlight data */
static struct samsung_bl_gpio_info origen_bl_gpio_info = {
	.no	= EXYNOS4_GPD0(0),
	.func	= S3C_GPIO_SFN(2),
};

static struct platform_pwm_backlight_data origen_bl_data = {
	.pwm_id		= 0,
	.pwm_period_ns	= 1000,
};

/*
 * The following lookup table is used to override device names when devices
 * are registered from device tree. This is temporarily added to enable
 * device tree support addition for the Exynos4 architecture.
 *
 * For drivers that require platform data to be provided from the machine
 * file, a platform data pointer can also be supplied along with the
 * devices names. Usually, the platform data elements that cannot be parsed
 * from the device tree by the drivers (example: function pointers) are
 * supplied. But it should be noted that this is a temporary mechanism and
 * at some point, the drivers should be capable of parsing all the platform
 * data from the device tree.
 */
static const struct of_dev_auxdata exynos4_auxdata_lookup[] __initconst = {
	OF_DEV_AUXDATA("samsung,exynos4210-uart", EXYNOS4_PA_UART0,
				"exynos4210-uart.0", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-uart", EXYNOS4_PA_UART1,
				"exynos4210-uart.1", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-uart", EXYNOS4_PA_UART2,
				"exynos4210-uart.2", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-uart", EXYNOS4_PA_UART3,
				"exynos4210-uart.3", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-sdhci", EXYNOS4_PA_HSMMC(0),
				"exynos4-sdhci.0", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-sdhci", EXYNOS4_PA_HSMMC(1),
				"exynos4-sdhci.1", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-sdhci", EXYNOS4_PA_HSMMC(2),
				"exynos4-sdhci.2", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-sdhci", EXYNOS4_PA_HSMMC(3),
				"exynos4-sdhci.3", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(0),
				"s3c2440-i2c.0", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(1),
				"s3c2440-i2c.1", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(2),
				"s3c2440-i2c.2", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(3),
				"s3c2440-i2c.3", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(4),
				"s3c2440-i2c.4", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(5),
				"s3c2440-i2c.5", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(6),
				"s3c2440-i2c.6", NULL),
	OF_DEV_AUXDATA("samsung,s3c2440-i2c", EXYNOS4_PA_IIC(7),
				"s3c2440-i2c.7", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-spi", EXYNOS4_PA_SPI0,
				"exynos4210-spi.0", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-spi", EXYNOS4_PA_SPI1,
				"exynos4210-spi.1", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-spi", EXYNOS4_PA_SPI2,
				"exynos4210-spi.2", NULL),
	OF_DEV_AUXDATA("arm,pl330", EXYNOS4_PA_PDMA0, "dma-pl330.0", NULL),
	OF_DEV_AUXDATA("arm,pl330", EXYNOS4_PA_PDMA1, "dma-pl330.1", NULL),
	OF_DEV_AUXDATA("arm,pl330", EXYNOS4_PA_MDMA1, "dma-pl330.2", NULL),
	OF_DEV_AUXDATA("samsung,exynos4210-tmu", EXYNOS4_PA_TMU,
				"exynos-tmu", NULL),
	OF_DEV_AUXDATA("samsung,exynos-ehci", EXYNOS4_PA_EHCI, "s5p-ehci",
			&origen_ehci_pdata),
	OF_DEV_AUXDATA("samsung,exynos-ohci", EXYNOS4_PA_OHCI, "exynos-ohci",
			&origen_ohci_pdata),
	OF_DEV_AUXDATA("samsung,exynos-hsotg", EXYNOS4_PA_HSOTG, "s3c-hsotg",
			&origen_hsotg_pdata),
	OF_DEV_AUXDATA("samsung,exynos4210-fimd", EXYNOS4_PA_FIMD0,
			"exynos4-fb.0", NULL),
	{},
};

static void __init exynos4_dt_map_io(void)
{
	exynos_init_io(NULL, 0);
	s3c24xx_init_clocks(24000000);
}

static void __init exynos4_setup_fimd(void)
{
	unsigned int reg;

	reg = __raw_readl(S3C_VA_SYS + 0x0210);
	reg |= (1 << 1);
	__raw_writel(reg, S3C_VA_SYS + 0x0210);
}

static void __init exynos4_dt_machine_init(void)
{
	of_platform_populate(NULL, of_default_bus_match_table,
				exynos4_auxdata_lookup, NULL);
	samsung_bl_set(&origen_bl_gpio_info, &origen_bl_data);
	exynos4_setup_fimd();
}

static char const *exynos4_dt_compat[] __initdata = {
	"samsung,exynos4210",
	"samsung,exynos4212",
	"samsung,exynos4412",
	NULL
};

DT_MACHINE_START(EXYNOS4210_DT, "Samsung Exynos4 (Flattened Device Tree)")
	/* Maintainer: Thomas Abraham <thomas.abraham@linaro.org> */
	.smp		= smp_ops(exynos_smp_ops),
	.init_irq	= exynos4_init_irq,
	.map_io		= exynos4_dt_map_io,
	.handle_irq	= gic_handle_irq,
	.init_machine	= exynos4_dt_machine_init,
	.init_late	= exynos_init_late,
	.timer		= &exynos4_timer,
	.dt_compat	= exynos4_dt_compat,
	.restart        = exynos4_restart,
MACHINE_END

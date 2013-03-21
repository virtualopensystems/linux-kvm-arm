/* linux/arch/arm/mach-exynos/mach-origen_quad.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/serial_core.h>
#include <linux/gpio.h>
#include <linux/mmc/host.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/input.h>

#include <linux/i2c.h>
#include <linux/lcd.h>
#include <linux/mfd/samsung/s5m8767.h>
#include <linux/mfd/samsung/core.h>
#include <linux/pwm.h>
#include <linux/pwm_backlight.h>
#include <linux/regulator/machine.h>

#include <video/platform_lcd.h>
#include <video/samsung_fimd.h>
#include <drm/exynos_drm.h>

#include <asm/mach/arch.h>
#include <asm/hardware/gic.h>
#include <asm/mach-types.h>

#include <plat/backlight.h>
#include <plat/clock.h>
#include <plat/cpu.h>
#include <plat/devs.h>
#include <plat/fb.h>
#include <plat/gpio-cfg.h>
#include <plat/mfc.h>
#include <linux/platform_data/i2c-s3c2410.h>
#include <plat/regs-serial.h>
#include <plat/sdhci.h>

#include <mach/map.h>
#include "common.h"

/* Following are default values for UCON, ULCON and UFCON UART registers */
#define ORIGEN_QUAD_UCON_DEFAULT	(S3C2410_UCON_TXILEVEL |	\
				 S3C2410_UCON_RXILEVEL |	\
				 S3C2410_UCON_TXIRQMODE |	\
				 S3C2410_UCON_RXIRQMODE |	\
				 S3C2410_UCON_RXFIFO_TOI |	\
				 S3C2443_UCON_RXERR_IRQEN)

#define ORIGEN_QUAD_ULCON_DEFAULT	S3C2410_LCON_CS8

#define ORIGEN_QUAD_UFCON_DEFAULT	(S3C2410_UFCON_FIFOMODE |	\
				 S5PV210_UFCON_TXTRIG4 |	\
				 S5PV210_UFCON_RXTRIG4)


static struct s3c2410_uartcfg origen_quad_uartcfgs[] __initdata = {
	[0] = {
		.hwport		= 0,
		.flags		= 0,
		.ucon		= ORIGEN_QUAD_UCON_DEFAULT,
		.ulcon		= ORIGEN_QUAD_ULCON_DEFAULT,
		.ufcon		= ORIGEN_QUAD_UFCON_DEFAULT,
	},
	[1] = {
		.hwport		= 1,
		.flags		= 0,
		.ucon		= ORIGEN_QUAD_UCON_DEFAULT,
		.ulcon		= ORIGEN_QUAD_ULCON_DEFAULT,
		.ufcon		= ORIGEN_QUAD_UFCON_DEFAULT,
	},
	[2] = {
		.hwport		= 2,
		.flags		= 0,
		.ucon		= ORIGEN_QUAD_UCON_DEFAULT,
		.ulcon		= ORIGEN_QUAD_ULCON_DEFAULT,
		.ufcon		= ORIGEN_QUAD_UFCON_DEFAULT,
	},
	[3] = {
		.hwport		= 3,
		.flags		= 0,
		.ucon		= ORIGEN_QUAD_UCON_DEFAULT,
		.ulcon		= ORIGEN_QUAD_ULCON_DEFAULT,
		.ufcon		= ORIGEN_QUAD_UFCON_DEFAULT,
	},
};


static struct s3c_sdhci_platdata origen_quad_hsmmc2_pdata __initdata = {
	.cd_type		= S3C_SDHCI_CD_INTERNAL,
};

/* S5M8767 Regulator */
static int s5m_cfg_irq(void)
{
	/* AP_PMIC_IRQ: EINT22 */
	s3c_gpio_cfgpin(EXYNOS4_GPX2(6), S3C_GPIO_SFN(0xF));
	s3c_gpio_setpull(EXYNOS4_GPX2(6), S3C_GPIO_PULL_UP);
	return 0;
}

static struct regulator_consumer_supply s5m8767_ldo1_supply[] = {
	REGULATOR_SUPPLY("vdd_alive", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo2_supply[] = {
	REGULATOR_SUPPLY("vddq_m12", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo3_supply[] = {
	REGULATOR_SUPPLY("vddioap_18", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo4_supply[] = {
	REGULATOR_SUPPLY("vddq_pre", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo5_supply[] = {
	REGULATOR_SUPPLY("vdd18_2m", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo6_supply[] = {
	REGULATOR_SUPPLY("vdd10_mpll", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo7_supply[] = {
	REGULATOR_SUPPLY("vdd10_xpll", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo8_supply[] = {
	REGULATOR_SUPPLY("vdd10_mipi", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo9_supply[] = {
	REGULATOR_SUPPLY("vdd33_lcd", "platform-lcd"),
};

static struct regulator_consumer_supply s5m8767_ldo10_supply[] = {
	REGULATOR_SUPPLY("vdd18_mipi", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo11_supply[] = {
	REGULATOR_SUPPLY("vdd18_abb1", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo12_supply[] = {
	REGULATOR_SUPPLY("vdd33_uotg", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo13_supply[] = {
	REGULATOR_SUPPLY("vddioperi_18", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo14_supply[] = {
	REGULATOR_SUPPLY("vdd18_abb02", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo15_supply[] = {
	REGULATOR_SUPPLY("vdd10_ush", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo16_supply[] = {
	REGULATOR_SUPPLY("vdd18_hsic", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo17_supply[] = {
	REGULATOR_SUPPLY("vddioap_mmc012_28", NULL),
};
static struct regulator_consumer_supply s5m8767_ldo18_supply[] = {
	REGULATOR_SUPPLY("vddioperi_28", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo19_supply[] = {
	REGULATOR_SUPPLY("dvdd25", NULL),
};


static struct regulator_consumer_supply s5m8767_ldo20_supply[] = {
	REGULATOR_SUPPLY("vdd28_cam", NULL),
};
static struct regulator_consumer_supply s5m8767_ldo21_supply[] = {
	REGULATOR_SUPPLY("vdd28_af", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo22_supply[] = {
	REGULATOR_SUPPLY("vdda28_2m", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo23_supply[] = {
	REGULATOR_SUPPLY("vdd_tf", NULL),
};


static struct regulator_consumer_supply s5m8767_ldo24_supply[] = {
	REGULATOR_SUPPLY("vdd33_a31", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo25_supply[] = {
	REGULATOR_SUPPLY("vdd18_cam", NULL),
};

static struct regulator_consumer_supply s5m8767_ldo26_supply[] = {
	REGULATOR_SUPPLY("vdd18_a31", NULL),
};
static struct regulator_consumer_supply s5m8767_ldo27_supply[] = {
	REGULATOR_SUPPLY("gps_1v8", NULL),
};
static struct regulator_consumer_supply s5m8767_ldo28_supply[] = {
	REGULATOR_SUPPLY("dvdd12", NULL),
};


static struct regulator_consumer_supply s5m8767_buck1_consumer =
	REGULATOR_SUPPLY("vdd_mif", NULL);

static struct regulator_consumer_supply s5m8767_buck2_consumer =
	REGULATOR_SUPPLY("vdd_arm", NULL);

static struct regulator_consumer_supply s5m8767_buck3_consumer =
	REGULATOR_SUPPLY("vdd_int", NULL);

static struct regulator_consumer_supply s5m8767_buck4_consumer =
	REGULATOR_SUPPLY("vdd_g3d", NULL);

static struct regulator_consumer_supply s5m8767_buck5_consumer =
	REGULATOR_SUPPLY("vdd_m12", NULL);
static struct regulator_consumer_supply s5m8767_buck6_consumer =
	REGULATOR_SUPPLY("vdd12_5m", NULL);

static struct regulator_consumer_supply s5m8767_buck9_consumer =
	REGULATOR_SUPPLY("vddf28_emmc", NULL);



#define REGULATOR_INIT(_ldo, _name, _min_uV, _max_uV, _always_on, _ops_mask,\
		_disabled) \
	static struct regulator_init_data s5m8767_##_ldo##_init_data = {		\
		.constraints = {					\
			.name	= _name,				\
			.min_uV = _min_uV,				\
			.max_uV = _max_uV,				\
			.always_on	= _always_on,			\
			.boot_on	= _always_on,			\
			.apply_uV	= 1,				\
			.valid_ops_mask = _ops_mask,			\
			.state_mem	= {				\
				.disabled	= _disabled,		\
				.enabled	= !(_disabled),		\
			}						\
		},							\
		.num_consumer_supplies = ARRAY_SIZE(s5m8767_##_ldo##_supply),	\
		.consumer_supplies = &s5m8767_##_ldo##_supply[0],			\
	};

REGULATOR_INIT(ldo1, "VDD_ALIVE", 1100000, 1100000, 1,
		REGULATOR_CHANGE_STATUS, 0);
REGULATOR_INIT(ldo2, "VDDQ_M12", 1200000, 1200000, 1,
		REGULATOR_CHANGE_STATUS, 1);//sleep controlled by pwren
REGULATOR_INIT(ldo3, "VDDIOAP_18", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 0);
REGULATOR_INIT(ldo4, "VDDQ_PRE", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 1); //sleep controlled by pwren

REGULATOR_INIT(ldo5, "VDD18_2M", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo6, "VDD10_MPLL", 1000000, 1000000, 1,
		REGULATOR_CHANGE_STATUS, 1);//sleep controlled by pwren
REGULATOR_INIT(ldo7, "VDD10_XPLL", 1000000, 1000000, 1,
		REGULATOR_CHANGE_STATUS, 1);//sleep controlled by pwren
REGULATOR_INIT(ldo8, "VDD10_MIPI", 1000000, 1000000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo9, "VDD33_LCD", 3300000, 3300000, 1, //LCD
		REGULATOR_CHANGE_STATUS, 1);


REGULATOR_INIT(ldo10, "VDD18_MIPI", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo11, "VDD18_ABB1", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 0); //???
REGULATOR_INIT(ldo12, "VDD33_UOTG", 3300000, 3300000, 1,
		REGULATOR_CHANGE_STATUS, 0);
REGULATOR_INIT(ldo13, "VDDIOPERI_18", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 0);//???
REGULATOR_INIT(ldo14, "VDD18_ABB02", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 0); //???
REGULATOR_INIT(ldo15, "VDD10_USH", 1000000, 1000000, 1,
		REGULATOR_CHANGE_STATUS, 1);

//liang, VDD18_HSIC must be 1.8V, otherwise USB HUB 3503A can't be recognized
REGULATOR_INIT(ldo16, "VDD18_HSIC", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo17, "VDDIOAP_MMC012_28", 2800000, 2800000, 1,
		REGULATOR_CHANGE_STATUS, 0); //???
REGULATOR_INIT(ldo18, "VDDIOPERI_28", 2800000, 2800000, 1,
		REGULATOR_CHANGE_STATUS, 0);//???
REGULATOR_INIT(ldo19, "DVDD25", 2500000, 2500000, 1,
		REGULATOR_CHANGE_STATUS, 1); //??
REGULATOR_INIT(ldo20, "VDD28_CAM", 2800000, 2800000, 1,
		REGULATOR_CHANGE_STATUS, 1);

REGULATOR_INIT(ldo21, "VDD28_AF", 2800000, 2800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo22, "VDDA28_2M", 2800000, 2800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo23, "VDD28_TF", 2800000, 2800000, 1,
		REGULATOR_CHANGE_STATUS, 1);//sleep controlled by pwren
REGULATOR_INIT(ldo24, "VDD33_A31", 3300000, 3300000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo25, "VDD18_CAM", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo26, "VDD18_A31", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo27, "GPS_1V8", 1800000, 1800000, 1,
		REGULATOR_CHANGE_STATUS, 1);
REGULATOR_INIT(ldo28, "DVDD12", 1200000, 1200000, 1,
		REGULATOR_CHANGE_STATUS, 1);


static struct regulator_init_data s5m8767_buck1_data = {
	.constraints	= {
		.name		= "vdd_mif range",
		.min_uV		= 950000,
		.max_uV		= 1100000,
		.boot_on	= 1,
		.always_on      = 1,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE |
				  REGULATOR_CHANGE_STATUS,
		.state_mem	= {
			.disabled	= 1,
		},
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &s5m8767_buck1_consumer,
};

static struct regulator_init_data s5m8767_buck2_data = {
	.constraints	= {
		.name		= "vdd_arm range",
		.min_uV		=  925000,
		.max_uV		= 1300000,
		.boot_on	= 1,
		.always_on      = 1,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE |
				  REGULATOR_CHANGE_STATUS,
		.state_mem	= {
			.disabled	= 1,
		},
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &s5m8767_buck2_consumer,
};

static struct regulator_init_data s5m8767_buck3_data = {
	.constraints	= {
		.name		= "vdd_int range",
		.min_uV		=  900000,
		.max_uV		= 1200000,
		.boot_on	= 1,
		.always_on      = 1,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE |
				REGULATOR_CHANGE_STATUS,
		.state_mem	= {
			.uV		= 1100000,
			.mode		= REGULATOR_MODE_NORMAL,
			.disabled	= 1,
		},
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &s5m8767_buck3_consumer,
};

static struct regulator_init_data s5m8767_buck4_data = {
	.constraints	= {
		.name		= "vdd_g3d range",
		.min_uV		= 750000,
		.max_uV		= 1500000,
		.boot_on	= 1,
		.always_on      = 1,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE |
				REGULATOR_CHANGE_STATUS,
		.state_mem	= {
			.disabled	= 1,
		},
	},
	.num_consumer_supplies = 1,
	.consumer_supplies = &s5m8767_buck4_consumer,
};

static struct regulator_init_data s5m8767_buck5_data = {
	.constraints	= {
		.name		= "vdd_m12 range",
		.min_uV		= 750000,
		.max_uV		= 1500000,
		.boot_on	= 1,
		.always_on      = 1,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE |
				REGULATOR_CHANGE_STATUS,
		.state_mem	= {
			.enabled	= 1,
		},
	},
	.num_consumer_supplies = 1,
	.consumer_supplies = &s5m8767_buck5_consumer,
};
static struct regulator_init_data s5m8767_buck6_data = {
	.constraints	= {
		.name		= "vdd12_5m range",
		.min_uV		= 750000,
		.max_uV		= 1500000,
		.boot_on	= 1,
		.always_on      = 1,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE |
				REGULATOR_CHANGE_STATUS,
		.state_mem	= {
			.disabled	= 1,
		},
	},
	.num_consumer_supplies = 1,
	.consumer_supplies = &s5m8767_buck6_consumer,
};

static struct regulator_init_data s5m8767_buck9_data = {
	.constraints	= {
		.name		= "vddf28_emmc range",
		.min_uV		= 750000,
		.max_uV		= 3000000,
		.boot_on	= 1,
		.always_on      = 1,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE |
				REGULATOR_CHANGE_STATUS,
		.state_mem	= {
			.disabled	= 1,
		},
	},
	.num_consumer_supplies = 1,
	.consumer_supplies = &s5m8767_buck9_consumer,
};

static struct sec_regulator_data origen_quad_regulators[] = {
	{ S5M8767_BUCK1, &s5m8767_buck1_data },
	{ S5M8767_BUCK2, &s5m8767_buck2_data },
	{ S5M8767_BUCK3, &s5m8767_buck3_data },
	{ S5M8767_BUCK4, &s5m8767_buck4_data },
	{ S5M8767_BUCK5, &s5m8767_buck5_data },
	{ S5M8767_BUCK6, &s5m8767_buck6_data },
	{ S5M8767_BUCK9, &s5m8767_buck9_data },

	{ S5M8767_LDO1, &s5m8767_ldo1_init_data },
	{ S5M8767_LDO2, &s5m8767_ldo2_init_data },
	{ S5M8767_LDO3, &s5m8767_ldo3_init_data },
	{ S5M8767_LDO4, &s5m8767_ldo4_init_data },
	{ S5M8767_LDO5, &s5m8767_ldo5_init_data },
	{ S5M8767_LDO6, &s5m8767_ldo6_init_data },
	{ S5M8767_LDO7, &s5m8767_ldo7_init_data },
	{ S5M8767_LDO8, &s5m8767_ldo8_init_data },
	{ S5M8767_LDO9, &s5m8767_ldo9_init_data },
	{ S5M8767_LDO10, &s5m8767_ldo10_init_data },

	{ S5M8767_LDO11, &s5m8767_ldo11_init_data },
	{ S5M8767_LDO12, &s5m8767_ldo12_init_data },
	{ S5M8767_LDO13, &s5m8767_ldo13_init_data },
	{ S5M8767_LDO14, &s5m8767_ldo14_init_data },
	{ S5M8767_LDO15, &s5m8767_ldo15_init_data },
	{ S5M8767_LDO16, &s5m8767_ldo16_init_data },
	{ S5M8767_LDO17, &s5m8767_ldo17_init_data },
	{ S5M8767_LDO18, &s5m8767_ldo18_init_data },
	{ S5M8767_LDO19, &s5m8767_ldo19_init_data },
	{ S5M8767_LDO20, &s5m8767_ldo20_init_data },

	{ S5M8767_LDO21, &s5m8767_ldo21_init_data },
	{ S5M8767_LDO22, &s5m8767_ldo22_init_data },
	{ S5M8767_LDO23, &s5m8767_ldo23_init_data },
	{ S5M8767_LDO24, &s5m8767_ldo24_init_data },
	{ S5M8767_LDO25, &s5m8767_ldo25_init_data },
	{ S5M8767_LDO26, &s5m8767_ldo26_init_data },
	{ S5M8767_LDO27, &s5m8767_ldo27_init_data },
	{ S5M8767_LDO28, &s5m8767_ldo28_init_data },
};

struct sec_opmode_data s5m_opmode_data[S5M8767_REG_MAX] = {
	[S5M8767_BUCK1] =	{ S5M8767_BUCK1, SEC_OPMODE_ON},
	[S5M8767_BUCK2] =	{ S5M8767_BUCK2, SEC_OPMODE_ON},
	[S5M8767_BUCK3] =	{ S5M8767_BUCK3, SEC_OPMODE_ON},
	[S5M8767_BUCK4] =	{ S5M8767_BUCK4, SEC_OPMODE_ON},
	[S5M8767_BUCK5] =	{ S5M8767_BUCK5, SEC_OPMODE_ON},
	[S5M8767_BUCK6] =	{ S5M8767_BUCK6, SEC_OPMODE_ON},
	[S5M8767_BUCK9] =	{ S5M8767_BUCK9, SEC_OPMODE_ON},

	[S5M8767_LDO1] =	{S5M8767_LDO1, SEC_OPMODE_ON},
	[S5M8767_LDO2] =	{S5M8767_LDO2, SEC_OPMODE_ON},
	[S5M8767_LDO3] =	{S5M8767_LDO3, SEC_OPMODE_ON},
	[S5M8767_LDO4] =	{S5M8767_LDO4, SEC_OPMODE_ON},
	[S5M8767_LDO5] =	{S5M8767_LDO5, SEC_OPMODE_ON},
	[S5M8767_LDO6] =	{S5M8767_LDO6, SEC_OPMODE_ON},
	[S5M8767_LDO7] =	{S5M8767_LDO7, SEC_OPMODE_ON},
	[S5M8767_LDO8] =	{S5M8767_LDO8, SEC_OPMODE_ON},
	[S5M8767_LDO9] =	{S5M8767_LDO9, SEC_OPMODE_ON},
	[S5M8767_LDO10] =	{S5M8767_LDO10, SEC_OPMODE_ON},

	[S5M8767_LDO11] =	{S5M8767_LDO11, SEC_OPMODE_ON},
	[S5M8767_LDO12] =	{S5M8767_LDO12, SEC_OPMODE_ON},
	[S5M8767_LDO13] =	{S5M8767_LDO13, SEC_OPMODE_ON},
	[S5M8767_LDO14] =	{S5M8767_LDO14, SEC_OPMODE_ON},
	[S5M8767_LDO15] =	{S5M8767_LDO15, SEC_OPMODE_ON},
	[S5M8767_LDO16] =	{S5M8767_LDO16, SEC_OPMODE_ON},
	[S5M8767_LDO17] =	{S5M8767_LDO17, SEC_OPMODE_ON},
	[S5M8767_LDO18] =	{S5M8767_LDO18, SEC_OPMODE_ON},
	[S5M8767_LDO19] =	{S5M8767_LDO19, SEC_OPMODE_ON},
	[S5M8767_LDO20] =	{S5M8767_LDO20, SEC_OPMODE_ON},

	[S5M8767_LDO21] =	{S5M8767_LDO21, SEC_OPMODE_ON},
	[S5M8767_LDO22] =	{S5M8767_LDO22, SEC_OPMODE_ON},
	[S5M8767_LDO23] =	{S5M8767_LDO23, SEC_OPMODE_ON},
	[S5M8767_LDO24] =	{S5M8767_LDO24, SEC_OPMODE_ON},
	[S5M8767_LDO25] =	{S5M8767_LDO25, SEC_OPMODE_ON},
	[S5M8767_LDO26] =	{S5M8767_LDO26, SEC_OPMODE_ON},
	[S5M8767_LDO27] =	{S5M8767_LDO27, SEC_OPMODE_ON},
	[S5M8767_LDO28] =	{S5M8767_LDO28, SEC_OPMODE_ON},
};

static struct sec_platform_data origen_quad_s5m8767_pdata = {
	.device_type		= S5M8767X,
	.num_regulators		= ARRAY_SIZE(origen_quad_regulators),
	.regulators		= origen_quad_regulators,
	.cfg_pmic_irq		= s5m_cfg_irq,
	.opmode			= s5m_opmode_data,

	.buck2_gpiodvs		= false,
	.buck3_gpiodvs		= false,
	.buck4_gpiodvs		= false,

	.buck2_voltage[0]	= 1250000,
	.buck2_voltage[1]	= 1200000,
	.buck2_voltage[2]	= 1200000,
	.buck2_voltage[3]	= 1200000,
	.buck2_voltage[4]	= 1200000,
	.buck2_voltage[5]	= 1200000,
	.buck2_voltage[6]	= 1200000,
	.buck2_voltage[7]	= 1200000,

	.buck3_voltage[0]	= 1100000,
	.buck3_voltage[1]	= 1100000,
	.buck3_voltage[2]	= 1100000,
	.buck3_voltage[3]	= 1100000,
	.buck3_voltage[4]	= 1100000,
	.buck3_voltage[5]	= 1100000,
	.buck3_voltage[6]	= 1100000,
	.buck3_voltage[7]	= 1100000,

	.buck4_voltage[0]	= 1200000,
	.buck4_voltage[1]	= 1200000,
	.buck4_voltage[2]	= 1200000,
	.buck4_voltage[3]	= 1200000,
	.buck4_voltage[4]	= 1200000,
	.buck4_voltage[5]	= 1200000,
	.buck4_voltage[6]	= 1200000,
	.buck4_voltage[7]	= 1200000,

	.buck_default_idx	= 3,
	.buck_gpios[0]		= EXYNOS4_GPX2(3),
	.buck_gpios[1]		= EXYNOS4_GPX2(4),
	.buck_gpios[2]		= EXYNOS4_GPX2(5),

	.buck_ds[0]		= EXYNOS4_GPM3(5),
	.buck_ds[1]		= EXYNOS4_GPM3(6),
	.buck_ds[2]		= EXYNOS4_GPM3(7),

	.buck_ramp_delay	= 50,
	.buck2_ramp_enable	= true,
	.buck3_ramp_enable	= true,
	.buck4_ramp_enable	= true,
};
/* End of S5M8767 */

static void lcd_hv070wsa_set_power(struct plat_lcd_data *pd, unsigned int power)
{
	int ret;

	if (power)
		ret = gpio_request_one(EXYNOS4_GPX0(6),
					GPIOF_OUT_INIT_HIGH, "GPX0_6");
	else
		ret = gpio_request_one(EXYNOS4_GPX0(6),
					GPIOF_OUT_INIT_LOW, "GPX0_6");

	gpio_free(EXYNOS4_GPX0(6));

	if (ret)
		pr_err("failed to request gpio for LCD power: %d\n", ret);
}

static struct plat_lcd_data origen_quad_lcd_hv070wsa_data = {
	.set_power = lcd_hv070wsa_set_power,
};

static struct platform_device origen_quad_lcd_hv070wsa = {
	.name			= "platform-lcd",
	.dev.parent		= &s5p_device_fimd0.dev,
	.dev.platform_data	= &origen_quad_lcd_hv070wsa_data,
};

static struct pwm_lookup origen_quad_pwm_lookup[] = {
	PWM_LOOKUP("s3c24xx-pwm.0", 0, "pwm-backlight.0", NULL),
};

#ifdef CONFIG_DRM_EXYNOS
static struct exynos_drm_fimd_pdata drm_fimd_pdata = {
	.panel	= {
		.timing	= {
			.left_margin	= 64,
			.right_margin	= 16,
			.upper_margin	= 64,
			.lower_margin	= 16,
			.hsync_len	= 48,
			.vsync_len	= 3,
			.xres		= 1024,
			.yres		= 600,
		},
	},
	.vidcon0	= VIDCON0_VIDOUT_RGB | VIDCON0_PNRMODE_RGB,
	.vidcon1	= VIDCON1_INV_HSYNC | VIDCON1_INV_VSYNC |
				VIDCON1_INV_VCLK,
	.default_win	= 0,
	.bpp		= 32,
};
#else
static struct s3c_fb_pd_win origen_quad_fb_win0 = {
	.xres		= 1024,
	.yres		= 600,
	.max_bpp	= 32,
	.default_bpp	= 24,
	.virtual_x	= 1024,
	.virtual_y	= 2 * 600,
};

static struct s3c_fb_pd_win origen_quad_fb_win1 = {
	.xres		= 1024,
	.yres		= 600,
	.max_bpp	= 32,
	.default_bpp	= 24,
	.virtual_x	= 1024,
	.virtual_y	= 2 * 600,
};

static struct s3c_fb_pd_win origen_quad_fb_win2 = {
	.xres		= 1024,
	.yres		= 600,
	.max_bpp	= 32,
	.default_bpp	= 24,
	.virtual_x	= 1024,
	.virtual_y	= 2 * 600,
};

static struct fb_videomode origen_quad_lcd_timing = {
	.left_margin	= 64,
	.right_margin	= 16,
	.upper_margin	= 64,
	.lower_margin	= 16,
	.hsync_len	= 48,
	.vsync_len	= 3,
	.xres		= 1024,
	.yres		= 600,
};

static struct s3c_fb_platdata origen_quad_lcd_pdata __initdata = {
	.win[0]		= &origen_quad_fb_win0,
	.win[1]		= &origen_quad_fb_win1,
	.win[2]		= &origen_quad_fb_win2,
	.vtiming	= &origen_quad_lcd_timing,
	.vidcon0	= VIDCON0_VIDOUT_RGB | VIDCON0_PNRMODE_RGB,
	.vidcon1	= VIDCON1_INV_HSYNC | VIDCON1_INV_VSYNC |
				VIDCON1_INV_VCLK,
	.setup_gpio	= exynos4_fimd0_gpio_setup_24bpp,
};
#endif

static struct platform_device *origen_quad_devices[] __initdata = {
	&s3c_device_wdt,
	&s3c_device_rtc,
	&s3c_device_hsmmc2,
	&s3c_device_i2c0,
	&s5p_device_fimc0,
	&s5p_device_fimc1,
	&s5p_device_fimc2,
	&s5p_device_fimc3,
	&s5p_device_fimc_md,
	&s5p_device_fimd0,
	&s5p_device_mfc,
	&s5p_device_mfc_l,
	&s5p_device_mfc_r,
#ifdef CONFIG_DRM_EXYNOS
	&exynos_device_drm,
#endif
	&origen_quad_lcd_hv070wsa,
};

/* LCD Backlight data */
static struct samsung_bl_gpio_info origen_quad_bl_gpio_info = {
	.no		= EXYNOS4_GPD0(1),
	.func		= S3C_GPIO_SFN(2),
};

static struct platform_pwm_backlight_data origen_quad_bl_data = {
	.pwm_id		= 0,
	.pwm_period_ns	= 1000,
};

static void __init origen_quad_map_io(void)
{
	exynos_init_io(NULL, 0);
	s3c24xx_init_clocks(clk_xusbxti.rate);
	s3c24xx_init_uarts(origen_quad_uartcfgs, ARRAY_SIZE(origen_quad_uartcfgs));
}

static void __init origen_quad_power_init(void)
{
	gpio_request(EXYNOS4_GPX2(6), "PMIC_IRQ");
	s3c_gpio_cfgpin(EXYNOS4_GPX2(6), S3C_GPIO_SFN(0xf));
	s3c_gpio_setpull(EXYNOS4_GPX2(6), S3C_GPIO_PULL_UP);
}

static struct i2c_board_info i2c0_devs[] __initdata = {
	{
		I2C_BOARD_INFO("sec_pmic", 0xCC >> 1),
		.platform_data	= &origen_quad_s5m8767_pdata,
		.irq		= IRQ_EINT(22),
	},
};

static void __init origen_quad_reserve(void)
{
	s5p_mfc_reserve_mem(0x43000000, 8 << 20, 0x51000000, 8 << 20);
}

static void __init origen_quad_machine_init(void)
{
	origen_quad_power_init();

	s3c_i2c0_set_platdata(NULL);
	i2c_register_board_info(0, i2c0_devs, ARRAY_SIZE(i2c0_devs));

	s3c_sdhci2_set_platdata(&origen_quad_hsmmc2_pdata);

#ifdef CONFIG_DRM_EXYNOS
	s5p_device_fimd0.dev.platform_data = &drm_fimd_pdata;
	exynos4_fimd0_gpio_setup_24bpp();
#else
	s5p_fimd0_set_platdata(&origen_quad_lcd_pdata);
#endif
	pwm_add_table(origen_quad_pwm_lookup, ARRAY_SIZE(origen_quad_pwm_lookup));
	samsung_bl_set(&origen_quad_bl_gpio_info, &origen_quad_bl_data);

	platform_add_devices(origen_quad_devices, ARRAY_SIZE(origen_quad_devices));
}

MACHINE_START(ORIGEN_QUAD, "ORIGEN_QUAD")
	.atag_offset	= 0x100,
	.init_irq	= exynos4_init_irq,
	.map_io		= origen_quad_map_io,
	.handle_irq	= gic_handle_irq,
	.init_machine	= origen_quad_machine_init,
	.init_late	= exynos_init_late,
	.timer		= &exynos4_timer,
	.reserve	= &origen_quad_reserve,
	.restart	= exynos4_restart,

MACHINE_END

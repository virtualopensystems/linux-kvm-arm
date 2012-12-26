/*
 * Copyright (C) 2011 Samsung Electronics Co.Ltd
 * Author: Joonyoung Shim <jy0922.shim@samsung.com>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/usb/samsung_usb_phy.h>
#include <linux/platform_data/samsung-usbphy.h>
#include <mach/regs-pmu.h>
#include <mach/regs-usb-phy.h>
#include <plat/cpu.h>
#include <plat/map-base.h>
#include <plat/usb-phy.h>

#define PHY_ENABLE	1
#define PHY_DISABLE	0
#define EXYNOS5_USB_CFG		(S3C_VA_SYS + 0x230)

static atomic_t host_usage;

static int exynos4_usb_host_phy_is_on(void)
{
	if (soc_is_exynos5250()) {
		return (readl(EXYNOS5_PHY_HOST_CTRL0) &
				HOST_CTRL0_PHYSWRSTALL) ? 0 : 1;
	} else {
		return (readl(EXYNOS4_PHYPWR) &
				PHY1_STD_ANALOG_POWERDOWN) ? 0 : 1;
	}
}

static void exynos_usb_mux_change(struct platform_device *pdev, int val)
{
	u32 is_host;
	if (soc_is_exynos5250()) {
		is_host = readl(EXYNOS5_USB_CFG);
		writel(val, EXYNOS5_USB_CFG);
	}
	if (is_host != val)
		dev_dbg(&pdev->dev, "Change USB MUX from %s to %s",
		is_host ? "Host" : "Device", val ? "Host" : "Device");
}

static struct clk *exynos_usb_clock_enable(struct platform_device *pdev)
{
	struct clk *usb_clk = NULL;
	int err = 0;

	if (soc_is_exynos5250())
		usb_clk = clk_get(&pdev->dev, "usbhost");
	else
		usb_clk = clk_get(&pdev->dev, "otg");
	if (IS_ERR(usb_clk)) {
		dev_err(&pdev->dev, "Failed to get otg clock\n");
		return NULL;
	}

	err = clk_enable(usb_clk);
	if (err) {
		clk_put(usb_clk);
		return NULL;
	}
	return usb_clk;
}

static int exynos4210_usb_phy_clkset(struct platform_device *pdev)
{
	struct clk *xusbxti_clk;
	u32 phyclk = 0;

	if (soc_is_exynos5250())
		xusbxti_clk = clk_get(&pdev->dev, "ext_xtal");
	else
		xusbxti_clk = clk_get(&pdev->dev, "xusbxti");

	if (xusbxti_clk && !IS_ERR(xusbxti_clk)) {
		if (soc_is_exynos4210()) {
			/* set clock frequency for PLL */
			phyclk = readl(EXYNOS4_PHYCLK) & ~EXYNOS4210_CLKSEL_MASK;

			switch (clk_get_rate(xusbxti_clk)) {
			case 12 * MHZ:
				phyclk |= EXYNOS4210_CLKSEL_12M;
				break;
			case 48 * MHZ:
				phyclk |= EXYNOS4210_CLKSEL_48M;
				break;
			default:
			case 24 * MHZ:
				phyclk |= EXYNOS4210_CLKSEL_24M;
				break;
			}
			writel(phyclk, EXYNOS4_PHYCLK);
		} else if (soc_is_exynos4212() || soc_is_exynos4412()) {
			/* set clock frequency for PLL */
			phyclk = readl(EXYNOS4_PHYCLK) & ~EXYNOS4X12_CLKSEL_MASK;

			switch (clk_get_rate(xusbxti_clk)) {
			case 9600 * KHZ:
				phyclk |= EXYNOS4X12_CLKSEL_9600K;
				break;
			case 10 * MHZ:
				phyclk |= EXYNOS4X12_CLKSEL_10M;
				break;
			case 12 * MHZ:
				phyclk |= EXYNOS4X12_CLKSEL_12M;
				break;
			case 19200 * KHZ:
				phyclk |= EXYNOS4X12_CLKSEL_19200K;
				break;
			case 20 * MHZ:
				phyclk |= EXYNOS4X12_CLKSEL_20M;
				break;
			default:
			case 24 * MHZ:
				/* default reference clock */
				phyclk |= EXYNOS4X12_CLKSEL_24M;
				break;
			}
			writel(phyclk, EXYNOS4_PHYCLK);
		} else if (soc_is_exynos5250()) {
			/* set clock frequency for PLL */
			switch (clk_get_rate(xusbxti_clk)) {
			case 96 * 100000:
				phyclk |= EXYNOS5_CLKSEL_9600K;
				break;
			case 10 * MHZ:
				phyclk |= EXYNOS5_CLKSEL_10M;
				break;
			case 12 * MHZ:
				phyclk |= EXYNOS5_CLKSEL_12M;
				break;
			case 192 * 100000:
				phyclk |= EXYNOS5_CLKSEL_19200K;
				break;
			case 20 * MHZ:
				phyclk |= EXYNOS5_CLKSEL_20M;
				break;
			case 50 * MHZ:
				phyclk |= EXYNOS5_CLKSEL_50M;
				break;
			case 24 * MHZ:
			default:
				/* default reference clock */
				phyclk |= EXYNOS5_CLKSEL_24M;
				break;
			}
		}
		clk_put(xusbxti_clk);
	}
	return phyclk;
}
#if 0
static void exynos_usb_phy_control(enum usb_phy_type phy_type , int on)
{
	if (soc_is_exynos5250()) {
		if (phy_type & USB_PHY)
			writel(on, S5P_USBHOST_PHY_CONTROL);
	}
}
#endif
static int exynos4210_usb_phy0_init(struct platform_device *pdev)
{
	u32 rstcon;

	writel(readl(S5P_USBDEVICE_PHY_CONTROL) | S5P_USBDEVICE_PHY_ENABLE,
			S5P_USBDEVICE_PHY_CONTROL);

	exynos4210_usb_phy_clkset(pdev);

	/* set to normal PHY0 */
	writel((readl(EXYNOS4_PHYPWR) & ~PHY0_NORMAL_MASK), EXYNOS4_PHYPWR);

	/* reset PHY0 and Link */
	rstcon = readl(EXYNOS4_RSTCON) | PHY0_SWRST_MASK;
	writel(rstcon, EXYNOS4_RSTCON);
	udelay(10);

	rstcon &= ~PHY0_SWRST_MASK;
	writel(rstcon, EXYNOS4_RSTCON);

	return 0;
}

static int exynos4210_usb_phy0_exit(struct platform_device *pdev)
{
	writel((readl(EXYNOS4_PHYPWR) | PHY0_ANALOG_POWERDOWN |
				PHY0_OTG_DISABLE), EXYNOS4_PHYPWR);

	writel(readl(S5P_USBDEVICE_PHY_CONTROL) & ~S5P_USBDEVICE_PHY_ENABLE,
			S5P_USBDEVICE_PHY_CONTROL);

	return 0;
}

static int exynos4210_usb_phy1_init(struct platform_device *pdev)
{
	struct clk *otg_clk;
	u32 rstcon;

	atomic_inc(&host_usage);

	otg_clk = exynos_usb_clock_enable(pdev);
	if (otg_clk == NULL)
		dev_err(&pdev->dev, "Failed to enable otg clock\n");

	if (exynos4_usb_host_phy_is_on())
		return 0;

	writel(readl(S5P_USBHOST_PHY_CONTROL) | S5P_USBHOST_PHY_ENABLE,
			S5P_USBHOST_PHY_CONTROL);

	exynos4210_usb_phy_clkset(pdev);

	/* floating prevention logic: disable */
	writel((readl(EXYNOS4_PHY1CON) | FPENABLEN), EXYNOS4_PHY1CON);

	/* set to normal HSIC 0 and 1 of PHY1 */
	writel((readl(EXYNOS4_PHYPWR) & ~PHY1_HSIC_NORMAL_MASK),
			EXYNOS4_PHYPWR);

	/* set to normal standard USB of PHY1 */
	writel((readl(EXYNOS4_PHYPWR) & ~PHY1_STD_NORMAL_MASK), EXYNOS4_PHYPWR);

	/* reset all ports of both PHY and Link */
	rstcon = readl(EXYNOS4_RSTCON) | HOST_LINK_PORT_SWRST_MASK |
		PHY1_SWRST_MASK;
	writel(rstcon, EXYNOS4_RSTCON);
	udelay(10);

	rstcon &= ~(HOST_LINK_PORT_SWRST_MASK | PHY1_SWRST_MASK);
	writel(rstcon, EXYNOS4_RSTCON);
	udelay(80);

	clk_disable(otg_clk);
	clk_put(otg_clk);

	return 0;
}

static int exynos4210_usb_phy1_exit(struct platform_device *pdev)
{
	struct clk *otg_clk;

	if (atomic_dec_return(&host_usage) > 0)
		return 0;

	otg_clk = exynos_usb_clock_enable(pdev);
	if (otg_clk == NULL)
		dev_err(&pdev->dev, "Failed to enable otg clock\n");

	writel((readl(EXYNOS4_PHYPWR) | PHY1_STD_ANALOG_POWERDOWN),
			EXYNOS4_PHYPWR);

	writel(readl(S5P_USBHOST_PHY_CONTROL) & ~S5P_USBHOST_PHY_ENABLE,
			S5P_USBHOST_PHY_CONTROL);

	clk_disable(otg_clk);
	clk_put(otg_clk);

	return 0;
}


int s5p_usb_phy_init(struct platform_device *pdev, int type)
{
	if (type == USB_PHY_TYPE_DEVICE)
		return exynos4210_usb_phy0_init(pdev);
	else if (type == USB_PHY_TYPE_HOST) {
			return exynos4210_usb_phy1_init(pdev);
	}

	return -EINVAL;
}

int s5p_usb_phy_exit(struct platform_device *pdev, int type)
{

	if (type == USB_PHY_TYPE_DEVICE)
		return exynos4210_usb_phy0_exit(pdev);
	else if (type == USB_PHY_TYPE_HOST) {
			return exynos4210_usb_phy1_exit(pdev);
	}
	return -EINVAL;
}

 void s5p_usb_phy_pmu_isolation(int on, int type)
 {
	if (type == USB_PHY_TYPE_HOST) {
		if (on)
			writel(readl(S5P_USBHOST_PHY_CONTROL)
				& ~S5P_USBHOST_PHY_ENABLE,
					S5P_USBHOST_PHY_CONTROL);
		else
			writel(readl(S5P_USBHOST_PHY_CONTROL)
				| S5P_USBHOST_PHY_ENABLE,
					S5P_USBHOST_PHY_CONTROL);
	}else if(type == USB_PHY_TYPE_DRD) {
		if (on)
			writel(readl(S5P_USBDRD_PHY_CONTROL)
				& ~S5P_USBDRD_PHY_ENABLE,
					S5P_USBDRD_PHY_CONTROL);
		else
			writel(readl(S5P_USBDRD_PHY_CONTROL)
                                 | S5P_USBDRD_PHY_ENABLE,
                                         S5P_USBDRD_PHY_CONTROL);
	} else {
		if (on)
			writel(readl(S5P_USBDEVICE_PHY_CONTROL)
				& ~S5P_USBDEVICE_PHY_ENABLE,
					S5P_USBDEVICE_PHY_CONTROL);
		else
			writel(readl(S5P_USBDEVICE_PHY_CONTROL)
				| S5P_USBDEVICE_PHY_ENABLE,
					S5P_USBDEVICE_PHY_CONTROL);
	}
 }

/* Switch between HOST and OTG link from PHY_CFG */
void s5p_usb_phy_cfg_sel(struct device *dev, int type)
{
	u32 is_host;

	is_host = readl(EXYNOS5_USB_CFG);
	writel(type, EXYNOS5_USB_CFG);

	if (is_host != type)
		dev_dbg(dev, "Changed USB MUX from %s to %s",
			is_host ? "Host" : "Device", type ? "Host" : "Device");
}

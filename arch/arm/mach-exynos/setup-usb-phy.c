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
#include <mach/regs-pmu.h>
#include <mach/regs-usb-phy.h>
#include <plat/cpu.h>
#include <plat/usb-phy.h>

#define PHY_ENABLE	1
#define PHY_DISABLE	0

enum usb_phy_type {
	USB_PHY		= (0x1 << 0),
};

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

static void exynos_usb_phy_control(enum usb_phy_type phy_type , int on)
{
	if (soc_is_exynos5250()) {
		if (phy_type & USB_PHY)
			writel(on, S5P_USBHOST_PHY_CONTROL);
	}
}

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

static int exynos5_usb_phy20_init(struct platform_device *pdev)
{
	struct clk *host_clk;
	u32 refclk_freq;
	u32 hostphy_ctrl0;
	u32 otgphy_sys;
	u32 hsic_ctrl;
	u32 ehcictrl;
	u32 ohcictrl;

	atomic_inc(&host_usage);
	host_clk = exynos_usb_clock_enable(pdev);
	if (host_clk == NULL) {
		dev_err(&pdev->dev, "Failed to enable USB2.0 host clock\n");
		return -1;
	}

	if (exynos4_usb_host_phy_is_on()) {
		dev_err(&pdev->dev, "Already power on PHY\n");
		return 0;
	}

	exynos_usb_mux_change(pdev, 1);

	exynos_usb_phy_control(USB_PHY, PHY_ENABLE);

	/* Host and Device should be set at the same time */
	hostphy_ctrl0 = readl(EXYNOS5_PHY_HOST_CTRL0);
	hostphy_ctrl0 &= ~(HOST_CTRL0_FSEL_MASK);
	otgphy_sys = readl(EXYNOS5_PHY_OTG_SYS);
	otgphy_sys &= ~(OTG_SYS_CTRL0_FSEL_MASK);

	/* 2.0 phy reference clock configuration */
	refclk_freq = exynos4210_usb_phy_clkset(pdev);
	hostphy_ctrl0 |= (refclk_freq << HOST_CTRL0_CLKSEL_SHIFT);
	otgphy_sys |= (refclk_freq << OTG_SYS_CLKSEL_SHIFT);

	/* COMMON Block configuration during suspend */
	hostphy_ctrl0 |= (HOST_CTRL0_COMMONON_N);
	otgphy_sys &= ~(OTG_SYS_COMMON_ON);

	/* otg phy reset */
	otgphy_sys &= ~(OTG_SYS_FORCE_SUSPEND | OTG_SYS_SIDDQ_UOTG
						| OTG_SYS_FORCE_SLEEP);
	otgphy_sys &= ~(OTG_SYS_REF_CLK_SEL_MASK << OTG_SYS_REF_CLK_SEL_SHIFT);
	otgphy_sys |= (((OTG_SYS_REF_CLK_SEL_CLKCORE & OTG_SYS_REF_CLK_SEL_MASK)
						<< OTG_SYS_REF_CLK_SEL_SHIFT)
						| OTG_SYS_OTGDISABLE);
	otgphy_sys |= (OTG_SYS_PHY0_SW_RST | OTG_SYS_LINK_SW_RST_UOTG
						| OTG_SYS_PHYLINK_SW_RESET);
	writel(otgphy_sys, EXYNOS5_PHY_OTG_SYS);
	udelay(10);
	otgphy_sys &= ~(OTG_SYS_PHY0_SW_RST | OTG_SYS_LINK_SW_RST_UOTG
						| OTG_SYS_PHYLINK_SW_RESET);
	writel(otgphy_sys, EXYNOS5_PHY_OTG_SYS);

	/* host phy reset */
	hostphy_ctrl0 &= ~(HOST_CTRL0_PHYSWRST | HOST_CTRL0_PHYSWRSTALL
						| HOST_CTRL0_SIDDQ);
	hostphy_ctrl0 &= ~(HOST_CTRL0_FORCESUSPEND | HOST_CTRL0_FORCESLEEP);
	hostphy_ctrl0 |= (HOST_CTRL0_LINKSWRST | HOST_CTRL0_UTMISWRST);
	writel(hostphy_ctrl0, EXYNOS5_PHY_HOST_CTRL0);
	udelay(10);
	hostphy_ctrl0 &= ~(HOST_CTRL0_LINKSWRST | HOST_CTRL0_UTMISWRST);
	writel(hostphy_ctrl0, EXYNOS5_PHY_HOST_CTRL0);

	/* HSIC phy reset */
	hsic_ctrl = (((HSIC_CTRL_REFCLKDIV_12 & HSIC_CTRL_REFCLKDIV_MASK)
				<< HSIC_CTRL_REFCLKDIV_SHIFT)
			| ((HSIC_CTRL_REFCLKSEL & HSIC_CTRL_REFCLKSEL_MASK)
				<< HSIC_CTRL_REFCLKSEL_SHIFT)
			| HSIC_CTRL_PHYSWRST);
	writel(hsic_ctrl, EXYNOS5_PHY_HSIC_CTRL1);
	writel(hsic_ctrl, EXYNOS5_PHY_HSIC_CTRL2);
	udelay(10);
	hsic_ctrl &= ~(HSIC_CTRL_PHYSWRST);
	writel(hsic_ctrl, EXYNOS5_PHY_HSIC_CTRL1);
	writel(hsic_ctrl, EXYNOS5_PHY_HSIC_CTRL2);

	udelay(80);

	/* enable EHCI DMA burst  */
	ehcictrl = readl(EXYNOS5_PHY_HOST_EHCICTRL);
	ehcictrl |= (EHCICTRL_ENAINCRXALIGN | EHCICTRL_ENAINCR4
				| EHCICTRL_ENAINCR8 | EHCICTRL_ENAINCR16);
	writel(ehcictrl, EXYNOS5_PHY_HOST_EHCICTRL);

	/* set ohci_suspend_on_n */
	ohcictrl = readl(EXYNOS5_PHY_HOST_OHCICTRL);
	ohcictrl |= OHCICTRL_SUSPLGCY;
	writel(ohcictrl, EXYNOS5_PHY_HOST_OHCICTRL);

	clk_disable(host_clk);
	clk_put(host_clk);
	return 0;
}

static int exynos5_usb_phy20_exit(struct platform_device *pdev)
{
	struct clk *host_clk;
	u32 hostphy_ctrl0;
	u32 otgphy_sys;
	u32 hsic_ctrl;

	if (atomic_dec_return(&host_usage) > 0) {
		dev_info(&pdev->dev, "still being used\n");
		return -EBUSY;
	}

	host_clk = exynos_usb_clock_enable(pdev);
	if (host_clk == NULL) {
		dev_err(&pdev->dev, "Failed to enable otg clock this time\n");
		return -1;
	}

	hsic_ctrl = (((HSIC_CTRL_REFCLKDIV_12 & HSIC_CTRL_REFCLKDIV_MASK)
				<< HSIC_CTRL_REFCLKDIV_SHIFT)
			| ((HSIC_CTRL_REFCLKSEL	& HSIC_CTRL_REFCLKSEL_MASK)
				<< HSIC_CTRL_REFCLKSEL_SHIFT)
			| HSIC_CTRL_SIDDQ | HSIC_CTRL_FORCESLEEP
			| HSIC_CTRL_FORCESUSPEND);
	writel(hsic_ctrl, EXYNOS5_PHY_HSIC_CTRL1);
	writel(hsic_ctrl, EXYNOS5_PHY_HSIC_CTRL2);

	hostphy_ctrl0 = readl(EXYNOS5_PHY_HOST_CTRL0);
	hostphy_ctrl0 |= (HOST_CTRL0_SIDDQ);
	hostphy_ctrl0 |= (HOST_CTRL0_FORCESUSPEND | HOST_CTRL0_FORCESLEEP);
	hostphy_ctrl0 |= (HOST_CTRL0_PHYSWRST | HOST_CTRL0_PHYSWRSTALL);
	writel(hostphy_ctrl0, EXYNOS5_PHY_HOST_CTRL0);

	otgphy_sys = readl(EXYNOS5_PHY_OTG_SYS);
	otgphy_sys |= (OTG_SYS_FORCE_SUSPEND | OTG_SYS_SIDDQ_UOTG
				| OTG_SYS_FORCE_SLEEP);
	writel(otgphy_sys, EXYNOS5_PHY_OTG_SYS);

	exynos_usb_phy_control(USB_PHY, PHY_DISABLE);

	clk_disable(host_clk);
	clk_put(host_clk);
	return 0;
}

int s5p_usb_phy_init(struct platform_device *pdev, int type)
{
	if (type == S5P_USB_PHY_DEVICE)
		return exynos4210_usb_phy0_init(pdev);
	else if (type == S5P_USB_PHY_HOST) {
		if (soc_is_exynos5250())
			return exynos5_usb_phy20_init(pdev);
		else
			return exynos4210_usb_phy1_init(pdev);
	}

	return -EINVAL;
}

int s5p_usb_phy_exit(struct platform_device *pdev, int type)
{
	if (type == S5P_USB_PHY_DEVICE)
		return exynos4210_usb_phy0_exit(pdev);
	else if (type == S5P_USB_PHY_HOST) {
		if (soc_is_exynos5250())
			return exynos5_usb_phy20_exit(pdev);
		else
			return exynos4210_usb_phy1_exit(pdev);
	}
	return -EINVAL;
}

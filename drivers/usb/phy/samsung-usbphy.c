/*
copyright (c) 2012 Samsung Electronics Co., Ltd.
 *              http://www.samsung.com
 *
 * Author: Praveen Paneri <p.paneri@samsung.com>
 *
 * Samsung USB-PHY transceiver; talks to S3C HS OTG controller, EHCI-S5P and
 * OHCI-EXYNOS controllers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/usb/samsung_usb_phy.h>
#include <linux/platform_data/samsung-usbphy.h>

/* Register definitions */

#define SAMSUNG_PHYPWR				(0x00)

#define PHYPWR_NORMAL_MASK			(0x19 << 0)
#define PHYPWR_OTG_DISABLE			(0x1 << 4)
#define PHYPWR_ANALOG_POWERDOWN			(0x1 << 3)
#define PHYPWR_FORCE_SUSPEND			(0x1 << 1)
/* For Exynos4 */
#define PHYPWR_NORMAL_MASK_PHY0			(0x39 << 0)
#define PHYPWR_SLEEP_PHY0			(0x1 << 5)

#define SAMSUNG_PHYCLK				(0x04)

#define PHYCLK_MODE_USB11			(0x1 << 6)
#define PHYCLK_EXT_OSC				(0x1 << 5)
#define PHYCLK_COMMON_ON_N			(0x1 << 4)
#define PHYCLK_ID_PULL				(0x1 << 2)
#define PHYCLK_CLKSEL_MASK			(0x3 << 0)
#define PHYCLK_CLKSEL_48M			(0x0 << 0)
#define PHYCLK_CLKSEL_12M			(0x2 << 0)
#define PHYCLK_CLKSEL_24M			(0x3 << 0)

#define SAMSUNG_RSTCON				(0x08)

#define RSTCON_PHYLINK_SWRST			(0x1 << 2)
#define RSTCON_HLINK_SWRST			(0x1 << 1)
#define RSTCON_SWRST				(0x1 << 0)
/* EXYNOS5 */
#define EXYNOS5_PHY_HOST_CTRL0			(0x00)

#define HOST_CTRL0_PHYSWRSTALL			(0x1 << 31)

#define HOST_CTRL0_REFCLKSEL_MASK		(0x3)
#define HOST_CTRL0_REFCLKSEL(_x)		((_x) << 19)
#define HOST_CTRL0_REFCLKSEL_XTAL		\
		HOST_CTRL0_REFCLKSEL(0x0)
#define HOST_CTRL0_REFCLKSEL_EXTL		\
		HOST_CTRL0_REFCLKSEL(0x1)
#define HOST_CTRL0_REFCLKSEL_CLKCORE		\
		HOST_CTRL0_REFCLKSEL(0x2)

#define HOST_CTRL0_FSEL_MASK			(0x7 << 16)
#define HOST_CTRL0_FSEL(_x)			((_x) << 16)
#define HOST_CTRL0_FSEL_CLKSEL_50M		(0x7)
#define HOST_CTRL0_FSEL_CLKSEL_24M		(0x5)
#define HOST_CTRL0_FSEL_CLKSEL_20M		(0x4)
#define HOST_CTRL0_FSEL_CLKSEL_19200K		(0x3)
#define HOST_CTRL0_FSEL_CLKSEL_12M		(0x2)
#define HOST_CTRL0_FSEL_CLKSEL_10M		(0x1)
#define HOST_CTRL0_FSEL_CLKSEL_9600K		(0x0)

#define HOST_CTRL0_TESTBURNIN			(0x1 << 11)
#define HOST_CTRL0_RETENABLE			(0x1 << 10)
#define HOST_CTRL0_COMMONON_N			(0x1 << 9)
#define HOST_CTRL0_SIDDQ			(0x1 << 6)
#define HOST_CTRL0_FORCESLEEP			(0x1 << 5)
#define HOST_CTRL0_FORCESUSPEND			(0x1 << 4)
#define HOST_CTRL0_WORDINTERFACE		(0x1 << 3)
#define HOST_CTRL0_UTMISWRST			(0x1 << 2)
#define HOST_CTRL0_LINKSWRST			(0x1 << 1)
#define HOST_CTRL0_PHYSWRST			(0x1 << 0)

#define EXYNOS5_PHY_HOST_TUNE0			(0x04)

#define EXYNOS5_PHY_HSIC_CTRL1			(0x10)

#define EXYNOS5_PHY_HSIC_TUNE1			(0x14)

#define EXYNOS5_PHY_HSIC_CTRL2			(0x20)

#define EXYNOS5_PHY_HSIC_TUNE2			(0x24)

#define HSIC_CTRL_REFCLKSEL_MASK		(0x3)
#define HSIC_CTRL_REFCLKSEL			(0x2 << 23)

#define HSIC_CTRL_REFCLKDIV_MASK		(0x7f)
#define HSIC_CTRL_REFCLKDIV(_x)			((_x) << 16)
#define HSIC_CTRL_REFCLKDIV_12			\
		HSIC_CTRL_REFCLKDIV(0x24)
#define HSIC_CTRL_REFCLKDIV_15			\
		HSIC_CTRL_REFCLKDIV(0x1C)
#define HSIC_CTRL_REFCLKDIV_16			\
		HSIC_CTRL_REFCLKDIV(0x1A)
#define HSIC_CTRL_REFCLKDIV_19_2		\
		HSIC_CTRL_REFCLKDIV(0x15)
#define HSIC_CTRL_REFCLKDIV_20			\
		HSIC_CTRL_REFCLKDIV(0x14)

#define HSIC_CTRL_SIDDQ				(0x1 << 6)
#define HSIC_CTRL_FORCESLEEP			(0x1 << 5)
#define HSIC_CTRL_FORCESUSPEND			(0x1 << 4)
#define HSIC_CTRL_WORDINTERFACE			(0x1 << 3)
#define HSIC_CTRL_UTMISWRST			(0x1 << 2)
#define HSIC_CTRL_PHYSWRST			(0x1 << 0)

#define EXYNOS5_PHY_HOST_EHCICTRL		(0x30)

#define HOST_EHCICTRL_ENAINCRXALIGN		(0x1 << 29)
#define HOST_EHCICTRL_ENAINCR4			(0x1 << 28)
#define HOST_EHCICTRL_ENAINCR8			(0x1 << 27)
#define HOST_EHCICTRL_ENAINCR16			(0x1 << 26)

#define EXYNOS5_PHY_HOST_OHCICTRL		(0x34)

#define HOST_OHCICTRL_SUSPLGCY			(0x1 << 3)
#define HOST_OHCICTRL_APPSTARTCLK		(0x1 << 2)
#define HOST_OHCICTRL_CNTSEL			(0x1 << 1)
#define HOST_OHCICTRL_CLKCKTRST			(0x1 << 0)

#define EXYNOS5_PHY_OTG_SYS			(0x38)

#define OTG_SYS_PHYLINK_SWRESET			(0x1 << 14)
#define OTG_SYS_LINKSWRST_UOTG			(0x1 << 13)
#define OTG_SYS_PHY0_SWRST			(0x1 << 12)

#define OTG_SYS_REFCLKSEL_MASK			(0x3 << 9)
#define OTG_SYS_REFCLKSEL(_x)			((_x) << 9)
#define OTG_SYS_REFCLKSEL_XTAL			\
		OTG_SYS_REFCLKSEL(0x0)
#define OTG_SYS_REFCLKSEL_EXTL			\
		OTG_SYS_REFCLKSEL(0x1)
#define OTG_SYS_REFCLKSEL_CLKCORE		\
		OTG_SYS_REFCLKSEL(0x2)

#define OTG_SYS_IDPULLUP_UOTG			(0x1 << 8)
#define OTG_SYS_COMMON_ON			(0x1 << 7)

#define OTG_SYS_FSEL_MASK			(0x7 << 4)
#define OTG_SYS_FSEL(_x)			((_x) << 4)

#define OTG_SYS_FORCESLEEP			(0x1 << 3)
#define OTG_SYS_OTGDISABLE			(0x1 << 2)
#define OTG_SYS_SIDDQ_UOTG			(0x1 << 1)
#define OTG_SYS_FORCESUSPEND			(0x1 << 0)

#define EXYNOS5_PHY_OTG_TUNE			(0x40)

/* USB 3.0: DRD */
#define EXYNOS5_DRD_LINKSYSTEM			(0x04)

#define LINKSYSTEM_FLADJ_MASK			(0x3f << 1)
#define LINKSYSTEM_FLADJ(_x)			((_x) << 1)
#define LINKSYSTEM_XHCI_VERSION_CONTROL		(1 << 27)

#define EXYNOS5_DRD_PHYUTMI			(0x08)

#define PHYUTMI_OTGDISABLE			(1 << 6)
#define PHYUTMI_FORCESUSPEND			(1 << 1)
#define PHYUTMI_FORCESLEEP			(1 << 0)

#define EXYNOS5_DRD_PHYPIPE			(0x0C)

#define EXYNOS5_DRD_PHYCLKRST			(0x10)

#define PHYCLKRST_SSC_REFCLKSEL_MASK		(0xff << 23)
#define PHYCLKRST_SSC_REFCLKSEL(_x)		((_x) << 23)

#define PHYCLKRST_SSC_RANGE_MASK		(0x03 << 21)
#define PHYCLKRST_SSC_RANGE(_x)			((_x) << 21)

#define PHYCLKRST_SSC_EN			(1 << 20)
#define PHYCLKRST_REF_SSP_EN			(1 << 19)
#define PHYCLKRST_REF_CLKDIV2			(1 << 18)

#define PHYCLKRST_MPLL_MULTIPLIER_MASK		(0x7f << 11)
#define PHYCLKRST_MPLL_MULTIPLIER(_x)		((_x) << 11)
#define PHYCLKRST_MPLL_MULTIPLIER_100MHZ_REF	\
		PHYCLKRST_MPLL_MULTIPLIER(0x19)
#define PHYCLKRST_MPLL_MULTIPLIER_50M_REF	\
		PHYCLKRST_MPLL_MULTIPLIER(0x02)
#define PHYCLKRST_MPLL_MULTIPLIER_24MHZ_REF	\
		PHYCLKRST_MPLL_MULTIPLIER(0x68)
#define PHYCLKRST_MPLL_MULTIPLIER_20MHZ_REF	\
		PHYCLKRST_MPLL_MULTIPLIER(0x7d)
#define PHYCLKRST_MPLL_MULTIPLIER_19200KHZ_REF	\
		PHYCLKRST_MPLL_MULTIPLIER(0x02)

#define PHYCLKRST_FSEL_MASK			(0x3f << 5)
#define PHYCLKRST_FSEL(_x)			((_x) << 5)
#define PHYCLKRST_FSEL_PAD_100MHZ		\
		PHYCLKRST_FSEL(0x27)
#define PHYCLKRST_FSEL_PAD_24MHZ		\
		PHYCLKRST_FSEL(0x2a)
#define PHYCLKRST_FSEL_PAD_20MHZ		\
+		PHYCLKRST_FSEL(0x31)
#define PHYCLKRST_FSEL_PAD_19_2MHZ		\
		PHYCLKRST_FSEL(0x38)

#define PHYCLKRST_RETENABLEN			(1 << 4)

#define PHYCLKRST_REFCLKSEL_MASK		(0x03 << 2)
#define PHYCLKRST_REFCLKSEL(_x)			((_x) << 2)
#define PHYCLKRST_REFCLKSEL_PAD_REFCLK		\
		PHYCLKRST_REFCLKSEL(2)
#define PHYCLKRST_REFCLKSEL_EXT_REFCLK		\
		PHYCLKRST_REFCLKSEL(3)

#define PHYCLKRST_PORTRESET			(1 << 1)
#define PHYCLKRST_COMMONONN			(1 << 0)

#define EXYNOS5_DRD_PHYREG0			(0x14)
#define EXYNOS5_DRD_PHYREG1			(0x18)

#define EXYNOS5_DRD_PHYPARAM0			(0x1C)

#define PHYPARAM0_REF_USE_PAD			(0x1 << 31)
#define PHYPARAM0_REF_LOSLEVEL_MASK		(0x1f << 26)
#define PHYPARAM0_REF_LOSLEVEL			(0x9 << 26)

#define EXYNOS5_DRD_PHYPARAM1			(0x20)

#define PHYPARAM1_PCS_TXDEEMPH_MASK		(0x1f << 0)
#define PHYPARAM1_PCS_TXDEEMPH			(0x1C)

#define EXYNOS5_DRD_PHYTERM			(0x24)

#define EXYNOS5_DRD_PHYTEST			(0x28)

#define PHYTEST_POWERDOWN_SSP			(1 << 3)
#define PHYTEST_POWERDOWN_HSP			(1 << 2)

#define EXYNOS5_DRD_PHYADP			(0x2C)

#define EXYNOS5_DRD_PHYBATCHG			(0x30)

#define PHYBATCHG_UTMI_CLKSEL			(0x1 << 2)

#define EXYNOS5_DRD_PHYRESUME			(0x34)
#define EXYNOS5_DRD_LINKPORT			(0x44)

#ifndef MHZ
#define MHZ (1000*1000)
#endif

enum samsung_cpu_type {
	TYPE_S3C64XX,
	TYPE_EXYNOS4210,
	TYPE_EXYNOS5250,
};

/*
 * struct samsung_usbphy - transceiver driver state
 * @phy: transceiver structure
 * @phy3: transceiver structure for USB 3.0
 * @plat: platform data
 * @dev: The parent device supplied to the probe function
 * @clk: usb phy clock
 * @regs: usb phy register memory base
 * @regs_phy3: usb 3.0 phy register memory base
 * @ref_clk_freq: reference clock frequency selection
 * @cpu_type: machine identifier
 * @phy_type: It keeps track of the PHY type.
 * @host_usage: host_phy usage count.
*/
struct samsung_usbphy {
	struct usb_phy	phy;
	struct usb_phy	phy3;
	struct samsung_usbphy_data *plat;
	struct device	*dev;
	struct clk	*clk;
	void __iomem	*regs;
	void __iomem	*regs_phy3;
	int		ref_clk_freq;
	int		cpu_type;
	enum samsung_usb_phy_type phy_type;
	atomic_t	host_usage;
};

#define phy_to_sphy(x)		container_of((x), struct samsung_usbphy, phy)
#define phy3_to_sphy(x)		container_of((x), struct samsung_usbphy, phy3)
/*
+ * PHYs are different for USB Device and USB Host. Controllers can make
+ * sure that the correct PHY type is selected by calling this function
+ * before any PHY operation.
+ */
int samsung_usbphy_set_type(struct usb_phy *phy,
				enum samsung_usb_phy_type phy_type)
{
	struct samsung_usbphy *sphy = phy_to_sphy(phy);

	if (sphy->phy_type != phy_type)
		sphy->phy_type = phy_type;

	return 0;
}

/*
 * Returns reference clock frequency selection value
 */
static int samsung_usbphy_get_refclk_freq(struct samsung_usbphy *sphy)
{
	struct clk *ref_clk;
	int refclk_freq = 0;

	if (sphy->cpu_type == TYPE_EXYNOS5250)
		ref_clk = clk_get(sphy->dev, "ext_xtal");
	else
		ref_clk = clk_get(sphy->dev, "xusbxti");
	if (IS_ERR(ref_clk)) {
		dev_err(sphy->dev, "Failed to get reference clock\n");
		return PTR_ERR(ref_clk);
	}
			if (sphy->cpu_type == TYPE_EXYNOS5250) {
		/* set clock frequency for PLL */
		switch (clk_get_rate(ref_clk)) {
		case 96 * 100000:
			refclk_freq |= HOST_CTRL0_FSEL_CLKSEL_9600K;
			break;
		case 10 * MHZ:
			refclk_freq |= HOST_CTRL0_FSEL_CLKSEL_10M;
			break;
		case 12 * MHZ:
			refclk_freq |= HOST_CTRL0_FSEL_CLKSEL_12M;
			break;
		case 192 * 100000:
			refclk_freq |= HOST_CTRL0_FSEL_CLKSEL_19200K;
			break;
		case 20 * MHZ:
			refclk_freq |= HOST_CTRL0_FSEL_CLKSEL_20M;
			break;
		case 50 * MHZ:
			refclk_freq |= HOST_CTRL0_FSEL_CLKSEL_50M;
			break;
		case 24 * MHZ:
		default:
			/* default reference clock */
			refclk_freq |= HOST_CTRL0_FSEL_CLKSEL_24M;
		}
	} else {
		switch (clk_get_rate(ref_clk)) {
		case 12 * MHZ:
			refclk_freq = PHYCLK_CLKSEL_12M;
			break;
		case 24 * MHZ:
			refclk_freq = PHYCLK_CLKSEL_24M;
			break;
		case 48 * MHZ:
			refclk_freq = PHYCLK_CLKSEL_48M;
			break;
		default:
			if (sphy->cpu_type == TYPE_S3C64XX)
				refclk_freq = PHYCLK_CLKSEL_48M;
			else
				refclk_freq = PHYCLK_CLKSEL_24M;
			break;
		}
	}
	clk_put(ref_clk);

	return refclk_freq;
}

 /*
 * Sets the phy clk as EXTREFCLK (XXTI) which is internal clock form clock core.
 */
static u32 exynos5_usbphy3_set_clock(struct samsung_usbphy *sphy)
{
	u32 reg;
	u32 refclk;

	refclk = sphy->ref_clk_freq;

	reg = PHYCLKRST_REFCLKSEL_EXT_REFCLK |
		PHYCLKRST_FSEL(refclk);

	switch (refclk) {
	case HOST_CTRL0_FSEL_CLKSEL_50M:
		reg |= (PHYCLKRST_MPLL_MULTIPLIER_50M_REF |
			PHYCLKRST_SSC_REFCLKSEL(0x00));
		break;
	case HOST_CTRL0_FSEL_CLKSEL_20M:
		reg |= (PHYCLKRST_MPLL_MULTIPLIER_20MHZ_REF |
			PHYCLKRST_SSC_REFCLKSEL(0x00));
		break;
	case HOST_CTRL0_FSEL_CLKSEL_19200K:
		reg |= (PHYCLKRST_MPLL_MULTIPLIER_19200KHZ_REF |
			PHYCLKRST_SSC_REFCLKSEL(0x88));
		break;
	case HOST_CTRL0_FSEL_CLKSEL_24M:
	default:
		reg |= (PHYCLKRST_MPLL_MULTIPLIER_24MHZ_REF |
			PHYCLKRST_SSC_REFCLKSEL(0x88));
		break;
	}

	return reg;
}

static int exynos5_phyhost_is_on(void *regs)
{
	return (readl(regs + EXYNOS5_PHY_HOST_CTRL0) &
				HOST_CTRL0_SIDDQ) ? 0 : 1;
}

static int samsung_exynos5_usbphy3_enable(struct samsung_usbphy *sphy)
{
	void __iomem *regs = sphy->regs_phy3;
	u32 phyparam0;
	u32 phyparam1;
	u32 linksystem;
	u32 phybatchg;
	u32 phytest;
	u32 phyclkrst;
	/* Reset USB 3.0 PHY */
	writel(0x0, regs + EXYNOS5_DRD_PHYREG0);

	phyparam0 = readl(regs + EXYNOS5_DRD_PHYPARAM0);
	/* Select PHY CLK source */
	phyparam0 &= ~PHYPARAM0_REF_USE_PAD;
	/* Set Loss-of-Signal Detector sensitivity */
	phyparam0 &= ~PHYPARAM0_REF_LOSLEVEL_MASK;
	phyparam0 |= PHYPARAM0_REF_LOSLEVEL;
	writel(phyparam0, regs + EXYNOS5_DRD_PHYPARAM0);

	writel(0x0, regs + EXYNOS5_DRD_PHYRESUME);

	/*
	 * Setting the Frame length Adj value[6:1] to default 0x20
	 * See xHCI 1.0 spec, 5.2.4
	 */
	linksystem = LINKSYSTEM_XHCI_VERSION_CONTROL |
			LINKSYSTEM_FLADJ(0x20);
	writel(linksystem, regs + EXYNOS5_DRD_LINKSYSTEM);

	phyparam1 = readl(regs + EXYNOS5_DRD_PHYPARAM1);
	/* Set Tx De-Emphasis level */
	phyparam1 &= ~PHYPARAM1_PCS_TXDEEMPH_MASK;
	phyparam1 |= PHYPARAM1_PCS_TXDEEMPH;
	writel(phyparam1, regs + EXYNOS5_DRD_PHYPARAM1);

	phybatchg = readl(regs + EXYNOS5_DRD_PHYBATCHG);
	phybatchg |= PHYBATCHG_UTMI_CLKSEL;
	writel(phybatchg, regs + EXYNOS5_DRD_PHYBATCHG);

	/* PHYTEST POWERDOWN Control */
	phytest = readl(regs + EXYNOS5_DRD_PHYTEST);
	phytest &= ~(PHYTEST_POWERDOWN_SSP |
			PHYTEST_POWERDOWN_HSP);
	writel(phytest, regs + EXYNOS5_DRD_PHYTEST);

	/* UTMI Power Control */
	writel(PHYUTMI_OTGDISABLE, regs + EXYNOS5_DRD_PHYUTMI);

	phyclkrst = exynos5_usbphy3_set_clock(sphy);

	phyclkrst |= PHYCLKRST_PORTRESET |
			/* Digital power supply in normal operating mode */
			PHYCLKRST_RETENABLEN |
			/* Enable ref clock for SS function */
			PHYCLKRST_REF_SSP_EN |
			/* Enable spread spectrum */
			PHYCLKRST_SSC_EN |
			/* Power down HS Bias and PLL blocks in suspend mode */
			PHYCLKRST_COMMONONN;

	writel(phyclkrst, regs + EXYNOS5_DRD_PHYCLKRST);

	udelay(10);

	phyclkrst &= ~(PHYCLKRST_PORTRESET);
	writel(phyclkrst, regs + EXYNOS5_DRD_PHYCLKRST);

	return 0;
}

static void samsung_exynos5_usbphy_enable(struct samsung_usbphy *sphy)
{
	void __iomem *regs = sphy->regs;
	u32 phyclk = sphy->ref_clk_freq;
	u32 phyhost;
	u32 phyotg;
	u32 phyhsic;
	u32 ehcictrl;
	u32 ohcictrl;

	atomic_inc(&sphy->host_usage);

	if (exynos5_phyhost_is_on(regs)) {
		dev_info(sphy->dev, "Already power on PHY\n");
		return;
	}
	/* Selecting Host/OTG mode; After reset USB2.0PHY_CFG: HOST */
	if (sphy->plat && sphy->plat->phy_cfg_sel)
		sphy->plat->phy_cfg_sel(sphy->dev, USB_PHY_TYPE_HOST);

	/* Host configuration */
	phyhost = readl(regs + EXYNOS5_PHY_HOST_CTRL0);

	/* phy reference clock configuration */
	phyhost &= ~HOST_CTRL0_FSEL_MASK;
	phyhost |= HOST_CTRL0_FSEL(phyclk);

	/* host phy reset */
	phyhost &= ~(HOST_CTRL0_PHYSWRST |
			HOST_CTRL0_PHYSWRSTALL |
			HOST_CTRL0_SIDDQ |
			/* Enable normal mode of operation */
			HOST_CTRL0_FORCESUSPEND |
			HOST_CTRL0_FORCESLEEP);

	/* Link reset */
	phyhost |= (HOST_CTRL0_LINKSWRST |
			HOST_CTRL0_UTMISWRST |
			/* COMMON Block configuration during suspend */
			HOST_CTRL0_COMMONON_N);
	writel(phyhost, regs + EXYNOS5_PHY_HOST_CTRL0);
	udelay(10);
	phyhost &= ~(HOST_CTRL0_LINKSWRST |
			HOST_CTRL0_UTMISWRST);
	writel(phyhost, regs + EXYNOS5_PHY_HOST_CTRL0);

	/* OTG configuration */
	phyotg = readl(regs + EXYNOS5_PHY_OTG_SYS);

	/* phy reference clock configuration */
	phyotg &= ~OTG_SYS_FSEL_MASK;
	phyotg |= OTG_SYS_FSEL(phyclk);

	/* Enable normal mode of operation */
	phyotg &= ~(OTG_SYS_FORCESUSPEND |
			OTG_SYS_SIDDQ_UOTG |
			OTG_SYS_FORCESLEEP |
			OTG_SYS_REFCLKSEL_MASK |
			/* COMMON Block configuration during suspend */
			OTG_SYS_COMMON_ON);

	/* OTG phy & link reset */
	phyotg |= (OTG_SYS_PHY0_SWRST |
			OTG_SYS_LINKSWRST_UOTG |
			OTG_SYS_PHYLINK_SWRESET |
			OTG_SYS_OTGDISABLE |
			/* Set phy refclk */
			OTG_SYS_REFCLKSEL_CLKCORE);

	writel(phyotg, regs + EXYNOS5_PHY_OTG_SYS);
	udelay(10);
	phyotg &= ~(OTG_SYS_PHY0_SWRST |
			OTG_SYS_LINKSWRST_UOTG |
			OTG_SYS_PHYLINK_SWRESET);
	writel(phyotg, regs + EXYNOS5_PHY_OTG_SYS);

	/* HSIC phy configuration */
	phyhsic = (HSIC_CTRL_REFCLKDIV_12 |
			HSIC_CTRL_REFCLKSEL |
			HSIC_CTRL_PHYSWRST);
	writel(phyhsic, regs + EXYNOS5_PHY_HSIC_CTRL1);
	writel(phyhsic, regs + EXYNOS5_PHY_HSIC_CTRL2);
	udelay(10);
	phyhsic &= ~HSIC_CTRL_PHYSWRST;
	writel(phyhsic, regs + EXYNOS5_PHY_HSIC_CTRL1);
	writel(phyhsic, regs + EXYNOS5_PHY_HSIC_CTRL2);

	udelay(80);

	/* enable EHCI DMA burst */
	ehcictrl = readl(regs + EXYNOS5_PHY_HOST_EHCICTRL);
	ehcictrl |= (HOST_EHCICTRL_ENAINCRXALIGN |
				HOST_EHCICTRL_ENAINCR4 |
				HOST_EHCICTRL_ENAINCR8 |
				HOST_EHCICTRL_ENAINCR16);
	writel(ehcictrl, regs + EXYNOS5_PHY_HOST_EHCICTRL);

	/* set ohci_suspend_on_n */
	ohcictrl = readl(regs + EXYNOS5_PHY_HOST_OHCICTRL);
	ohcictrl |= HOST_OHCICTRL_SUSPLGCY;
	writel(ohcictrl, regs + EXYNOS5_PHY_HOST_OHCICTRL);
}

static void samsung_exynos5_usbphy3_disable(struct samsung_usbphy *sphy)
{
	u32 phyutmi;
	u32 phyclkrst;
	u32 phytest;
	void __iomem *regs = sphy->regs_phy3;

	phyutmi = PHYUTMI_OTGDISABLE |
			PHYUTMI_FORCESUSPEND |
			PHYUTMI_FORCESLEEP;
	writel(phyutmi, regs + EXYNOS5_DRD_PHYUTMI);

	/* Resetting the PHYCLKRST enable bits to reduce leakage current */
	phyclkrst = readl(regs + EXYNOS5_DRD_PHYCLKRST);
	phyclkrst &= ~(PHYCLKRST_REF_SSP_EN |
			PHYCLKRST_SSC_EN |
			PHYCLKRST_COMMONONN);
	writel(phyclkrst, regs + EXYNOS5_DRD_PHYCLKRST);

	/* Control PHYTEST to remove leakage current */
	phytest = readl(regs + EXYNOS5_DRD_PHYTEST);
	phytest |= (PHYTEST_POWERDOWN_SSP |
			PHYTEST_POWERDOWN_HSP);
	writel(phytest, regs + EXYNOS5_DRD_PHYTEST);
}

static void samsung_exynos5_usbphy_disable(struct samsung_usbphy *sphy)
{
	void __iomem *regs = sphy->regs;
	u32 phyhost;
	u32 phyotg;
	u32 phyhsic;

	if (atomic_dec_return(&sphy->host_usage) > 0) {
		dev_info(sphy->dev, "still being used\n");
		return;
	}

	phyhsic = (HSIC_CTRL_REFCLKDIV_12 |
			HSIC_CTRL_REFCLKSEL |
			HSIC_CTRL_SIDDQ |
			HSIC_CTRL_FORCESLEEP |
			HSIC_CTRL_FORCESUSPEND);
	writel(phyhsic, regs + EXYNOS5_PHY_HSIC_CTRL1);
	writel(phyhsic, regs + EXYNOS5_PHY_HSIC_CTRL2);

	phyhost = readl(regs + EXYNOS5_PHY_HOST_CTRL0);
	phyhost |= (HOST_CTRL0_SIDDQ |
			HOST_CTRL0_FORCESUSPEND |
			HOST_CTRL0_FORCESLEEP |
			HOST_CTRL0_PHYSWRST |
			HOST_CTRL0_PHYSWRSTALL);
	writel(phyhost, regs + EXYNOS5_PHY_HOST_CTRL0);

	phyotg = readl(regs + EXYNOS5_PHY_OTG_SYS);
	phyotg |= (OTG_SYS_FORCESUSPEND |
			OTG_SYS_SIDDQ_UOTG |
			OTG_SYS_FORCESLEEP);
	writel(phyotg, regs + EXYNOS5_PHY_OTG_SYS);
}

static int samsung_usbphy3_init(struct usb_phy *phy3)
{
	struct samsung_usbphy *sphy;
	int ret = 0;

	sphy = phy3_to_sphy(phy3);

	if (sphy->cpu_type != TYPE_EXYNOS5250) {
		dev_err(sphy->dev, "Not a valid cpu_type for USB 3.0\n");
		return -ENODEV;
	}
	/* setting default phy-type for USB 3.0 */
	samsung_usbphy_set_type(&sphy->phy3, USB_PHY_TYPE_DRD);

	/* Enable the phy clock */
	ret = clk_prepare_enable(sphy->clk);
	if (ret) {
		dev_err(sphy->dev, "%s: clk_prepare_enable failed\n", __func__);
		return ret;
	}

	/* Disable phy isolation */
	if (sphy->plat && sphy->plat->pmu_isolation)
		sphy->plat->pmu_isolation(false, sphy->phy_type);

	/* Initialize usb phy registers */
	samsung_exynos5_usbphy3_enable(sphy);

	/* Disable the phy clock */
	clk_disable_unprepare(sphy->clk);

	return ret;
}

/*
 * The function passed to the usb driver for phy shutdown
 */
static void samsung_usbphy3_shutdown(struct usb_phy *phy3)
{
	struct samsung_usbphy *sphy;

	sphy = phy3_to_sphy(phy3);

	if (sphy->cpu_type != TYPE_EXYNOS5250) {
		dev_err(sphy->dev, "Not a valid cpu_type for USB 3.0\n");
		return;
	}

	/* setting default phy-type for USB 3.0 */
	samsung_usbphy_set_type(&sphy->phy3, USB_PHY_TYPE_DRD);

	if (clk_prepare_enable(sphy->clk)) {
		dev_err(sphy->dev, "%s: clk_prepare_enable failed\n", __func__);
		return;
	}

	/* De-initialize usb phy registers */
	samsung_exynos5_usbphy3_disable(sphy);

	/* Enable phy isolation */
	if (sphy->plat && sphy->plat->pmu_isolation)
		sphy->plat->pmu_isolation(true, sphy->phy_type);

	clk_disable_unprepare(sphy->clk);
}

static void samsung_usbphy_enable(struct samsung_usbphy *sphy)
{
	void __iomem *regs = sphy->regs;
	u32 phypwr;
	u32 phyclk;
	u32 rstcon;

	/* set clock frequency for PLL */
	phyclk = sphy->ref_clk_freq;
	phypwr = readl(regs + SAMSUNG_PHYPWR);
	rstcon = readl(regs + SAMSUNG_RSTCON);

	switch (sphy->cpu_type) {
	case TYPE_S3C64XX:
		phyclk &= ~PHYCLK_COMMON_ON_N;
		phypwr &= ~PHYPWR_NORMAL_MASK;
		rstcon |= RSTCON_SWRST;
		break;
	case TYPE_EXYNOS4210:
		phypwr &= ~PHYPWR_NORMAL_MASK_PHY0;
		rstcon |= RSTCON_SWRST;
	default:
		break;
	}

	writel(phyclk, regs + SAMSUNG_PHYCLK);
	/* set to normal of PHY0 */
	writel(phypwr, regs + SAMSUNG_PHYPWR);
	/* reset all ports of PHY and Link */
	writel(rstcon, regs + SAMSUNG_RSTCON);
	udelay(10);
	rstcon &= ~RSTCON_SWRST;
	writel(rstcon, regs + SAMSUNG_RSTCON);
}

static void samsung_usbphy_disable(struct samsung_usbphy *sphy)
{
	void __iomem *regs = sphy->regs;
	u32 phypwr;

	phypwr = readl(regs + SAMSUNG_PHYPWR);

	switch (sphy->cpu_type) {
	case TYPE_S3C64XX:
		phypwr |= PHYPWR_NORMAL_MASK;
		break;
	case TYPE_EXYNOS4210:
		phypwr |= PHYPWR_NORMAL_MASK_PHY0;
	default:
		break;
	}

	/* unset to normal of PHY0 */
	writel(phypwr, regs + SAMSUNG_PHYPWR);
}

/*
 * The function passed to the usb driver for phy initialization
 */
static int samsung_usbphy_init(struct usb_phy *phy)
{
	struct samsung_usbphy *sphy;
	int ret = 0;

	sphy = phy_to_sphy(phy);

	/* Enable the phy clock */
	ret = clk_prepare_enable(sphy->clk);
	if (ret) {
		dev_err(sphy->dev, "%s: clk_prepare_enable failed\n", __func__);
		return ret;
	}

	/* Disable phy isolation */
	if (sphy->plat && sphy->plat->pmu_isolation)
		sphy->plat->pmu_isolation(false, sphy->phy_type);

	/* Initialize usb phy registers */
	if (sphy->cpu_type == TYPE_EXYNOS5250)
		samsung_exynos5_usbphy_enable(sphy);
	else
		samsung_usbphy_enable(sphy);
	/* Disable the phy clock */
	clk_disable_unprepare(sphy->clk);
	return ret;
}

/*
+ * The function passed to the usb driver for phy shutdown
+ */
static void samsung_usbphy_shutdown(struct usb_phy *phy)
{
	struct samsung_usbphy *sphy;

	sphy = phy_to_sphy(phy);

	if (clk_prepare_enable(sphy->clk)) {
		dev_err(sphy->dev, "%s: clk_prepare_enable failed\n", __func__);
		return;
	}

	/* De-initialize usb phy registers */
	if (sphy->cpu_type == TYPE_EXYNOS5250)
		samsung_exynos5_usbphy_disable(sphy);
	else
		samsung_usbphy_disable(sphy);

	/* Enable phy isolation */
	if (sphy->plat && sphy->plat->pmu_isolation)
		sphy->plat->pmu_isolation(true, sphy->phy_type);

	clk_disable_unprepare(sphy->clk);
}

static const struct of_device_id samsung_usbphy_dt_match[];

static inline int samsung_usbphy_get_driver_data(struct platform_device *pdev)
{
	if (IS_ENABLED(CONFIG_OF) && pdev->dev.of_node) {
		int data;
		const struct of_device_id *match;
		match = of_match_node(samsung_usbphy_dt_match,
							pdev->dev.of_node);
		data = (int) match->data;
		return data;
	}

	return platform_get_device_id(pdev)->driver_data;
}

static int samsung_usbphy_probe(struct platform_device *pdev)
{
	struct samsung_usbphy *sphy;
	struct samsung_usbphy_data *pdata;
	struct device *dev = &pdev->dev;
	struct resource *phy_mem;
	void __iomem	*phy_base;
	struct resource *phy3_mem;
	void __iomem	*phy3_base = NULL;
	struct clk *clk;
	int	ret = 0;

	pdata = pdev->dev.platform_data;
	if (!pdata) {
		dev_err(&pdev->dev, "%s: no platform data defined\n", __func__);
		return -EINVAL;
	}
	phy_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!phy_mem) {
		dev_err(dev, "%s: missing mem resource\n", __func__);
		return -ENODEV;
	}

	phy_base = devm_request_and_ioremap(dev, phy_mem);
	if (!phy_base) {
		dev_err(dev, "%s: register mapping failed\n", __func__);
		return -ENXIO;
	}

	sphy = devm_kzalloc(dev, sizeof(*sphy), GFP_KERNEL);
	if (!sphy)
		return -ENOMEM;

	sphy->dev		= &pdev->dev;
	sphy->plat		= pdata;
	sphy->regs		= phy_base;
	sphy->phy.dev		= sphy->dev;
	sphy->phy.label		= "samsung-usbphy";
	sphy->phy.init		= samsung_usbphy_init;
	sphy->phy.shutdown	= samsung_usbphy_shutdown;
	sphy->cpu_type		= samsung_usbphy_get_driver_data(pdev);
	sphy->ref_clk_freq	= samsung_usbphy_get_refclk_freq(sphy);
	platform_set_drvdata(pdev, sphy);

	if (sphy->cpu_type == TYPE_EXYNOS5250)
		clk = devm_clk_get(dev, "usbhost");
	else
		clk = devm_clk_get(dev, "otg");
	if (IS_ERR(clk)) {
		dev_err(dev, "Failed to get otg clock\n");
		return PTR_ERR(clk);
	}

	sphy->clk = clk;

	if (sphy->cpu_type == TYPE_EXYNOS5250) {
		phy3_mem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
		if (!phy3_mem) {
			dev_err(dev, "%s: missing mem resource\n", __func__);
			return -ENODEV;
		}
		phy3_base = devm_request_and_ioremap(dev, phy3_mem);
		if (!phy3_base) {
			dev_err(dev, "%s: register mapping failed\n", __func__);
			return -ENXIO;
		}
	}

	sphy->regs_phy3		= phy3_base;
	sphy->phy3.dev		= sphy->dev;
	sphy->phy3.label	= "samsung-usbphy3";
	sphy->phy3.init		= samsung_usbphy3_init;
	sphy->phy3.shutdown	= samsung_usbphy3_shutdown;

	ret = usb_add_phy(&sphy->phy, USB_PHY_TYPE_USB2);

	if (ret)
		return ret;

	if (sphy->cpu_type != TYPE_EXYNOS5250) {
		dev_warn(dev, "Not a valid cpu_type for USB 3.0\n");
	} else {
		ret = usb_add_phy(&sphy->phy3, USB_PHY_TYPE_USB3);
		if (ret)
			return ret;
	}
	return ret;
}

static int __exit samsung_usbphy_remove(struct platform_device *pdev)
{
	struct samsung_usbphy *sphy = platform_get_drvdata(pdev);

	usb_remove_phy(&sphy->phy);
	if (sphy->cpu_type == TYPE_EXYNOS5250)
		usb_remove_phy(&sphy->phy3);
	return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id samsung_usbphy_dt_match[] = {
	{
		.compatible = "samsung,s3c64xx-usbphy",
		.data = (void *)TYPE_S3C64XX,
	}, {
		.compatible = "samsung,exynos4210-usbphy",
		.data = (void *)TYPE_EXYNOS4210,
	},{
		.compatible = "samsung,exynos5250-usbphy",
		.data = (void *)TYPE_EXYNOS5250,
	},
	{},
};
MODULE_DEVICE_TABLE(of, samsung_usbphy_dt_match);
#else
#define samsung_usbphy_dt_match NULL
#endif

static struct platform_device_id samsung_usbphy_driver_ids[] = {
	{
		.name		= "s3c64xx-usbphy",
		.driver_data	= TYPE_S3C64XX,
	}, {
		.name		= "exynos4210-usbphy",
		.driver_data	= TYPE_EXYNOS4210,
	},
	{},
};

MODULE_DEVICE_TABLE(platform, samsung_usbphy_driver_ids);

static struct platform_driver samsung_usbphy_driver = {
	.probe		= samsung_usbphy_probe,
	.remove		= samsung_usbphy_remove,
	.id_table	= samsung_usbphy_driver_ids,
	.driver		= {
		//.name	= "samsung-usbphy",
		.name	= "exynos5250-usbphy",
		.owner	= THIS_MODULE,
		.of_match_table = samsung_usbphy_dt_match,
	},
};

module_platform_driver(samsung_usbphy_driver);

MODULE_DESCRIPTION("Samsung USB phy controller");
MODULE_AUTHOR("Praveen Paneri <p.paneri@samsung.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:samsung-usbphy");

#include <linux/module.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/ahci_platform.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>

#include <plat/cpu.h>

#include <mach/irqs.h>
#include <mach/map.h>
#include <mach/regs-pmu.h>
#include <mach/regs-sata.h>

#include "sata_phy.h"

struct i2c_client *i2c_client;

static struct i2c_driver sataphy_i2c_driver;

struct exynos_sata_phy {
	void __iomem *mmio;
	struct resource *mem;
	struct clk *clk;
};

static u32 time_limit_cnt;

static bool sata_is_reg(void __iomem *base, u32 reg, u32 checkbit, u32 Status)
{
	if ((readl(base + reg) & checkbit) == Status)
		return true;
	else
		return false;
}

static bool wait_for_reg_status(void __iomem *base, u32 reg, u32 checkbit,
		u32 Status)
{
	time_limit_cnt = 0;
	while (!sata_is_reg(base, reg, checkbit, Status)) {
		if (time_limit_cnt == SATA_TIME_LIMIT) {
			return false;
		}
		udelay(1000);
		time_limit_cnt++;
	}
	return true;
}

int sataphy_init(struct sata_phy *phy)
{	int i =100;
	int ret;
	u32 val;
	u8 buf[] = {0x3A, 0x0B};  /* Values to be written to enable 40 bits interface */

	u8 buff[100];

	struct exynos_sata_phy *sata_phy ;

	sata_phy = (struct exynos_sata_phy *)phy->priv_data;

	clk_enable(sata_phy->clk);

	writel(S5P_PMU_SATA_PHY_CONTROL_EN, EXYNOS5_SATA_PHY_CONTROL);

        val = 0;
        writel(val, sata_phy->mmio + SATA_RESET);
  
	val = readl(sata_phy->mmio + SATA_RESET);
        val |= 0xFF;
        writel(val, sata_phy->mmio + SATA_RESET);


        val = readl(sata_phy->mmio + SATA_RESET);
        val |= LINK_RESET;
        writel(val, sata_phy->mmio + SATA_RESET);

        val = readl(sata_phy->mmio + SATA_RESET);
        val |= RESET_CMN_RST_N;
        writel(val, sata_phy->mmio + SATA_RESET);

        val = readl(sata_phy->mmio + SATA_PHSATA_CTRLM);
        val &= ~PHCTRLM_REF_RATE;
        writel(val, sata_phy->mmio + SATA_PHSATA_CTRLM);

        /* High speed enable for Gen3 */
        val = readl(sata_phy->mmio + SATA_PHSATA_CTRLM);
        val |= PHCTRLM_HIGH_SPEED;
        writel(val, sata_phy->mmio + SATA_PHSATA_CTRLM);

        val = readl(sata_phy->mmio + SATA_CTRL0);
        val |= CTRL0_P0_PHY_CALIBRATED_SEL|CTRL0_P0_PHY_CALIBRATED;
        writel(val, sata_phy->mmio + SATA_CTRL0);
        
	writel(SATA_PHY_GENERATION3, sata_phy->mmio + SATA_MODE0);
	
	ret = i2c_master_send(i2c_client, buf , sizeof buf);	

	/* release cmu reset */
        val = readl(sata_phy->mmio + SATA_RESET);
        val &= ~RESET_CMN_RST_N;
        writel(val, sata_phy->mmio + SATA_RESET);

        val = readl(sata_phy->mmio + SATA_RESET);
        val |= RESET_CMN_RST_N;
        writel(val, sata_phy->mmio+ SATA_RESET);
	
        if (wait_for_reg_status(sata_phy->mmio , SATA_PHSATA_STATM,
                                PHSTATM_PLL_LOCKED, 1)){
                return 0;
	}
	return -1;
}

int sataphy_shutdown(struct sata_phy *phy)
{

	struct exynos_sata_phy *sata_phy ;

        sata_phy = (struct exynos_sata_phy *)phy->priv_data;

        clk_disable(sata_phy->clk);

	return 0;
}


static int __init sata_i2c_probe(struct i2c_client *client,
                         const struct i2c_device_id *i2c_id)
{
	i2c_client = client ;		
	return 0;
}

static int __init sata_phy_probe(struct platform_device *pdev)
{
	struct exynos_sata_phy *sataphy;
	struct clk *clk_sata_i2c;
	struct sata_phy *phy;
	int ret = 0;

	phy = kzalloc(sizeof(struct sata_phy), GFP_KERNEL);
	if (!phy) {
                dev_err(&pdev->dev, "failed to allocate memory\n");
                ret = -ENOMEM;
		goto out;
        }

	sataphy = kzalloc(sizeof(struct exynos_sata_phy), GFP_KERNEL);
        if (!sataphy){
                dev_err(&pdev->dev, "failed to allocate memory\n");
                ret = -ENOMEM;
		goto err;
        }

	sataphy->mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
        if (!sataphy->mem) {
                dev_err(&pdev->dev, "no mmio space\n");
                ret = -EINVAL;
		goto err0;
        }

	sataphy->mmio = ioremap( sataphy->mem->start, resource_size(sataphy->mem));

        if (!sataphy->mmio) {
                dev_err(&pdev->dev, "failed to allocate memory for SATA PHY CTRL\n");
                ret = -ENOMEM;
		goto err1;
        }

	sataphy->clk = clk_get(&pdev->dev, "sata_phy");
	if (IS_ERR(sataphy->clk)) {
                dev_err(&pdev->dev, "failed to get clk_i2c\n");
                ret = PTR_ERR(sataphy->clk);
                sataphy->clk = NULL;
		goto err2;
        }

	phy->init = sataphy_init;
	phy->shutdown = sataphy_shutdown;
	phy->priv_data = (void *)sataphy;
	phy->dev = &pdev->dev;

	sata_add_phy(phy, SATA_PHY_GENERATION3);

	i2c_add_driver(&sataphy_i2c_driver);

	platform_set_drvdata(pdev, phy);

	return ret; 

err2:
	iounmap(sataphy->mmio);	

err1:
	release_resource(sataphy->mem);	

err0:
	kfree(sataphy);

err:
	kfree(phy);

out :
	return ret;
}

static int sata_phy_remove(struct platform_device *pdev)
{
	struct sata_phy *phy;
	struct exynos_sata_phy *sataphy;

	phy = platform_get_drvdata(pdev);	
	
	sataphy = (struct exynos_sata_phy *)phy->priv_data;	
	sata_remove_phy(phy);

	iounmap(sataphy->mmio);
	release_resource(sataphy->mem);
	kfree(sataphy);
	
	return 0;
}


static const struct of_device_id sata_phy_of_match[] = {
        { .compatible = "samsung,exynos-sata-phy", },
        { .compatible = "samsung,i2c-phy", },
        {},
};
MODULE_DEVICE_TABLE(of, sata_phy_of_match);

static const struct i2c_device_id phy_i2c_device_match[] = {
        { "sataphy", 0 },
        {},
};

MODULE_DEVICE_TABLE(of, phy_i2c_device_match);

static struct platform_driver sata_phy_driver = {
        .probe  = sata_phy_probe,
	.remove = sata_phy_remove,
        .driver = {
                .name = "sata-phy",
                .owner = THIS_MODULE,
                .of_match_table = sata_phy_of_match,
        },
};

static struct i2c_driver sataphy_i2c_driver = {
        .driver = {
                .name   = "i2c-phy",
		.owner  = THIS_MODULE,
		.of_match_table = sata_phy_of_match,
        },
        .probe          = sata_i2c_probe,
	.id_table       = phy_i2c_device_match,
};


module_platform_driver(sata_phy_driver);

/*
 * Simple lcd panel power control driver.
 *
 * Copyright (c) 2011-2012 Samsung Electronics Co., Ltd.
 * Copyright (c) 2011-2012 Linaro Ltd.
 *
 * This driver is for controlling power for raster type lcd panels that requires
 * its nRESET interface line to be connected and controlled by a GPIO of the
 * host system and the Vcc line controlled by a voltage regulator.  This
 * excludes support for lcd panels that use a serial command interface or direct
 * memory mapped IO interface.
 *
 * The nRESET interface line of the panel should be connected to a gpio of the
 * host system. The Vcc pin is controlled using a external volatage regulator.
 * Panel backlight is not controlled by this driver.
 *
 * This driver is derived from platform-lcd.c which was written by
 * Ben Dooks <ben@simtec.co.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
*/

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/fb.h>
#include <linux/lcd.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/regulator/consumer.h>
#include <video/lcd_pwrctrl.h>

struct lcd_pwrctrl {
	struct device		*dev;
	struct lcd_device	*lcd;
	struct lcd_pwrctrl_data	*pdata;
	struct regulator	*regulator;
	unsigned int		power;
	bool			suspended;
	bool			pwr_en;
};

static int lcd_pwrctrl_get_power(struct lcd_device *lcd)
{
	struct lcd_pwrctrl *lp = lcd_get_data(lcd);
	return lp->power;
}

static int lcd_pwrctrl_set_power(struct lcd_device *lcd, int power)
{
	struct lcd_pwrctrl *lp = lcd_get_data(lcd);
	struct lcd_pwrctrl_data *pd = lp->pdata;
	bool lcd_enable;
	int lcd_reset, ret = 0;

	lcd_enable = (power == FB_BLANK_POWERDOWN || lp->suspended) ? 0 : 1;
	lcd_reset = (pd->invert) ? !lcd_enable : lcd_enable;

	if (lp->pwr_en == lcd_enable)
		return 0;

	if (!IS_ERR_OR_NULL(lp->regulator)) {
		if (lcd_enable) {
			if (regulator_enable(lp->regulator)) {
				dev_info(lp->dev, "regulator enable failed\n");
				ret = -EPERM;
			}
		} else {
			if (regulator_disable(lp->regulator)) {
				dev_info(lp->dev, "regulator disable failed\n");
				ret = -EPERM;
			}
		}
	}

	gpio_direction_output(lp->pdata->gpio, lcd_reset);
	lp->power = power;
	lp->pwr_en = lcd_enable;
	return ret;
}

static int lcd_pwrctrl_check_fb(struct lcd_device *lcd, struct fb_info *info)
{
	struct lcd_pwrctrl *lp = lcd_get_data(lcd);
	return lp->dev->parent == info->device;
}

static struct lcd_ops lcd_pwrctrl_ops = {
	.get_power	= lcd_pwrctrl_get_power,
	.set_power	= lcd_pwrctrl_set_power,
	.check_fb	= lcd_pwrctrl_check_fb,
};

#ifdef CONFIG_OF
static void lcd_pwrctrl_parse_dt(struct device *dev,
					struct lcd_pwrctrl_data *pdata)
{
	struct device_node *np = dev->of_node;

	pdata->gpio = of_get_named_gpio(np, "lcd-reset-gpio", 0);
	if (of_get_property(np, "lcd-reset-active-high", NULL))
		pdata->invert = true;
}
#endif

static int lcd_pwrctrl_probe(struct platform_device *pdev)
{
	struct lcd_pwrctrl *lp;
	struct lcd_pwrctrl_data *pdata = pdev->dev.platform_data;
	struct device *dev = &pdev->dev;
	int err;

#ifdef CONFIG_OF
	if (dev->of_node) {
		pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
		if (!pdata) {
			dev_err(dev, "memory allocation for pdata failed\n");
			return -ENOMEM;
		}
		lcd_pwrctrl_parse_dt(dev, pdata);
	}
#endif

	if (!pdata) {
		dev_err(dev, "platform data not available\n");
		return -EINVAL;
	}

	lp = devm_kzalloc(dev, sizeof(struct lcd_pwrctrl), GFP_KERNEL);
	if (!lp) {
		dev_err(dev, "memory allocation failed for private data\n");
		return -ENOMEM;
	}

	err = gpio_request(pdata->gpio, "LCD-nRESET");
	if (err) {
		dev_err(dev, "gpio [%d] request failed\n", pdata->gpio);
		return err;
	}

	/*
	 * If power to lcd and/or lcd interface is controlled using a regulator,
	 * get the handle to the regulator for later use during power switching.
	 */
	lp->regulator = devm_regulator_get(dev, "vcc-lcd");
	if (IS_ERR(lp->regulator))
		dev_info(dev, "could not find regulator\n");

	lp->dev = dev;
	lp->pdata = pdata;
	lp->lcd = lcd_device_register(dev_name(dev), dev, lp, &lcd_pwrctrl_ops);
	if (IS_ERR(lp->lcd)) {
		dev_err(dev, "cannot register lcd device\n");
		gpio_free(pdata->gpio);
		return PTR_ERR(lp->lcd);
	}

	platform_set_drvdata(pdev, lp);
	lcd_pwrctrl_set_power(lp->lcd, FB_BLANK_NORMAL);
	return 0;
}

static int lcd_pwrctrl_remove(struct platform_device *pdev)
{
	struct lcd_pwrctrl *lp = platform_get_drvdata(pdev);
	lcd_device_unregister(lp->lcd);
	gpio_free(lp->pdata->gpio);
	return 0;
}

#ifdef CONFIG_PM
static int lcd_pwrctrl_suspend(struct device *dev)
{
	struct lcd_pwrctrl *lp = dev_get_drvdata(dev);

	lp->suspended = true;
	lcd_pwrctrl_set_power(lp->lcd, FB_BLANK_POWERDOWN);
	return 0;
}

static int lcd_pwrctrl_resume(struct device *dev)
{
	struct lcd_pwrctrl *lp = dev_get_drvdata(dev);

	lp->suspended = false;
	lcd_pwrctrl_set_power(lp->lcd, FB_BLANK_UNBLANK);
	return 0;
}

static const struct dev_pm_ops lcd_pwrctrl_dev_pm_ops = {
	.suspend	= lcd_pwrctrl_suspend,
	.resume		= lcd_pwrctrl_resume,
};

#define LCD_PWRCTRL_DEV_PM_OPS	(&lcd_pwrctrl_dev_pm_ops)
#else
#define LCD_PWRCTRL_DEV_PM_OPS	NULL
#endif /* CONFIG_PM */

#ifdef CONFIG_OF
static const struct of_device_id lcd_pwrctrl_match[] = {
	{ .compatible = "lcd-powercontrol", },
	{},
};
MODULE_DEVICE_TABLE(of, lcd_pwrctrl_match);
#endif

static struct platform_driver lcd_pwrctrl_driver = {
	.driver		= {
		.name	= "lcd-pwrctrl",
		.owner	= THIS_MODULE,
		.pm	= LCD_PWRCTRL_DEV_PM_OPS,
		.of_match_table	= of_match_ptr(lcd_pwrctrl_match),
	},
	.probe		= lcd_pwrctrl_probe,
	.remove		= lcd_pwrctrl_remove,
};

module_platform_driver(lcd_pwrctrl_driver);

MODULE_AUTHOR("Thomas Abraham <thomas.ab@samsung.com>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:lcd-pwrctrl");

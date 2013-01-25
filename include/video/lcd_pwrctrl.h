/*
 * Simple lcd panel power control driver.
 *
 * Copyright (c) 2011-2012 Samsung Electronics Co., Ltd.
 * Copyright (c) 2011-2012 Linaro Ltd.
 *
 * This driver is derived from platform-lcd.h which was written by
 * Ben Dooks <ben@simtec.co.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
*/

/**
 * struct lcd_pwrctrl_data - platform data for lcd_pwrctrl driver.
 * @gpio: GPIO number of the host system that connects to nRESET line.
 * @invert: True, if output of gpio connected to nRESET should be inverted.
 */
struct lcd_pwrctrl_data {
	int		gpio;
	bool		invert;
};

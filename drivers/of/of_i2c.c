/*
 * OF helpers for the I2C API
 *
 * Copyright (c) 2008 Jochen Friedrich <jochen@scram.de>
 *
 * Based on a previous patch from Jon Smirl <jonsmirl@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/i2c.h>
#include <linux/of.h>
#include <linux/of_i2c.h>
#include <linux/module.h>

void of_register_i2c_devices(struct i2c_adapter *adap,
			     struct device_node *adap_node)
{
	void *result;
	struct device_node *node;

	for_each_child_of_node(adap_node, node) {
		struct i2c_board_info info = {};
		struct dev_archdata dev_ad = {};
		const __be32 *addr;
		int len;

		if (of_modalias_node(node, info.type, sizeof(info.type)) < 0)
			continue;

		addr = of_get_property(node, "reg", &len);
		if (!addr || len < sizeof(int) || *addr > (1 << 10) - 1) {
			printk(KERN_ERR
			       "of-i2c: invalid i2c device entry\n");
			continue;
		}

		info.irq = irq_of_parse_and_map(node, 0);

		info.addr = be32_to_cpup(addr);

		info.of_node = node;
		info.archdata = &dev_ad;

		request_module("%s", info.type);

		result = i2c_new_device(adap, &info);
		if (result == NULL) {
			printk(KERN_ERR
			       "of-i2c: Failed to load driver for %s\n",
			       info.type);
			irq_dispose_mapping(info.irq);
			continue;
		}

		/*
		 * Get the node to not lose the dev_archdata->of_node.
		 * Currently there is no way to put it back, as well as no
		 * of_unregister_i2c_devices() call.
		 */
		of_node_get(node);
	}
}
EXPORT_SYMBOL(of_register_i2c_devices);

static int of_dev_node_match(struct device *dev, void *data)
{
        return dev->of_node == data;
}

/* must call put_device() when done with returned i2c_client device */
struct i2c_client *of_find_i2c_device_by_node(struct device_node *node)
{
	struct device *dev;

	dev = bus_find_device(&i2c_bus_type, NULL, node,
					 of_dev_node_match);
	if (!dev)
		return NULL;

	return to_i2c_client(dev);
}
EXPORT_SYMBOL(of_find_i2c_device_by_node);

MODULE_LICENSE("GPL");

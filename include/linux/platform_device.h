/*
 * platform_device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 *
 * This file is released under the GPLv2
 *
 * See Documentation/driver-model/ for more information.
 */

#ifndef _PLATFORM_DEVICE_H_
#define _PLATFORM_DEVICE_H_

#include <linux/device.h>
#include <linux/mod_devicetable.h>

struct platform_device {
	const char	* name;
	int		id;
	struct device	dev;
	u32		num_resources;
	struct resource	* resource;

	const struct platform_device_id	*id_entry;

	/* arch specific additions */
	struct pdev_archdata	archdata;
};

#define platform_get_device_id(pdev)	((pdev)->id_entry)

#define to_platform_device(x) container_of((x), struct platform_device, dev)

extern int platform_device_register(struct platform_device *);
extern void platform_device_unregister(struct platform_device *);

extern struct bus_type platform_bus_type;
extern struct device platform_bus;

extern struct resource *platform_get_resource(struct platform_device *, unsigned int, unsigned int);
extern int platform_get_irq(struct platform_device *, unsigned int);
extern struct resource *platform_get_resource_byname(struct platform_device *, unsigned int, const char *);
extern int platform_get_irq_byname(struct platform_device *, const char *);
extern int platform_add_devices(struct platform_device **, int);

extern struct platform_device *platform_device_register_simple(const char *, int id,
					const struct resource *, unsigned int);
extern struct platform_device *platform_device_register_data(struct device *,
		const char *, int, const void *, size_t);

extern struct platform_device *platform_device_alloc(const char *name, int id);
extern int platform_device_add_resources(struct platform_device *pdev,
					 const struct resource *res,
					 unsigned int num);
extern int platform_device_add_data(struct platform_device *pdev, const void *data, size_t size);
extern int platform_device_add(struct platform_device *pdev);
extern void platform_device_del(struct platform_device *pdev);
extern void platform_device_put(struct platform_device *pdev);

struct platform_driver {
	int (*probe)(struct platform_device *);
	int (*remove)(struct platform_device *);
	void (*shutdown)(struct platform_device *);
	int (*suspend)(struct platform_device *, pm_message_t state);
	int (*resume)(struct platform_device *);
	struct device_driver driver;
	const struct platform_device_id *id_table;
};

extern int platform_driver_register(struct platform_driver *);
extern void platform_driver_unregister(struct platform_driver *);

/* non-hotpluggable platform devices may use this so that probe() and
 * its support may live in __init sections, conserving runtime memory.
 */
extern int platform_driver_probe(struct platform_driver *driver,
		int (*probe)(struct platform_device *));

#define platform_get_drvdata(_dev)	dev_get_drvdata(&(_dev)->dev)
#define platform_set_drvdata(_dev,data)	dev_set_drvdata(&(_dev)->dev, (data))

extern struct platform_device *platform_create_bundle(struct platform_driver *driver,
					int (*probe)(struct platform_device *),
					struct resource *res, unsigned int n_res,
					const void *data, size_t size);

/* early platform driver interface */
struct early_platform_driver {
	const char *class_str;
	struct platform_driver *pdrv;
	struct list_head list;
	int requested_id;
	char *buffer;
	int bufsize;
};

#define EARLY_PLATFORM_ID_UNSET -2
#define EARLY_PLATFORM_ID_ERROR -3

extern int early_platform_driver_register(struct early_platform_driver *epdrv,
					  char *buf);
extern void early_platform_add_devices(struct platform_device **devs, int num);

static inline int is_early_platform_device(struct platform_device *pdev)
{
	return !pdev->dev.driver;
}

extern void early_platform_driver_register_all(char *class_str);
extern int early_platform_driver_probe(char *class_str,
				       int nr_probe, int user_only);
extern void early_platform_cleanup(void);

#define early_platform_init(class_string, platdrv)		\
	early_platform_init_buffer(class_string, platdrv, NULL, 0)

#ifndef MODULE
#define early_platform_init_buffer(class_string, platdrv, buf, bufsiz)	\
static __initdata struct early_platform_driver early_driver = {		\
	.class_str = class_string,					\
	.buffer = buf,							\
	.bufsize = bufsiz,						\
	.pdrv = platdrv,						\
	.requested_id = EARLY_PLATFORM_ID_UNSET,			\
};									\
static int __init early_platform_driver_setup_func(char *buffer)	\
{									\
	return early_platform_driver_register(&early_driver, buffer);	\
}									\
early_param(class_string, early_platform_driver_setup_func)
#else /* MODULE */
#define early_platform_init_buffer(class_string, platdrv, buf, bufsiz)	\
static inline char *early_platform_driver_setup_func(void)		\
{									\
	return bufsiz ? buf : NULL;					\
}
#endif /* MODULE */

#endif /* _PLATFORM_DEVICE_H_ */

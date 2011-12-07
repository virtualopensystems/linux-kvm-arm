#include <linux/module.h>
#include <linux/err.h>
#include <linux/ath6kl.h>

static const struct ath6kl_platform_data *platform_data;

int __init ath6kl_set_platform_data(const struct ath6kl_platform_data *data)
{
	if (platform_data)
		return -EBUSY;
	if (!data)
		return -EINVAL;

	platform_data = kmemdup(data, sizeof(*data), GFP_KERNEL);
	if (!platform_data)
		return -ENOMEM;
	return 0;
}

const struct ath6kl_platform_data *ath6kl_get_platform_data(void)
{
	if (!platform_data)
		return ERR_PTR(-ENODEV);
	return platform_data;
}
EXPORT_SYMBOL(ath6kl_get_platform_data);

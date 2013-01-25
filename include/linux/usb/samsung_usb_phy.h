/*
 *copyright (C) 2012 Samsung Electronics Co.Ltd
 *		http://www.samsung.com/
 *
 * Defines phy types for samsung usb phy controllers - HOST or DEIVCE.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/usb/phy.h>
enum samsung_usb_phy_type
{
	USB_PHY_TYPE_DEVICE,
	USB_PHY_TYPE_HOST,
	USB_PHY_TYPE_DRD,
};

#ifdef CONFIG_SAMSUNG_USBPHY
extern int samsung_usbphy_set_type(struct usb_phy *phy,
				enum samsung_usb_phy_type phy_type);
#else
static inline int samsung_usbphy_set_type(struct usb_phy *phy,
				enum samsung_usb_phy_type phy_type)
{
	return 0;
}
#endif /* CONFIG_SAMSUNG_USBPHY */

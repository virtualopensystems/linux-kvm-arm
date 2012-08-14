#include <stdbool.h>
#include <string.h>
#include <linux/kvm.h>

#include "guest-driver.h"

/* We don't have any special mmio addresses for cp15 testing. */
GUEST_TEST(cp15, NULL);

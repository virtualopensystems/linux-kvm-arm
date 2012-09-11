#include <stdbool.h>
#include <string.h>
#include <linux/kvm.h>

#include "guest-driver.h"

/* Return false to stop the VM */
static bool cond_test(struct kvm_run *kvm_run, int vcpu_fd)
{
	return false;
}

GUEST_TEST(cond, cond_test);

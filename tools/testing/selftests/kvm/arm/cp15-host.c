#include <strings.h>
#include <stdbool.h>
#include <string.h>
#include <linux/kvm.h>
#include <err.h>
#include <assert.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "guest-driver.h"
#include "cp15_test.h"

#define MORE_THAN_ENOUGH 1000

/* Given a simple mask, get those bits. */
static inline u32 get_bits(u32 index, u32 mask)
{
	return (index & mask) >> (ffs(mask) - 1);
}

/* Puts in the position indicated by mask (assumes val fits in mask) */
static inline u32 set_bits(u32 val, u32 mask)
{
	return val << (ffs(mask)-1);
}

/* Exercise KVM_VCPU_GET_MSR_INDEX_LIST */
static void check_indexlist(int vcpu_fd)
{
	unsigned int i;
	bool found_ttbr0 = false, found_ttbr1 = false;
	struct {
		struct kvm_msr_list head;
		u32 indices[MORE_THAN_ENOUGH];
	} list;

	/* Attempt with too-short array should fail, with E2BIG, and not
	 * write outside the array bounds given. */
	list.head.nmsrs = 1;
	list.indices[1] = 0xdeadbeef;

	if (ioctl(vcpu_fd, KVM_VCPU_GET_MSR_INDEX_LIST, &list) != -1)
		errx(1, "KVM_VCPU_GET_MSR_INDEX_LIST(1) succeeded?");
	if (errno != E2BIG)
		err(1, "KVM_VCPU_GET_MSR_INDEX_LIST(1) failed with bad errno");
	assert(list.head.nmsrs > 1);
	assert(list.indices[1] == 0xdeadbeef);

	/* Now for real. */
	list.head.nmsrs = MORE_THAN_ENOUGH;
	if (ioctl(vcpu_fd, KVM_VCPU_GET_MSR_INDEX_LIST, &list) != 0)
		err(1, "KVM_VCPU_GET_MSR_INDEX_LIST");

	assert(list.head.nmsrs < MORE_THAN_ENOUGH);
	for (i = 0; i < list.head.nmsrs; i++) {
		u32 idx = list.indices[i];
		if (get_bits(idx, KVM_ARM_MSR_64_BIT_MASK) == 1
		    && get_bits(idx, KVM_ARM_MSR_64_CRM_MASK) == 2) {
			switch (get_bits(idx, KVM_ARM_MSR_64_OPC1_MASK)) {
			case 0:
				assert(!found_ttbr0);
				found_ttbr0 = true;
				break;
			case 1:
				assert(!found_ttbr1);
				found_ttbr1 = true;
				break;
			}
		}
	}
	assert(found_ttbr0);
	assert(found_ttbr1);
}

/* Return false to stop the VM */
static bool cp15_test(struct kvm_run *kvm_run, int vcpu_fd)
{
	static bool indexlist_checked = false;
	unsigned long phys_addr;
	bool is_write;
	unsigned char *data;
	unsigned long len;
	struct msrs {
		struct kvm_msrs head;
		struct kvm_msr_entry entries[2];
	} msrs;

	/* We check here that replacing a CP15 register works. */
	phys_addr = (unsigned long)kvm_run->mmio.phys_addr;
	is_write = kvm_run->mmio.is_write;
	data = kvm_run->mmio.data;
	len = kvm_run->mmio.len;

	if (len != 4)
		return false;

	/* Do this on first access. */
	if (!indexlist_checked) {
		check_indexlist(vcpu_fd);
		indexlist_checked = true;
	}

	/* TTBR0 */
	msrs.entries[0].index =
		set_bits(15, KVM_ARM_MSR_COPROC_MASK) |
		set_bits(1, KVM_ARM_MSR_64_BIT_MASK) |
		set_bits(2, KVM_ARM_MSR_64_CRM_MASK);
	/* TTBR1 */
	msrs.entries[1].index =
		set_bits(15, KVM_ARM_MSR_COPROC_MASK) |
		set_bits(1, KVM_ARM_MSR_64_BIT_MASK) |
		set_bits(2, KVM_ARM_MSR_64_CRM_MASK) |
		set_bits(1, KVM_ARM_MSR_64_OPC1_MASK);

	/* Zero out high bits of data. */
	msrs.entries[0].data = msrs.entries[1].data = 0;

	switch (phys_addr) {
	case CP15_TTBR0:
		msrs.head.nmsrs = 1;
		if (is_write) {
			memcpy(&msrs.entries[0].data, data, len);
			if (ioctl(vcpu_fd, KVM_SET_MSRS, &msrs) != 0)
				err(1, "KVM_SET_MSRS(TTBR0) failed");
		} else {
			if (ioctl(vcpu_fd, KVM_GET_MSRS, &msrs) != 0)
				err(1, "KVM_GET_MSRS(TTBR0) failed");
			memcpy(data, &msrs.entries[0].data, len);
		}
		return true;

	/* Test for API with n > 1 */
	case CP15_TTBR0_TTBR1:
		msrs.head.nmsrs = 2;
		if (is_write) {
			memcpy(&msrs.entries[0].data, data, len);
			memcpy(&msrs.entries[1].data, data, len);
			if (ioctl(vcpu_fd, KVM_SET_MSRS, &msrs) != 0)
				err(1, "KVM_SET_MSRS(TTBR0/1) failed");
		} else {
			if (ioctl(vcpu_fd, KVM_GET_MSRS, &msrs) != 0)
				err(1, "KVM_GET_MSRS(TTBR0/1) failed");
			/* Guest sets lower 32 bits to the same value. */
			if ((msrs.entries[0].data ^ msrs.entries[1].data)
			    & 0xFFFFFFFF) {
				errx(1, "TTBR0(0x%llx) != TTRB1(0x%llx)",
				     msrs.entries[0].data,
				     msrs.entries[1].data);
			}
			memcpy(data, &msrs.entries[0].data, len);
		}
		return true;
	}
	return false;
}

GUEST_TEST(cp15, cp15_test);

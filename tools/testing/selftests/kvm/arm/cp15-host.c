#include <strings.h>
#include <stdbool.h>
#include <string.h>
#include <linux/kvm.h>
#include <err.h>
#include <assert.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdio.h>

#include "guest-driver.h"
#include "cp15_test.h"

#define MORE_THAN_ENOUGH 1000

/* Given a simple mask, get those bits. */
static inline u32 get_bits(u32 index, u32 mask)
{
	return (index & mask) >> (ffs(mask) - 1);
}

/* Exercise KVM_GET_REG_LIST */
static void check_indexlist(int vcpu_fd)
{
	unsigned int i, num_core = 0, num_demux = 0;
	bool found_ttbr0 = false, found_ttbr1 = false, found_tpidprw = false;
	struct {
		struct kvm_reg_list head;
		__u64 indices[MORE_THAN_ENOUGH];
	} list;

	/* Attempt with too-short array should fail, with E2BIG, and not
	 * write outside the array bounds given. */
	list.head.n = 1;
	list.indices[1] = 0xdeadbeef;

	if (ioctl(vcpu_fd, KVM_GET_REG_LIST, &list) != -1)
		errx(1, "KVM_GET_REG_LIST(1) succeeded?");
	if (errno != E2BIG)
		err(1, "KVM_GET_REG_LIST(1) failed with bad errno");
	assert(list.head.n > 1);
	assert(list.indices[1] == 0xdeadbeef);

	/* Now for real. */
	list.head.n = MORE_THAN_ENOUGH;
	if (ioctl(vcpu_fd, KVM_GET_REG_LIST, &list) != 0)
		err(1, "KVM_GET_REG_LIST");

	assert(list.head.n < MORE_THAN_ENOUGH);
	for (i = 0; i < list.head.n; i++) {
		__u64 idx = list.indices[i];
		struct kvm_one_reg r;
		__u64 val;
		int cp;

		if ((idx & KVM_REG_ARCH_MASK) != KVM_REG_ARM)
			errx(1, "Invalid non-ARM index 0x%llx", idx);

		cp = (idx&KVM_REG_ARM_COPROC_MASK) >> KVM_REG_ARM_COPROC_SHIFT;

		if (cp == (KVM_REG_ARM_CORE >> KVM_REG_ARM_COPROC_SHIFT))
			num_core++;

		if (cp == (KVM_REG_ARM_DEMUX >> KVM_REG_ARM_COPROC_SHIFT))
			num_demux++;

		if (KVM_REG_SIZE(idx) == 8 && cp == 15
		    && ((idx & KVM_REG_ARM_CRM_MASK) >> KVM_REG_ARM_CRM_SHIFT) == 2) {
			switch ((idx & KVM_REG_ARM_OPC1_MASK) >> KVM_REG_ARM_OPC1_SHIFT) {
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
		if (KVM_REG_SIZE(idx) == 4 && cp == 15
		    && ((idx & KVM_REG_ARM_CRM_MASK) >> KVM_REG_ARM_CRM_SHIFT == 0)
		    && ((idx & KVM_REG_ARM_32_CRN_MASK) >> KVM_REG_ARM_32_CRN_SHIFT == 13)
		    && ((idx & KVM_REG_ARM_32_OPC2_MASK) >> KVM_REG_ARM_32_OPC2_SHIFT == 4)
		    && ((idx & KVM_REG_ARM_OPC1_MASK) >> KVM_REG_ARM_OPC1_SHIFT == 0)) {
			assert(!found_tpidprw);
			found_tpidprw = true;
		}

		/* Test unchanged read/write works. */
		r.id = idx;
		r.addr = (long)&val;
		printf("%u: %#llx\n", i, idx);
		switch (KVM_REG_SIZE(idx)) {
		case 4:
			val = 0xabadc0ff00000000ULL;
			if (ioctl(vcpu_fd, KVM_GET_ONE_REG, &r) != 0)
				err(1, "Failed to GET_ONE_REG %#llx", idx);
			if (val >> 32 != 0xabadc0ff)
				errx(1, "GET_ONE_REG %#llx overwrote: %#llx",
				     idx, val);
			if (ioctl(vcpu_fd, KVM_SET_ONE_REG, &r) != 0)
				err(1, "Failed to SET_ONE_REG %#llx", idx);
			break;
		case 8:
			if (ioctl(vcpu_fd, KVM_GET_ONE_REG, &r) != 0)
				err(1, "Failed to GET_ONE_REG %#llx", idx);
			if (ioctl(vcpu_fd, KVM_SET_ONE_REG, &r) != 0)
				err(1, "Failed to SET_ONE_REG %#llx", idx);

			break;
		default:
			errx(1, "FIXME: unsupported reg size %u",
			     KVM_REG_SIZE(idx));
		}
	}
	assert(found_ttbr0);
	assert(found_ttbr1);
	assert(found_tpidprw);
	assert(num_demux > 2);
	assert(num_core == sizeof(struct kvm_regs) / 4);
}

/* Return false to stop the VM */
static bool cp15_test(struct kvm_run *kvm_run, int vcpu_fd)
{
	static bool indexlist_checked = false;
	unsigned long phys_addr;
	bool is_write;
	unsigned char *data;
	unsigned long len;
	struct kvm_one_reg reg;
	__u64 reg64;
	__u32 reg32;

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

	switch (phys_addr) {
	case CP15_TTBR0:
		reg.id = KVM_REG_ARM | KVM_REG_SIZE_U64
			| (15 << KVM_REG_ARM_COPROC_SHIFT)
			| (2 << KVM_REG_ARM_CRM_SHIFT)
			| (0 << KVM_REG_ARM_OPC1_SHIFT);

		reg.addr = (__u64)(long)&reg64;

		if (is_write) {
			/* High bits are 0. */
			reg64 = 0;
			memcpy(&reg64, data, len);
			if (ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg) != 0)
				err(1, "KVM_SET_ONE_REG(TTBR0) failed");
		} else {
			if (ioctl(vcpu_fd, KVM_GET_ONE_REG, &reg) != 0)
				err(1, "KVM_GET_ONE_REG(TTBR0) failed");
			memcpy(data, &reg64, len);
		}
		return true;

	case CP15_IFAR:
		reg.id = KVM_REG_ARM | KVM_REG_SIZE_U32
			| (15 << KVM_REG_ARM_COPROC_SHIFT)
			| (6 << KVM_REG_ARM_32_CRN_SHIFT)
			| (0 << KVM_REG_ARM_OPC1_SHIFT)
			| (2 << KVM_REG_ARM_32_OPC2_SHIFT);

		reg.addr = (__u64)(long)&reg32;
		
		if (is_write) {
			memcpy(&reg32, data, len);
			if (ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg) != 0)
				err(1, "KVM_SET_ONE_REG(IFAR) failed");
		} else {
			if (ioctl(vcpu_fd, KVM_GET_ONE_REG, &reg) != 0)
				err(1, "KVM_GET_ONE_REG(IFAR) failed");
			memcpy(data, &reg32, len);
		}
		return true;
	}
	return false;
}

GUEST_TEST(cp15, cp15_test);

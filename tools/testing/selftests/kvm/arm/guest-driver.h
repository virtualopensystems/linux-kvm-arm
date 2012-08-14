#ifndef __GUEST_DRIVER_H_
#define __GUEST_DRIVER_H_

#define pr_err(fmt, args...) fprintf(stderr, fmt, ##args)
#define pr_errno(fmt, args...) \
	fprintf(stderr, fmt ": %s\n", args, strerror(errno))

#define PAGE_SIZE (4096)
#define PAGE_MASK (~(PAGE_SIZE - 1))

#define CODE_SLOT 0
#define CODE_PHYS_BASE (0x80000000)
#define RAM_SIZE (1024 * PAGE_SIZE) /* 1 MB of physical RAM , yeah! */

int handle_mmio(struct kvm_run *kvm_run);

#endif /* __GUEST_DRIVER_H_ */

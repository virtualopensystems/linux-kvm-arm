/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <trace/events/kvm.h>

#define CREATE_TRACE_POINTS
#include "trace.h"

#include <asm/unified.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <asm/mman.h>
#include <asm/tlbflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>

#include "debug.h"

static void *kvm_arm_hyp_stack_page = NULL;

/* The VMID used in the VTTBR */
#define VMID_SIZE (1<<8)
static DECLARE_BITMAP(kvm_vmids, VMID_SIZE);
static DEFINE_MUTEX(kvm_vmids_mutex);

int kvm_arch_hardware_enable(void *garbage)
{
	return 0;
}

void kvm_arch_hardware_disable(void *garbage)
{
	/* There is no need for this now, so we just ignore that */
}

int kvm_arch_hardware_setup(void)
{
	return 0;
}

void kvm_arch_hardware_unsetup(void)
{
}

void kvm_arch_check_processor_compat(void *rtn)
{
	*(int *)rtn = 0;
}

void kvm_arch_sync_events(struct kvm *kvm)
{
}

int kvm_arch_init_vm(struct kvm *kvm)
{
	int ret = 0;
	phys_addr_t pgd_phys;
	unsigned long vmid;
	unsigned long start, end;


	mutex_lock(&kvm_vmids_mutex);
	vmid = find_first_zero_bit(kvm_vmids, VMID_SIZE);
	if (vmid >= VMID_SIZE) {
		mutex_unlock(&kvm_vmids_mutex);
		return -EBUSY;
	}
	__set_bit(vmid, kvm_vmids);
	kvm->arch.vmid = vmid;
	mutex_unlock(&kvm_vmids_mutex);

	ret = kvm_alloc_stage2_pgd(kvm);
	if (ret)
		goto out_fail_alloc;

	pgd_phys = virt_to_phys(kvm->arch.pgd);
	kvm->arch.vttbr = (pgd_phys & ((1LLU << 40) - 1) & ~((2 << VTTBR_X) - 1)) |
			  ((u64)vmid << 48);

	start = (unsigned long)kvm,
	end = start + sizeof(struct kvm);
	ret = create_hyp_mappings(kvm_hyp_pgd, start, end);
	if (ret)
		goto out_fail_hyp_mappings;

	return ret;
out_fail_hyp_mappings:
	remove_hyp_mappings(kvm_hyp_pgd, start, end);
out_fail_alloc:
	clear_bit(vmid, kvm_vmids);
	return ret;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	int i;

	kvm_free_stage2_pgd(kvm);

	if (kvm->arch.vmid != 0) {
		mutex_lock(&kvm_vmids_mutex);
		clear_bit(kvm->arch.vmid, kvm_vmids);
		mutex_unlock(&kvm_vmids_mutex);
	}

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (kvm->vcpus[i]) {
			kvm_arch_vcpu_free(kvm->vcpus[i]);
			kvm->vcpus[i] = NULL;
		}
	}
}

int kvm_dev_ioctl_check_extension(long ext)
{
	int r;
	switch (ext) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
		r = 1;
		break;
	case KVM_CAP_COALESCED_MMIO:
		r = KVM_COALESCED_MMIO_PAGE_OFFSET;
		break;
	default:
		r = 0;
		break;
	}
	return r;
}

long kvm_arch_dev_ioctl(struct file *filp,
			unsigned int ioctl, unsigned long arg)
{
	int ret = 0;

	switch (ioctl) {
	default:
		ret = -EINVAL;
	}

	if (ret < 0)
		printk(KERN_ERR "error processing ARM ioct: %d", ret);
	return ret;
}

int kvm_arch_set_memory_region(struct kvm *kvm,
			       struct kvm_userspace_memory_region *mem,
			       struct kvm_memory_slot old,
			       int user_alloc)
{
	return 0;
}

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				   struct kvm_memory_slot *memslot,
				   struct kvm_memory_slot old,
				   struct kvm_userspace_memory_region *mem,
				   int user_alloc)
{
	return 0;
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
				   struct kvm_userspace_memory_region *mem,
				   struct kvm_memory_slot old,
				   int user_alloc)
{
}

void kvm_arch_flush_shadow(struct kvm *kvm)
{
	// XXX What should this do?
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	int err;
	struct kvm_vcpu *vcpu;
	unsigned long start, end;

	vcpu = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = kvm_vcpu_init(vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	start = (unsigned long)vcpu,
	end = start + sizeof(struct kvm_vcpu);
	err = create_hyp_mappings(kvm_hyp_pgd, start, end);
	if (err)
		goto out_fail_hyp_mappings;

	return vcpu;
out_fail_hyp_mappings:
	remove_hyp_mappings(kvm_hyp_pgd, start, end);
free_vcpu:
	kmem_cache_free(kvm_vcpu_cache, vcpu);
out:
	return ERR_PTR(err);
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	KVMARM_NOT_IMPLEMENTED();
}

void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_free(vcpu);
}

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	return 0;
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	KVMARM_NOT_IMPLEMENTED();
	return 0;
}

void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
}

int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
                                        struct kvm_guest_debug *dbg)
{
	return -EINVAL;
}


int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	return -EINVAL;
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	return 0;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	KVMARM_NOT_IMPLEMENTED();
	return -EINVAL;
}

static int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu,
				    struct kvm_interrupt *intr)
{
	u32 mask;

	switch (intr->irq) {
	case EXCEPTION_IRQ:
		/* IRQ */
		mask = EXCEPTION_IRQ;
		break;
	case EXCEPTION_FIQ:
		/* FIQ */
		mask = EXCEPTION_FIQ;
		break;
	default:
		/* Only async exceptions are supported here */
		return -EINVAL;
	}

	if (intr->irq & 4) { /* FIXME: use IRQ_LINE instead */
		vcpu->arch.exception_pending |= mask;
		vcpu->arch.wait_for_interrupts = 0;
	} else
		vcpu->arch.exception_pending &= ~mask;

	return 0;
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	struct kvm_vcpu *vcpu = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;

	switch (ioctl) {
	case KVM_S390_STORE_STATUS: {
		return -EINVAL;
	}
	case KVM_INTERRUPT: {
		struct kvm_interrupt intr;

		r = -EFAULT;
		if (copy_from_user(&intr, argp, sizeof intr))
			break;
		r = kvm_vcpu_ioctl_interrupt(vcpu, &intr);
		break;
	}
	default:
		r = -EINVAL;
	}

	return r;
}

int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	return -ENOTSUPP;
}

long kvm_arch_vm_ioctl(struct file *filp,
		       unsigned int ioctl, unsigned long arg)
{
	printk(KERN_ERR "kvm_arch_vm_ioctl: Unsupported ioctl (%d)\n", ioctl);
	return -EINVAL;
}

static int init_hyp_mode(void)
{
	phys_addr_t init_phys_addr, init_end_phys_addr;
	unsigned long vector_ptr, hyp_stack_ptr;
	int err = 0;

	/*
	 * Allocate Hyp level-1 page table
	 */
	kvm_hyp_pgd = kzalloc(PTRS_PER_PGD * sizeof(pgd_t), GFP_KERNEL);
	if (!kvm_hyp_pgd)
		return -ENOMEM;

	/*
	 * Allocate stack page for Hypervisor-mode
	 */
	kvm_arm_hyp_stack_page = (void *)__get_free_page(GFP_KERNEL);
	if (!kvm_arm_hyp_stack_page) {
		err = -ENOMEM;
		goto out_free_pgd;
	}

	hyp_stack_ptr = (unsigned long)kvm_arm_hyp_stack_page + PAGE_SIZE;

	init_phys_addr = virt_to_phys((void *)&__kvm_hyp_init);
	init_end_phys_addr = virt_to_phys((void *)&__kvm_hyp_init_end);

	/*
	 * Create identity mapping
	 */
	hyp_identity_mapping_add(kvm_hyp_pgd,
				 (unsigned long)init_phys_addr,
				 (unsigned long)init_end_phys_addr);

	/*
	 * Set the HVBAR
	 */
	BUG_ON(init_phys_addr & 0x1f);
	asm volatile (
		"mov	r0, %[vector_ptr]\n\t"
		"ldr	r7, =SMCHYP_HVBAR_W\n\t"
		"smc	#0\n\t" :
		: [vector_ptr] "r" ((unsigned long)init_phys_addr)
		: "r0", "r7");

	/*
	 * Call initialization code
	 */
	asm volatile (
		"mov	r0, %[pgd_ptr]\n\t"
		"mov	r1, %[stack_ptr]\n\t"
		"hvc	#0\n\t" :
		: [pgd_ptr] "r" (virt_to_phys(kvm_hyp_pgd)),
		  [stack_ptr] "r" (hyp_stack_ptr)
		: "r0", "r1");

	/*
	 * Unmap the identity mapping
	 */
	hyp_identity_mapping_del(kvm_hyp_pgd,
				 (unsigned long)init_phys_addr,
				 (unsigned long)init_end_phys_addr);

	/*
	 * Set the HVBAR to the virtual kernel address
	 */
	vector_ptr = (unsigned long)&__kvm_hyp_vector;
	asm volatile (
		"mov	r0, %[vector_ptr]\n\t"
		"ldr	r7, =SMCHYP_HVBAR_W\n\t"
		"smc	#0\n\t" :
		: [vector_ptr] "r" ((unsigned long)vector_ptr)
		: "r0", "r7");

	return err;
out_free_pgd:
	kfree(kvm_hyp_pgd);
	kvm_hyp_pgd = NULL;
	return err;
}

static int init_hyp_memory(void)
{
	int err = 0;
	unsigned long start, end;

	/*
	 * Map Hyp exception vectors
	 */
	start = (unsigned long)&__kvm_hyp_vector;
	end = (unsigned long)&__kvm_hyp_vector_end;
	err = create_hyp_mappings(kvm_hyp_pgd, start, end);
	if (err) {
		kvm_err(err, "Cannot map hyp vector");
		goto out_free_mappings;
	}

	/*
	 * Map the world-switch code
	 */
	start = (unsigned long)&__kvm_vcpu_run;
	end = (unsigned long)&__kvm_vcpu_run_end;
	err = create_hyp_mappings(kvm_hyp_pgd, start, end);
	if (err) {
		kvm_err(err, "Cannot map world-switch code");
		goto out_free_mappings;
	}

	/*
	 * Map the Hyp stack page
	 */
	start = (unsigned long)kvm_arm_hyp_stack_page;
	end = start + PAGE_SIZE - 1;
	err = create_hyp_mappings(kvm_hyp_pgd, start, end);
	if (err) {
		kvm_err(err, "Cannot map hyp stack");
		goto out_free_mappings;
	}

	return err;
out_free_mappings:
	free_hyp_pmds(kvm_hyp_pgd);
	return err;
}

int kvm_arch_init(void *opaque)
{
	int err;

	err = init_hyp_mode();
	if (err)
		goto out_err;

	err = init_hyp_memory();
	if (err)
		goto out_err;

	set_bit(0, kvm_vmids);
	return 0;
out_err:
	return err;
}

void kvm_arch_exit(void)
{
	if (kvm_hyp_pgd) {
		free_hyp_pmds(kvm_hyp_pgd);
		kfree(kvm_hyp_pgd);
		kvm_hyp_pgd = NULL;
	}
}

static int arm_init(void)
{
	int rc = kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);
	if (rc == 0)
		kvm_arm_debugfs_init();
	return rc;
}

static void __exit arm_exit(void)
{
	kvm_exit();
	kvm_arm_debugfs_exit();
}

module_init(arm_init);
module_exit(arm_exit)

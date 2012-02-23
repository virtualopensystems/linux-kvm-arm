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
#include <linux/kvm.h>
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

static DEFINE_PER_CPU(unsigned long, kvm_arm_hyp_stack_page);

/* The VMID used in the VTTBR */
#define VMID_BITS               8
#define VMID_MASK               ((1 << VMID_BITS) - 1)
#define VMID_FIRST_GENERATION	(1 << VMID_BITS)
static u64 next_vmid;		/* The next available VMID in the sequence */
DEFINE_SPINLOCK(kvm_vmid_lock);

int kvm_arch_hardware_enable(void *garbage)
{
	return 0;
}

int kvm_arch_vcpu_should_kick(struct kvm_vcpu *vcpu)
{
	return 1;
}

void kvm_arch_hardware_disable(void *garbage)
{
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

int kvm_arch_vcpu_fault(struct kvm_vcpu *vcpu, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

void kvm_arch_free_memslot(struct kvm_memory_slot *free,
			   struct kvm_memory_slot *dont)
{
}

int kvm_arch_create_memslot(struct kvm_memory_slot *slot, unsigned long npages)
{
	return 0;
}

/**
 * kvm_arch_init_vm - initializes a VM data structure
 * @kvm:	pointer to the KVM struct
 */
int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	int ret = 0;

	if (type)
		return -EINVAL;

	ret = kvm_alloc_stage2_pgd(kvm);
	if (ret)
		goto out_fail_alloc;
	mutex_init(&kvm->arch.pgd_mutex);

	ret = create_hyp_mappings(kvm_hyp_pgd, kvm, kvm + 1);
	if (ret)
		goto out_free_stage2_pgd;

	/* Mark the initial VMID invalid */
	kvm->arch.vmid = 0;

	return ret;
out_free_stage2_pgd:
	kvm_free_stage2_pgd(kvm);
out_fail_alloc:
	return ret;
}

/**
 * kvm_arch_destroy_vm - destroy the VM data structure
 * @kvm:	pointer to the KVM struct
 */
void kvm_arch_destroy_vm(struct kvm *kvm)
{
	int i;

	kvm_free_stage2_pgd(kvm);

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
	return -EINVAL;
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
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	int err;
	struct kvm_vcpu *vcpu;

	vcpu = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = kvm_vcpu_init(vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	err = create_hyp_mappings(kvm_hyp_pgd, vcpu, vcpu + 1);
	if (err)
		goto free_vcpu;

	return vcpu;
free_vcpu:
	kmem_cache_free(kvm_vcpu_cache, vcpu);
out:
	return ERR_PTR(err);
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	kmem_cache_free(kvm_vcpu_cache, vcpu);
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
	return 0;
}

void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	vcpu->cpu = cpu;
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

int kvm_arch_vcpu_in_guest_mode(struct kvm_vcpu *v)
{
	return 0;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return -EINVAL;
}

static int kvm_arch_vm_ioctl_irq_line(struct kvm *kvm,
				      struct kvm_irq_level *irq_level)
{
	int mask;
	unsigned int vcpu_idx;
	struct kvm_vcpu *vcpu;
	unsigned long old, new, *ptr;

	vcpu_idx = irq_level->irq >> 1;
	if (vcpu_idx >= KVM_MAX_VCPUS)
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, vcpu_idx);
	if (!vcpu)
		return -EINVAL;

	if ((irq_level->irq & 1) == KVM_ARM_IRQ_LINE)
		mask = HCR_VI;
	else /* KVM_ARM_FIQ_LINE */
		mask = HCR_VF;

	trace_kvm_set_irq(irq_level->irq, irq_level->level, 0);

	ptr = (unsigned long *)&vcpu->arch.irq_lines;
	do {
		old = ACCESS_ONCE(*ptr);
		if (irq_level->level)
			new = old | mask;
		else
			new = old & ~mask;

		if (new == old)
			return 0; /* no change */
	} while (cmpxchg(ptr, old, new) != old);

	/*
	 * The vcpu irq_lines field was updated, wake up sleeping VCPUs and
	 * trigger a world-switch round on the running physical CPU to set the
	 * virtual IRQ/FIQ fields in the HCR appropriately.
	 */
	kvm_vcpu_kick(vcpu);

	return 0;
}

long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg)
{
	return -EINVAL;
}

int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	return -EINVAL;
}

long kvm_arch_vm_ioctl(struct file *filp,
		       unsigned int ioctl, unsigned long arg)
{
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;

	switch (ioctl) {
	case KVM_IRQ_LINE: {
		struct kvm_irq_level irq_event;

		if (copy_from_user(&irq_event, argp, sizeof irq_event))
			return -EFAULT;
		return kvm_arch_vm_ioctl_irq_line(kvm, &irq_event);
	}
	default:
		return -EINVAL;
	}
}

static void cpu_set_vector(void *vector)
{
	unsigned long vector_ptr;
	unsigned long smc_hyp_nr;

	vector_ptr = (unsigned long)vector;
	smc_hyp_nr = SMCHYP_HVBAR_W;

	/*
	 * Set the HVBAR
	 */
	asm volatile (
		"mov	r0, %[vector_ptr]\n\t"
		"mov	r7, %[smc_hyp_nr]\n\t"
		"smc	#0\n\t" : :
		[vector_ptr] "r" (vector_ptr),
		[smc_hyp_nr] "r" (smc_hyp_nr) :
		"r0", "r7");
}

static void cpu_init_hyp_mode(void *vector)
{
	unsigned long pgd_ptr;
	unsigned long hyp_stack_ptr;
	unsigned long stack_page;

	cpu_set_vector(vector);

	pgd_ptr = virt_to_phys(kvm_hyp_pgd);
	stack_page = __get_cpu_var(kvm_arm_hyp_stack_page);
	hyp_stack_ptr = stack_page + PAGE_SIZE;

	/*
	 * Call initialization code
	 */
	asm volatile (
		"mov	r0, %[pgd_ptr]\n\t"
		"mov	r1, %[hyp_stack_ptr]\n\t"
		"hvc	#0\n\t" : :
		[pgd_ptr] "r" (pgd_ptr),
		[hyp_stack_ptr] "r" (hyp_stack_ptr) :
		"r0", "r1");
}

/**
 * Inits Hyp-mode on all online CPUs
 */
static int init_hyp_mode(void)
{
	phys_addr_t init_phys_addr, init_end_phys_addr;
	int cpu;
	int err = 0;

	/*
	 * Allocate stack pages for Hypervisor-mode
	 */
	for_each_possible_cpu(cpu)
		per_cpu(kvm_arm_hyp_stack_page, cpu) = 0;
	for_each_possible_cpu(cpu) {
		unsigned long stack_page;

		stack_page = __get_free_page(GFP_KERNEL);
		if (!stack_page) {
			err = -ENOMEM;
			goto out_free_stack_pages;
		}

		per_cpu(kvm_arm_hyp_stack_page, cpu) = stack_page;
	}

	/*
	 * Allocate Hyp level-1 page table
	 */
	kvm_hyp_pgd = kzalloc(PTRS_PER_PGD * sizeof(pgd_t), GFP_KERNEL);
	if (!kvm_hyp_pgd)
		goto out_free_stack_pages;

	init_phys_addr = virt_to_phys(__kvm_hyp_init);
	init_end_phys_addr = virt_to_phys(__kvm_hyp_init_end);
	BUG_ON(init_phys_addr & 0x1f);

	/*
	 * Create identity mapping for the init code.
	 */
	hyp_idmap_add(kvm_hyp_pgd, (unsigned long)init_phys_addr,
				   (unsigned long)init_end_phys_addr);

	/*
	 * Execute the init code on each CPU.
	 *
	 * Note: The stack is not mapped yet, so don't do anything else than
	 * initializing the hypervisor mode on each CPU using a local stack
	 * space for temporary storage.
	 */
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, cpu_init_hyp_mode,
					 (void *)(long)init_phys_addr, 1);
	}

	/*
	 * Unmap the identity mapping
	 */
	hyp_idmap_del(kvm_hyp_pgd, (unsigned long)init_phys_addr,
				   (unsigned long)init_end_phys_addr);

	/*
	 * Map the Hyp-code called directly from the host
	 */
	err = create_hyp_mappings(kvm_hyp_pgd,
				  __kvm_hyp_code_start, __kvm_hyp_code_end);
	if (err) {
		kvm_err("Cannot map world-switch code\n");
		goto out_free_mappings;
	}

	/*
	 * Map the Hyp stack pages
	 */
	for_each_possible_cpu(cpu) {
		char *stack_page = (char *)per_cpu(kvm_arm_hyp_stack_page, cpu);
		err = create_hyp_mappings(kvm_hyp_pgd,
					  stack_page, stack_page + PAGE_SIZE);

		if (err) {
			kvm_err("Cannot map hyp stack\n");
			goto out_free_mappings;
		}
	}

	/*
	 * Set the HVBAR to the virtual kernel address
	 */
	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, cpu_set_vector,
					 __kvm_hyp_vector, 1);

	return 0;
out_free_mappings:
	free_hyp_pmds(kvm_hyp_pgd);
	kfree(kvm_hyp_pgd);
out_free_stack_pages:
	for_each_possible_cpu(cpu)
		free_page(per_cpu(kvm_arm_hyp_stack_page, cpu));
	kvm_hyp_pgd = NULL;
	return err;
}

/**
 * Initialize Hyp-mode and memory mappings on all CPUs.
 */
int kvm_arch_init(void *opaque)
{
	int err;

	err = init_hyp_mode();
	if (err)
		goto out_err;

	/*
	 * The upper 56 bits of VMIDs are used to identify the generation
	 * counter, so VMIDs initialized to 0, having generation == 0, will
	 * never be considered valid and therefor a new VMID must always be
	 * assigned. Whent he VMID generation rolls over, we start from
	 * VMID_FIRST_GENERATION again.
	 */
	next_vmid = VMID_FIRST_GENERATION;

	return 0;
out_err:
	return err;
}

void kvm_arch_exit(void)
{
	int cpu;

	free_hyp_pmds(kvm_hyp_pgd);
	for_each_possible_cpu(cpu)
		free_page(per_cpu(kvm_arm_hyp_stack_page, cpu));
	kfree(kvm_hyp_pgd);
	kvm_hyp_pgd = NULL;
}

static int arm_init(void)
{
	int rc = kvm_init(NULL, sizeof(struct kvm_vcpu), 0, THIS_MODULE);
	return rc;
}

static void __exit arm_exit(void)
{
	kvm_exit();
}

module_init(arm_init);
module_exit(arm_exit)

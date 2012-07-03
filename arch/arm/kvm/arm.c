/*
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 *
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

#include <asm/cputype.h>
#include <asm/unified.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <asm/mman.h>
#include <asm/idmap.h>
#include <asm/tlbflush.h>
#include <asm/cputype.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>

static DEFINE_PER_CPU(unsigned long, kvm_arm_hyp_stack_page);

/* The VMID used in the VTTBR */
static atomic64_t kvm_vmid_gen = ATOMIC64_INIT(1);
static u8 kvm_next_vmid;
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

	ret = create_hyp_mappings(kvm, kvm + 1);
	if (ret)
		goto out_free_stage2_pgd;

	/* Mark the initial VMID generation invalid */
	kvm->arch.vmid_gen = 0;

	return ret;
out_free_stage2_pgd:
	kvm_free_stage2_pgd(kvm);
out_fail_alloc:
	return ret;
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

	err = create_hyp_mappings(vcpu, vcpu + 1);
	if (err)
		goto vcpu_uninit;

	return vcpu;
vcpu_uninit:
	kvm_vcpu_uninit(vcpu);
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

int __attribute_const__ kvm_target_cpu(void)
{
	unsigned int midr;

	midr = read_cpuid_id();
	switch ((midr >> 4) & 0xfff) {
	case CORTEX_A15:
		return CORTEX_A15;
	default:
		return -EINVAL;
	}
}

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	int ret;

	ret = kvm_reset_vcpu(vcpu);
	if (ret < 0)
		return ret;

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
	return v->mode == IN_GUEST_MODE;
}

static void reset_vm_context(void *info)
{
	__kvm_flush_vm_context();
}

/**
 * check_new_vmid_gen - check that the VMID is still valid
 * @kvm: The VM's VMID to checkt
 *
 * return true if there is a new generation of VMIDs being used
 *
 * The hardware supports only 256 values with the value zero reserved for the
 * host, so we check if an assigned value belongs to a previous generation,
 * which which requires us to assign a new value. If we're the first to use a
 * VMID for the new generation, we must flush necessary caches and TLBs on all
 * CPUs.
 */
static bool check_new_vmid_gen(struct kvm *kvm)
{
	return unlikely(kvm->arch.vmid_gen != atomic64_read(&kvm_vmid_gen));
}

/**
 * update_vttbr - Update the VTTBR with a valid VMID before the guest runs
 * @kvm	The guest that we are about to run
 *
 * Called from kvm_arch_vcpu_ioctl_run before entering the guest to ensure the
 * VM has a valid VMID, otherwise assigns a new one and flushes corresponding
 * caches and TLBs.
 */
static void update_vttbr(struct kvm *kvm)
{
	phys_addr_t pgd_phys;

	if (!check_new_vmid_gen(kvm))
		return;

	spin_lock(&kvm_vmid_lock);

	/* First user of a new VMID generation? */
	if (unlikely(kvm_next_vmid == 0)) {
		atomic64_inc(&kvm_vmid_gen);
		kvm_next_vmid = 1;

		/* This does nothing on UP */
		smp_call_function(reset_vm_context, NULL, 1);

		/*
		 * On SMP we know no other CPUs can use this CPU's or
		 * each other's VMID since the kvm_vmid_lock blocks
		 * them from reentry to the guest.
		 */

		reset_vm_context(NULL);
	}

	kvm->arch.vmid_gen = atomic64_read(&kvm_vmid_gen);
	kvm->arch.vmid = kvm_next_vmid;
	kvm_next_vmid++;

	/* update vttbr to be used with the new vmid */
	pgd_phys = virt_to_phys(kvm->arch.pgd);
	kvm->arch.vttbr = pgd_phys & ((1LLU << 40) - 1)
			  & ~((2 << VTTBR_X) - 1);
	kvm->arch.vttbr |= (u64)(kvm->arch.vmid) << 48;

	spin_unlock(&kvm_vmid_lock);
}

/*
 * Return 0 to return to guest, < 0 on error, exit_reason ( > 0) on proper
 * exit to QEMU.
 */
static int handle_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
		       int exception_index)
{
	return -EINVAL;
}

/*
 * Return 0 to proceed with guest entry
 */
static int vcpu_pre_guest_enter(struct kvm_vcpu *vcpu, int *exit_reason)
{
	if (signal_pending(current)) {
		*exit_reason = KVM_EXIT_INTR;
		return -EINTR;
	}

	if (check_new_vmid_gen(vcpu->kvm))
		return 1;

	BUG_ON(__vcpu_mode(*vcpu_cpsr(vcpu)) == 0xf);

	return 0;
}

/**
 * kvm_arch_vcpu_ioctl_run - the main VCPU run function to execute guest code
 * @vcpu:	The VCPU pointer
 * @run:	The kvm_run structure pointer used for userspace state exchange
 *
 * This function is called through the VCPU_RUN ioctl called from user space. It
 * will execute VM code in a loop until the time slice for the process is used
 * or some emulation is needed from user space in which case the function will
 * return with return value 0 and with the kvm_run structure filled in with the
 * required data for the requested emulation.
 */
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret = 0;
	int exit_reason;
	sigset_t sigsaved;

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	exit_reason = KVM_EXIT_UNKNOWN;
	while (exit_reason == KVM_EXIT_UNKNOWN) {
		/*
		 * Check conditions before entering the guest
		 */
		cond_resched();

		update_vttbr(vcpu->kvm);

		local_irq_disable();

		/* Re-check atomic conditions */
		ret = vcpu_pre_guest_enter(vcpu, &exit_reason);
		if (ret != 0) {
			local_irq_enable();
			preempt_enable();
			continue;
		}

		/**************************************************************
		 * Enter the guest
		 */
		trace_kvm_entry(vcpu->arch.regs.pc);
		kvm_guest_enter();
		vcpu->mode = IN_GUEST_MODE;

		ret = __kvm_vcpu_run(vcpu);

		vcpu->mode = OUTSIDE_GUEST_MODE;
		vcpu->stat.exits++;
		kvm_guest_exit();
		trace_kvm_exit(vcpu->arch.regs.pc);
		local_irq_enable();

		/*
		 * Back from guest
		 *************************************************************/

		ret = handle_exit(vcpu, run, ret);
		if (ret < 0) {
			kvm_err("Error in handle_exit\n");
			break;
		} else {
			exit_reason = ret; /* 0 == KVM_EXIT_UNKNOWN */
		}
	}

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	run->exit_reason = exit_reason;
	return ret;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *irq_level)
{
	unsigned int vcpu_idx;
	struct kvm_vcpu *vcpu;
	unsigned long *ptr;
	bool set;
	int bit_nr;

	vcpu_idx = irq_level->irq >> 1;
	if (vcpu_idx >= KVM_MAX_VCPUS)
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, vcpu_idx);
	if (!vcpu)
		return -EINVAL;

	trace_kvm_set_irq(irq_level->irq, irq_level->level, 0);

	if ((irq_level->irq & 1) == KVM_ARM_IRQ_LINE)
		bit_nr = HCR_VI_BIT_NR;
	else /* KVM_ARM_FIQ_LINE */
		bit_nr = HCR_VF_BIT_NR;

	ptr = (unsigned long *)&vcpu->arch.irq_lines;
	if (irq_level->level)
		set = test_and_set_bit(bit_nr, ptr);
	else
		set = test_and_clear_bit(bit_nr, ptr);

	/*
	 * If we didn't change anything, no need to wake up or kick other CPUs
	 */
	if (!!set == !!irq_level->level)
		return 0;

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
	return -EINVAL;
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

	pgd_ptr = virt_to_phys(hyp_pgd);
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
	phys_addr_t init_phys_addr;
	int cpu;
	int err = 0;

	/*
	 * Allocate stack pages for Hypervisor-mode
	 */
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
	 * Execute the init code on each CPU.
	 *
	 * Note: The stack is not mapped yet, so don't do anything else than
	 * initializing the hypervisor mode on each CPU using a local stack
	 * space for temporary storage.
	 */
	init_phys_addr = virt_to_phys(__kvm_hyp_init);
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, cpu_init_hyp_mode,
					 (void *)(long)init_phys_addr, 1);
	}

	/*
	 * Unmap the identity mapping
	 */
	hyp_idmap_teardown();

	/*
	 * Map the Hyp-code called directly from the host
	 */
	err = create_hyp_mappings(__kvm_hyp_code_start, __kvm_hyp_code_end);
	if (err) {
		kvm_err("Cannot map world-switch code\n");
		goto out_free_mappings;
	}

	/*
	 * Map the Hyp stack pages
	 */
	for_each_possible_cpu(cpu) {
		char *stack_page = (char *)per_cpu(kvm_arm_hyp_stack_page, cpu);
		err = create_hyp_mappings(stack_page, stack_page + PAGE_SIZE);

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
	free_hyp_pmds();
out_free_stack_pages:
	for_each_possible_cpu(cpu)
		free_page(per_cpu(kvm_arm_hyp_stack_page, cpu));
	return err;
}

/**
 * Initialize Hyp-mode and memory mappings on all CPUs.
 */
int kvm_arch_init(void *opaque)
{
	int err;

	if (kvm_target_cpu() < 0) {
		kvm_err("Target CPU not supported!\n");
		return -ENODEV;
	}

	err = init_hyp_mode();
	if (err)
		goto out_err;

	return 0;
out_err:
	return err;
}

static void cpu_exit_hyp_mode(void *vector)
{
	cpu_set_vector(vector);

	/*
	 * Disable Hyp-MMU for each cpu
	 */
	asm volatile ("hvc	#0");
}

static int exit_hyp_mode(void)
{
	phys_addr_t exit_phys_addr;
	int cpu;

	/*
	 * TODO: flush Hyp TLB in case idmap code overlaps.
	 * Note that we should do this in the monitor code when switching the
	 * HVBAR, but this is going  away and should be rather done in the Hyp
	 * mode change of HVBAR.
	 */
	hyp_idmap_setup();
	exit_phys_addr = virt_to_phys(__kvm_hyp_exit);
	BUG_ON(exit_phys_addr & 0x1f);

	/*
	 * Execute the exit code on each CPU.
	 *
	 * Note: The stack is not mapped yet, so don't do anything else than
	 * initializing the hypervisor mode on each CPU using a local stack
	 * space for temporary storage.
	 */
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, cpu_exit_hyp_mode,
					 (void *)(long)exit_phys_addr, 1);
	}

	return 0;
}

void kvm_arch_exit(void)
{
	int cpu;

	exit_hyp_mode();

	free_hyp_pmds();
	for_each_possible_cpu(cpu)
		free_page(per_cpu(kvm_arm_hyp_stack_page, cpu));
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

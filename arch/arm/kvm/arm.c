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
#include <asm/cputype.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>

#include "debug.h"

#define TMP_LOG_LEN 512
static char __tmp_log_data[TMP_LOG_LEN];
DEFINE_SPINLOCK(__tmp_log_lock);
void __kvm_print_msg(char *fmt, ...)
{
	va_list ap;
	unsigned int size;

	spin_lock(&__tmp_log_lock);

	va_start(ap, fmt);
	size = vsnprintf(__tmp_log_data, TMP_LOG_LEN, fmt, ap);
	va_end(ap);

	if (size >= TMP_LOG_LEN)
		printk(KERN_ERR "Message exceeded log length!\n");
	else
		printk(KERN_INFO "%s", __tmp_log_data);

	spin_unlock(&__tmp_log_lock);
}

static DEFINE_PER_CPU(void *, kvm_arm_hyp_stack_page);

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
int kvm_arch_init_vm(struct kvm *kvm)
{
	int ret = 0;
	phys_addr_t pgd_phys;
	unsigned long vmid;

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
	mutex_init(&kvm->arch.pgd_mutex);

	pgd_phys = virt_to_phys(kvm->arch.pgd);
	kvm->arch.vttbr = pgd_phys & ((1LLU << 40) - 1) & ~((2 << VTTBR_X) - 1);
	kvm->arch.vttbr |= ((u64)vmid << 48);

	ret = create_hyp_mappings(kvm_hyp_pgd, kvm, kvm + 1);
	if (ret)
		goto out_free_stage2_pgd;

	return ret;
out_free_stage2_pgd:
	kvm_free_stage2_pgd(kvm);
out_fail_alloc:
	clear_bit(vmid, kvm_vmids);
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
	unsigned long cpsr;
	unsigned long sctlr;

	spin_lock_init(&vcpu->arch.irq_lock);

	/* Init execution CPSR */
	asm volatile ("mrs	%[cpsr], cpsr" :
			[cpsr] "=r" (cpsr));
	vcpu->arch.regs.cpsr = SVC_MODE | PSR_I_BIT | PSR_F_BIT | PSR_A_BIT |
				(cpsr & PSR_E_BIT);

	/* Init SCTLR with MMU disabled */
	asm volatile ("mrc	p15, 0, %[sctlr], c1, c0, 0" :
			[sctlr] "=r" (sctlr));
	vcpu->arch.cp15.c1_SCTLR = sctlr & ~1U;

	/* Compute guest MPIDR */
	vcpu->arch.cp15.c0_MPIDR = (read_cpuid_mpidr() & ~0xff) | vcpu->vcpu_id;

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

/**
 * kvm_arch_vcpu_runnable - determine if the vcpu can be scheduled
 * @v:		The VCPU pointer
 *
 * If the guest CPU is not waiting for interrupts then it is by definition
 * runnable.
 */
int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	return !v->arch.wait_for_interrupts;
}

static inline int handle_exit(struct kvm_vcpu *vcpu, struct kvm_run *run,
			      int exception_index)
{
	unsigned long hsr_ec;

	if (exception_index == ARM_EXCEPTION_IRQ)
		return 0;

	if (exception_index != ARM_EXCEPTION_HVC) {
		kvm_err(-EINVAL, "Unsupported exception type");
		return -EINVAL;
	}

	hsr_ec = (vcpu->arch.hsr & HSR_EC) >> HSR_EC_SHIFT;
	switch (hsr_ec) {
	case HSR_EC_WFI:
		return kvm_handle_wfi(vcpu, run);
	case HSR_EC_CP15_32:
	case HSR_EC_CP15_64:
		return kvm_handle_cp15_access(vcpu, run);
	case HSR_EC_CP14_MR:
		return kvm_handle_cp14_access(vcpu, run);
	case HSR_EC_CP14_LS:
		return kvm_handle_cp14_load_store(vcpu, run);
	case HSR_EC_CP14_64:
		return kvm_handle_cp14_access(vcpu, run);
	case HSR_EC_CP_0_13:
		return kvm_handle_cp_0_13_access(vcpu, run);
	case HSR_EC_CP10_ID:
		return kvm_handle_cp10_id(vcpu, run);
	case HSR_EC_SVC_HYP:
		/* SVC called from Hyp mode should never get here */
		kvm_msg("SVC called from Hyp mode shouldn't go here");
		BUG();
	case HSR_EC_HVC:
		kvm_msg("hvc: %x (at %08x)", vcpu->arch.hsr & ((1 << 16) - 1),
					     vcpu->arch.regs.pc);
		kvm_msg("         HSR: %8x", vcpu->arch.hsr);
		break;
	case HSR_EC_IABT:
	case HSR_EC_DABT:
		return kvm_handle_guest_abort(vcpu, run);
	case HSR_EC_IABT_HYP:
	case HSR_EC_DABT_HYP:
		/* The hypervisor should never cause aborts */
		kvm_msg("The hypervisor itself shouldn't cause aborts");
		BUG();
	default:
		kvm_msg("Unkown exception class: %08x (%08x)", hsr_ec,
				vcpu->arch.hsr);
		BUG();
	}

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
	int ret;

	for (;;) {
		if (vcpu->arch.wait_for_interrupts)
			goto wait_for_interrupts;

		if (run->exit_reason == KVM_EXIT_MMIO) {
			ret = kvm_handle_mmio_return(vcpu, vcpu->run);
			if (ret)
				break;
		}

		run->exit_reason = KVM_EXIT_UNKNOWN;

		trace_kvm_entry(vcpu->arch.regs.pc);

		local_irq_disable();
		kvm_guest_enter();

		ret = __kvm_vcpu_run(vcpu);

		kvm_guest_exit();
		local_irq_enable();

		trace_kvm_exit(vcpu->arch.regs.pc);

		ret = handle_exit(vcpu, run, ret);
		if (ret) {
			kvm_err(ret, "Error in handle_exit");
			break;
		}

		if (run->exit_reason == KVM_EXIT_MMIO)
			break;

		if (need_resched())
			kvm_resched(vcpu);
wait_for_interrupts:
		if (signal_pending(current)) {
			if (!run->exit_reason) {
				ret = -EINTR;
				run->exit_reason = KVM_EXIT_INTR;
			}
			break;
		}

		if (vcpu->arch.wait_for_interrupts)
			kvm_vcpu_block(vcpu);
	}

	return ret;
}

static int kvm_arch_vm_ioctl_irq_line(struct kvm *kvm,
				      struct kvm_irq_level *irq_level)
{
	u32 mask;
	unsigned int vcpu_idx;
	struct kvm_vcpu *vcpu;

	vcpu_idx = irq_level->irq / 2;
	if (vcpu_idx >= KVM_MAX_VCPUS)
		return -EINVAL;

	vcpu = kvm_get_vcpu(kvm, vcpu_idx);
	if (!vcpu)
		return -EINVAL;

	switch (irq_level->irq % 2) {
	case KVM_ARM_IRQ_LINE:
		mask = HCR_VI;
		break;
	case KVM_ARM_FIQ_LINE:
		mask = HCR_VF;
		break;
	default:
		return -EINVAL;
	}

	trace_kvm_irq_line(irq_level->irq % 2, irq_level->level, vcpu_idx);

	spin_lock(&vcpu->arch.irq_lock);
	if (irq_level->level) {
		vcpu->arch.virt_irq |= mask;

		/*
		 * Note that we grab the wq.lock before clearing the wfi flag
		 * since this ensures that a concurrent call to kvm_vcpu_block
		 * will either sleep before we grab the lock, in which case we
		 * wake it up, or will never sleep due to
		 * kvm_arch_vcpu_runnable being true (iow. this avoids having
		 * to grab the irq_lock in kvm_arch_vcpu_runnable).
		 */
		spin_lock(&vcpu->wq.lock);
		vcpu->arch.wait_for_interrupts = 0;

		if (waitqueue_active(&vcpu->wq))
			__wake_up_locked(&vcpu->wq, TASK_INTERRUPTIBLE);
		spin_unlock(&vcpu->wq.lock);
	} else
		vcpu->arch.virt_irq &= ~mask;
	spin_unlock(&vcpu->arch.irq_lock);

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
	/*
	 * Set the HVBAR
	 */
	asm volatile (
		"mov	r0, %[vector_ptr]\n\t"
		"ldr	r7, =SMCHYP_HVBAR_W\n\t"
		"smc	#0\n\t" : :
		[vector_ptr] "r" (vector) :
		"r0", "r7");
}

static void cpu_init_hyp_mode(void *vector)
{
	unsigned long hyp_stack_ptr;
	void *stack_page;

	stack_page = __get_cpu_var(kvm_arm_hyp_stack_page);
	hyp_stack_ptr = (unsigned long)stack_page + PAGE_SIZE;

	cpu_set_vector(vector);

	/*
	 * Call initialization code
	 */
	asm volatile (
		"mov	r0, %[pgd_ptr]\n\t"
		"mov	r1, %[stack_ptr]\n\t"
		"hvc	#0\n\t" : :
		[pgd_ptr] "r" (virt_to_phys(kvm_hyp_pgd)),
		[stack_ptr] "r" (hyp_stack_ptr) :
		"r0", "r1");
}

/**
 * Inits Hyp-mode on all online CPUs
 */
static int init_hyp_mode(void)
{
	phys_addr_t init_phys_addr, init_end_phys_addr;
	int err = 0;
	int cpu;

	/*
	 * Allocate Hyp level-1 page table
	 */
	kvm_hyp_pgd = kzalloc(PTRS_PER_PGD * sizeof(pgd_t), GFP_KERNEL);
	if (!kvm_hyp_pgd)
		return -ENOMEM;

	/*
	 * Allocate stack pages for Hypervisor-mode
	 */
	for_each_possible_cpu(cpu) {
		void *stack_page;

		stack_page = (void *)__get_free_page(GFP_KERNEL);
		if (!stack_page) {
			err = -ENOMEM;
			goto out_free_pgd;
		}

		per_cpu(kvm_arm_hyp_stack_page, cpu) = stack_page;
	}

	init_phys_addr = virt_to_phys(__kvm_hyp_init);
	init_end_phys_addr = virt_to_phys(__kvm_hyp_init_end);
	BUG_ON(init_phys_addr & 0x1f);

	/*
	 * Create identity mapping for the init code.
	 */
	hyp_identity_mapping_add(kvm_hyp_pgd,
				 (unsigned long)init_phys_addr,
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
	hyp_identity_mapping_del(kvm_hyp_pgd,
				 (unsigned long)init_phys_addr,
				 (unsigned long)init_end_phys_addr);

	/*
	 * Map Hyp exception vectors
	 */
	err = create_hyp_mappings(kvm_hyp_pgd,
				  __kvm_hyp_vector, __kvm_hyp_vector_end);
	if (err) {
		kvm_err(err, "Cannot map hyp vector");
		goto out_free_mappings;
	}

	/*
	 * Map the world-switch code
	 */
	err = create_hyp_mappings(kvm_hyp_pgd,
				  __kvm_vcpu_run, __kvm_vcpu_run_end);
	if (err) {
		kvm_err(err, "Cannot map world-switch code");
		goto out_free_mappings;
	}

	/*
	 * Map the Hyp stack pages
	 */
	for_each_possible_cpu(cpu) {
		char *stack_page = per_cpu(kvm_arm_hyp_stack_page, cpu);
		err = create_hyp_mappings(kvm_hyp_pgd,
					  stack_page, stack_page + PAGE_SIZE);

		if (err) {
			kvm_err(err, "Cannot map hyp stack");
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
	for_each_possible_cpu(cpu)
		free_page((unsigned long)per_cpu(kvm_arm_hyp_stack_page, cpu));
out_free_pgd:
	kfree(kvm_hyp_pgd);
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
	return rc;
}

static void __exit arm_exit(void)
{
	kvm_exit();
}

module_init(arm_init);
module_exit(arm_exit)

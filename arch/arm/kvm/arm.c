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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mman.h>
#include <linux/jiffies.h>
#include <linux/kfifo.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <asm/mman.h>

#define DEBUG_INSTR (0xef00babe)

/*
 * Static variables for logging and debugging
 */
u8 guest_debug = 0;
u32 irq_return = 0;
u32 irq_suppress = 0;

#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>

#include "trace.h"

/*
 * Assembly globals
 */
extern u32 __irq_vector_start;
extern u32 __irq_vector_end;

extern u32 __shared_page_start;
extern u32 __shared_page_end;

extern u32 __vcpu_run;
extern u32 __exception_return;
extern void __irq_svc(void);

extern struct kvm_vcpu *latest_vcpu;

/*
 * Function prototypes
 */
static u32		handle_exit(struct kvm_vcpu *vcpu, u32 interrupt);
static inline int	handle_shadow_fault(struct kvm_vcpu *vcpu,
					   gva_t fault_addr, gva_t instr_addr);
void			set_host_kernel_ng(struct kvm_vcpu *vcpu,
					   unsigned int val);


u32 get_shadow_l1_entry(struct kvm_vcpu *vcpu, gva_t gva)
{
	u32 l1_entry;

	l1_entry = *(vcpu->arch.shadow_pgtable->pgd + (gva >> 20));
	return l1_entry;
}

extern int get_l2_base(u32 l1_entry, u32 **l2_base);
u32 get_shadow_l2_entry(struct kvm_vcpu *vcpu, gva_t gva)
{
	u32 l1_entry;
	u32 l2_entry;
	u32 *l2_base;

	l1_entry = *(vcpu->arch.shadow_pgtable->pgd + (gva >> 20));
	BUG_ON((l1_entry & L1_TYPE_MASK) != L1_TYPE_COARSE);

	BUG_ON(get_l2_base(l1_entry, &l2_base));
	l2_entry = *(l2_base + ((gva >> 12) & 0xff));

	return l2_entry;
}

void print_shadow_mapping(struct kvm_vcpu *vcpu, gva_t gva)
{
	u32 l1_entry;

	l1_entry = get_shadow_l1_entry(vcpu, gva);
	kvm_msg("shadow l1_entry: %08x", l1_entry);
	if ((l1_entry & L1_TYPE_MASK) == L1_TYPE_COARSE)
	{
		u32 l2_entry = get_shadow_l2_entry(vcpu, gva);
		kvm_msg("shadow l2_entry: %08x", l2_entry);
	}
}

void print_guest_area(struct kvm_vcpu *vcpu, gva_t gva)
{
	//gva_t gva = (gva_t)(vcpu_reg(vcpu, 15));
	gfn_t gfn;
	gpa_t gpa, from, to;
	int ret;
	void *data;
	u32* ptr;

	/*
	 * For some reason it's necessary to clean the entire D-cache before
	 * we start reading guest page table entries - even though the guest
	 * kernel should flush the write.
	 */
	kvm_dcache_clean();
	ret = gva_to_gfn(vcpu, gva, &gfn, 0, NULL);
	if (ret < 0) {
		kvm_err(ret, "could not translate PC address");
		return;
	}

	if (!kvm_is_visible_gfn(vcpu->kvm, gfn)) {
		kvm_err(-EINVAL, "invalid PC address");
		return;
	}

	from = to = gpa = (gfn << PAGE_SHIFT) | (gva & ~PAGE_MASK);

	/* Print -/+ 10 instructions, but only if in same page */
	while (((from - 4) & PAGE_MASK) == (gpa & PAGE_MASK) && (gpa - from) < 40)
		from = from - 4;
	while (((to + 4) & PAGE_MASK) == (gpa & PAGE_MASK) && (to - gpa) < 40)
		to = to + 4;

	data = kmalloc(84, GFP_KERNEL);
	if (!data) {
		kvm_err(-ENOMEM, "cannot allocate buffer");
		return;
	}

	ret = kvm_read_guest(vcpu->kvm, from, data, to - from);
	if (ret < 0) {
		kvm_err(-EINVAL, "cannot read guest addresses 0x%08x to 0x%08x",
				from, to);
		return;
	}

	gva = gva - (gpa - from);
	ptr = (u32*)data;
	while (from <= to) {
		kvm_msg(" %c  0x%08x: 0x%08x", (from == gpa) ? '>' : '*',
			gva, *(ptr));
		from = from + 4;
		gva = gva + 4;
		ptr++;
	}

	kfree(data);
}

gfn_t unalias_gfn(struct kvm *kvm, gfn_t gfn)
{
	return gfn;
}

int kvm_cpu_has_interrupt(struct kvm_vcpu *v)
{
	if ((v->arch.exception_pending & EXCEPTION_FIQ) ||
	    (v->arch.exception_pending & EXCEPTION_IRQ))
		return 1;
	else
		return 0;
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	return (!v->arch.wait_for_interrupts);
}

void kvm_arch_hardware_enable(void *garbage)
{
	/* No virtualization hardware on ARM yet */
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

struct kvm *kvm_arch_create_vm(void)
{
	struct kvm *kvm;

	kvm = kzalloc(sizeof(struct kvm), GFP_KERNEL);
	if (!kvm)
		return ERR_PTR(-ENOMEM);

	return kvm;
}

void kvm_arch_sync_events(struct kvm *kvm)
{
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	int i;

	for (i = 0; i < KVM_MAX_VCPUS; ++i) {
		if (kvm->vcpus[i]) {
			kvm_arch_vcpu_free(kvm->vcpus[i]);
			kvm->vcpus[i] = NULL;
		}
	}

	kvm_free_physmem(kvm);
	kfree(kvm);
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

void kvm_arch_flush_shadow(struct kvm *kvm)
{
	// XXX Check if this should in fact flush our shadow pg table
}

static pte_t *walk_get_pte(struct mm_struct *mm, hva_t addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	pud = pud_alloc(mm, pgd, addr);
	if (!pud) {
		printk(KERN_ERR "Could not alloc pud!\n");
		return NULL;
	}
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd) {
		printk(KERN_ERR "Could not alloc pmd!\n");
		return NULL;
	}

	pte = pte_alloc_map(mm, pmd, addr);
	if (!pte) {
		printk(KERN_ERR "Could not alloc pte!\n");
		return NULL;
	}

	return pte;
}


static int remap_va_to_pfn(struct mm_struct *mm,
			   hva_t addr,
			   pfn_t pfn,
			   unsigned long prot)
{
	pte_t *page_table;
	pte_t entry;
	struct page *page;
	unsigned long flags;
	unsigned int vm_flags;

	page_table = walk_get_pte(mm, addr);
	if (!page_table)
		return -ENOMEM;

	page = pfn_to_page(pfn);

	flags = MAP_PRIVATE;
	vm_flags = calc_vm_prot_bits(prot) | calc_vm_flag_bits(flags) |
			mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

	entry = mk_pte(page, vm_get_page_prot(vm_flags));
	entry = pte_mkwrite(pte_mkdirty(entry));

	set_pte_at(mm, addr, page_table, entry);

	return 0;
}

static int unmap_va(struct mm_struct *mm, hva_t addr)
{
	pte_t *page_table;

	page_table = walk_get_pte(mm, addr);
	if (!page_table)
		return -ENOMEM;

	pte_clear(mm, addr, page_table);

	return 0;
}

static void config_shared_page_domain(struct mm_struct *mm)
{
	unsigned long irq_flags;
	unsigned long addr;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;

	local_irq_save(irq_flags);

	modify_domain(DOMAIN_KVM, DOMAIN_CLIENT);

	addr = SHARED_PAGE_BASE;
	pgd = pgd_offset(current->mm, addr);
	pmd = pmd_offset(pgd, addr);
	pmd[1] &= (~PMD_DOMAIN(0xf));
	pmd[1] |= PMD_DOMAIN(DOMAIN_KVM);

	if ((pmd[1] & PMD_TYPE_TABLE) != PMD_TYPE_TABLE) {
		kvm_msg("unsupported config for shared page host map");
		return;
	}

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(pte)) {
		kvm_msg("unsupported config for shared page host map");
		return;
	}
	set_pte_ext(pte, *pte, 0);

	clean_dcache_area(pmd + 1, sizeof(pmd_t));
	flush_tlb_kernel_page(addr);

	local_irq_restore(irq_flags);
}

static int check_processor_requirements(void)
{
	u32 ttbr_cr, c1_acr, c13_fcse, c9_tcm;

	/*
	 * TODO: Handle ARMv6 TTBR multiple registers and TTBR CR!
	 */
	asm ("mrc	p15, 0, %[res], c2, c0, 2": [res] "=r" (ttbr_cr));
	if (ttbr_cr != 0) {
		kvm_msg("multiple TTBRs currently not supported");
		return -EINVAL;
	}

	/*
	 * Check cache cleaning functions
	 */
	asm ("mrc	p15, 0, %[res], c1, c0, 1": [res] "=r" (c1_acr));
	if ((c1_acr & 0x10) != 0) {
		kvm_msg("Clean entire data cache disabled!");
		return -EINVAL;
	}

	/*
	 * Check that FCSE is disabled
	 */
	asm ("mrc	p15, 0, %[res], c13, c0, 0": [res] "=r" (c13_fcse));
	if ((c13_fcse & 0xfe000000) != 0) {
		kvm_msg("FCSE is not disabled (PID != 0) aborting");
		return -EINVAL;
	}

	/*
	 * Check the configuration of the TCM
	 */
	asm ("mrc	p15, 0, %[res], c9, c1, 0": [res] "=r" (c9_tcm));
	kvm_msg("Data TCM register:   %08x", c9_tcm);

	asm ("mrc	p15, 0, %[res], c9, c1, 1": [res] "=r" (c9_tcm));
	kvm_msg("Instr. TCM register: %08x", c9_tcm);

	return 0;
}

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	int err;
	pfn_t pfn;
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_arch *arch;
	struct shared_page *shared;
	int shared_code_len;
	int vcpu_run_offset, exception_return_offset;

	check_processor_requirements();

	vcpu = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = kvm_vcpu_init(vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	arch = &vcpu->arch; //alias to make code shorter

	/*
	 * Allocate shared page and map into kernel address space
	 */
	arch->shared_page_alloc = (u32*)__get_free_page(GFP_KERNEL);
	if (!arch->shared_page_alloc) {
		err = -ENOMEM;
		goto free_vcpu;
	}
	SetPageDirty(virt_to_page(arch->shared_page_alloc));
	pfn = page_to_pfn(virt_to_page(arch->shared_page_alloc));

	/*
	 * This mapping will be created as a global mapping (which will
	 * disregard ASID's in the TLB) since set_pte_at does this for
	 * all mappings >= TASK_SIZE (ie. in the kernel space)
	 */
	if (remap_va_to_pfn(&init_mm,
			    SHARED_PAGE_BASE,
			    pfn,
			    PROT_EXEC | PROT_READ | PROT_WRITE) < 0) {
		err = -EFAULT;
		goto free_shared;
	}
	shared_code_len = sizeof(u32) *
		(&__shared_page_end - &__shared_page_start);

	if ((PAGE_SIZE - shared_code_len) < (1<<10)) {
		printk(KERN_ERR "Shared page stack size is less than 2K.\n");
		err = -ENOMEM;
		goto free_shared;
	}


	/*
	 * Relocate code to shared page and setup pointers.
	 */
	arch->shared_page = (struct shared_page*)SHARED_PAGE_BASE;
	memcpy(arch->shared_page, &__shared_page_start, shared_code_len);
	shared = arch->shared_page;

	/* Setup vcpu's pointers into the shared page */
	arch->regs = &(shared->vcpu_regs);
	arch->mode = &(shared->vcpu_mode);
	vcpu_run_offset = &__vcpu_run - &__shared_page_start;
	arch->run = (int(*)(void *))((u32 *)arch->shared_page + vcpu_run_offset);

	/*
	 * Setup shared page stack pointer, return pointer and host kernel SVC
	 * handler address.
	 */
	shared->shared_sp = (u32)((u32 *)arch->shared_page
			+ (PAGE_SIZE / sizeof(u32)));
	shared->shared_sp -= 4;
	*((u32 *)(shared->shared_sp)) = SHARED_PAGE_BASE;
	exception_return_offset = &__exception_return - &__shared_page_start;
	shared->return_ptr = (u32)((u32 *)arch->shared_page
			+ exception_return_offset);
	shared->irq_svc_address = (unsigned long)(&__irq_svc);


	/*
	 * Allocate and set up guest exception vector page
	 */
	arch->guest_vectors = (u32*)__get_free_page(GFP_KERNEL);
	if (!arch->guest_vectors) {
		err = -ENOMEM;
		goto unmap_shared;
	}
	SetPageDirty(virt_to_page(arch->guest_vectors));
	memcpy(arch->guest_vectors, &__irq_vector_start,
		sizeof(u32) * (&__irq_vector_end - &__irq_vector_start));
	vcpu->arch.host_vectors_high = 1;

	/*
	 * Init MMU related structures
	 */
	INIT_LIST_HEAD(&arch->shadow_pgtable_list);
	arch->l2_unused_pt = NULL;

	arch->shadow_pgtable = kvm_alloc_l1_shadow(vcpu, 0);
	if (IS_ERR(arch->shadow_pgtable)) {
		err = PTR_ERR(arch->shadow_pgtable);
		goto free_vectors;
	}

	err = kvm_init_l1_shadow(vcpu, arch->shadow_pgtable);
	if (err)
		goto free_shadow;

	/*
	 * Init execution CPSR
	 */
	shared->execution_CPSR = USR_MODE | (vcpu->arch.regs->cpsr
			     & ~(MODE_MASK | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT));

	/*
	 * Start with guest debugging disabled
	 */
	guest_debug = 0;
	vcpu->arch.shared_page->full_flush_mode = 0;
	latest_vcpu = vcpu;
	kvm_arm_init_eventc();

	config_shared_page_domain(current->mm);

	return vcpu;
free_shadow:
	kvm_free_l1_shadow(vcpu, vcpu->arch.shadow_pgtable);
free_vectors:
	free_pages((u32)arch->guest_vectors, 0);
unmap_shared:
	unmap_va(&init_mm, SHARED_PAGE_BASE);
free_shared:
	free_pages((u32)arch->shared_page_alloc, 0);
free_vcpu:
	kmem_cache_free(kvm_vcpu_cache, vcpu);
out:
	return ERR_PTR(err);
}

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	kvm_shadow_pgtable *shadow, *tmp_shadow_iter;
	//kvm_shadow_pgtable tmp_shadow_iter;
	struct list_head *pgtables;

	latest_vcpu = NULL;

	/* FREE SOME TRANSLATION STRUCTURES HERE */

	/*
	 * Free shadow page tables
	 */
	pgtables = &vcpu->arch.shadow_pgtable_list;
	list_for_each_entry_safe(shadow, tmp_shadow_iter, pgtables, list) {
		kvm_free_l1_shadow(vcpu, shadow);
	}

	/*
	 * Free shared page and kvm host vector page
	 */
	__free_page(virt_to_page(vcpu->arch.shared_page_alloc));
	__free_page(virt_to_page(vcpu->arch.guest_vectors));

	kvm_vcpu_uninit(vcpu);
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
	__u32 control_reg;

	asm volatile ("mrc p15, 0, %[midr], c0, c0, 0\n\t"
		      "mrc p15, 0, %[ctr], c0, c0, 1\n\t"
		      "mrc p15, 0, %[tcmtr], c0, c0, 2\n\t"
		      "mrc p15, 0, %[control], c1, c0, 0" :
		      [midr]  "=r" (vcpu->arch.cp15.c0_MIDR),
		      [ctr]   "=r" (vcpu->arch.cp15.c0_CTR),
		      [tcmtr] "=r" (vcpu->arch.cp15.c0_TCMTR),
		      [control] "=r" (control_reg));

	/*
	 * Set all domains to use client access before the guest
	 * enables the MMU and must have set and overwriten this
	 * virtual register.
	 */
	vcpu->arch.cp15.c3_DACR = 0x55555555;

	/*
	 * Set the control register to the default reset value,
	 * but read the implementation defined bits off the physical
	 * CPU.
	 */
	vcpu->arch.cp15.c1_CR = 0x00050078 | (control_reg & 0x02400080);

	/*
	 * Don't wait for interrupts from the beginning
	 */
	vcpu->arch.wait_for_interrupts = 0;

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

int kvm_arch_vcpu_ioctl_debug_guest(struct kvm_vcpu *vcpu,
				    struct kvm_debug_guest *dbg)
{
	return -ENOTSUPP;
}

/*
 * Return a pointer to the register number valid in the specified mode of
 * the virtual CPU.
 */
u32* kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode)
{
	struct kvm_vcpu_regs *regs;
	u8 reg_idx;
	BUG_ON(reg_num > 15);

	regs = vcpu->arch.regs;

	/* The PC is trivial */
	if (reg_num == 15)
		return &(regs->r15);

	/* Non-banked registers */
	if (reg_num < 8)
		return &(regs->shared_reg[reg_num]);

	/* Banked registers r13 and r14 */
	if (reg_num >= 13) {
		reg_idx = reg_num - 13; /* 0=r13 and 1=r14 */
		switch (mode) {
		case MODE_FIQ:
			return &(regs->banked_fiq[reg_idx]);
		case MODE_IRQ:
			return &(regs->banked_irq[reg_idx]);
		case MODE_SVC:
			return &(regs->banked_svc[reg_idx]);
		case MODE_ABORT:
			return &(regs->banked_abt[reg_idx]);
		case MODE_UNDEF:
			return &(regs->banked_und[reg_idx]);
		case MODE_USER:
		case MODE_SYSTEM:
			return &(regs->banked_usr[reg_idx]);
		}
	}

	/* Banked FIQ registers r8-r12 */
	if (reg_num >= 8 && reg_num <= 12) {
		reg_idx = reg_num - 8; /* 0=r8, ..., 4=r12 */
		if (mode == MODE_FIQ)
			return &(regs->fiq_reg[reg_idx]);
		else
			return &(regs->usr_reg[reg_idx]);
	}

	BUG();
	return NULL;
}

/*
 * Helper function to do what's needed when switching modes
 */
static inline int kvm_switch_mode(struct kvm_vcpu *vcpu, u8 new_cpsr)
{
	u8 new_mode;
	u8 old_mode = VCPU_MODE(vcpu);
	int ret = 0;

	u8 modes_table[16] = {
		MODE_USER,	// 0x0
		MODE_FIQ,	// 0x1
		MODE_IRQ,	// 0x2
		MODE_SVC,	// 0x3
		0xf, 0xf, 0xf,
		MODE_ABORT,	// 0x7
		0xf, 0xf, 0xf,
		MODE_UNDEF,	// 0xb
		0xf, 0xf, 0xf,
		MODE_SYSTEM};	// 0xf

	new_mode = modes_table[new_cpsr & 0xf];
	BUG_ON(new_mode == 0xf);

	if (new_mode == old_mode)
		return 0;

	vcpu->arch.shared_page->vcpu_mode = new_mode;

	if (new_mode == MODE_USER || old_mode == MODE_USER) {
		/* Switch btw. priv. and non-priv. */
		ret = kvm_update_shadow_ap(vcpu, vcpu->arch.shadow_pgtable);

		if (new_mode != MODE_USER)
			kvm_arm_count_event(EVENT_SWITCH_PRIV);
		else
			kvm_arm_count_event(EVENT_SWITCH_PRIV);
	}

	kvm_trace_activity(65, "switch mode");
	kvm_arm_count_event(EVENT_SWITCH_MODE);

	return ret;
}

/*
 * Write to the virtual CPSR.
 * The CPSR should NEVER be written directly!
 */
void kvm_cpsr_write(struct kvm_vcpu *vcpu, u32 new_cpsr)
{
	if ((new_cpsr & MODE_MASK) != (vcpu->arch.regs->cpsr & MODE_MASK)) {
		BUG_ON(kvm_switch_mode(vcpu, new_cpsr));
	}

	BUG_ON((new_cpsr & PSR_N_BIT) && (new_cpsr & PSR_Z_BIT));

	if ((vcpu->arch.regs->cpsr & PSR_I_BIT) != (new_cpsr & PSR_I_BIT))  {
		int status = (new_cpsr & PSR_I_BIT) ? 0 : 1;
		if (status) {
			kvm_trace_activity(61, "IRQs on in guest");
			kvm_arm_count_event(EVENT_VCPU_IRQS_ON);
		} else {
			kvm_trace_activity(60, "IRQs off in guest");
			kvm_arm_count_event(EVENT_VCPU_IRQS_OFF);
		}
	}

	vcpu->arch.regs->cpsr = new_cpsr;
}

static void handle_mmio_return(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	void *dest;
	int len;

	if (!run->mmio.is_write) {
		dest = &(vcpu_reg(vcpu, vcpu->arch.mmio_rd));
		*((u32 *)dest) = 0;
		if ((unsigned int)vcpu->run->mmio.len > 4)
			len = 4;
		else
			len = (unsigned int)vcpu->run->mmio.len;

		memcpy(dest, vcpu->run->mmio.data, len);
	}
}

static int emulate_exception(struct kvm_vcpu *vcpu, u32 new_mode, u32 vector_offset)
{
	int ret;
	int host_high = vcpu->arch.host_vectors_high ? 1 : 0;
	int guest_high = kvm_guest_high_vectors(vcpu) ? 1 : 0;
	int tmp_cpsr;

	/* Change VCPU mode */
	tmp_cpsr = vcpu->arch.regs->cpsr;
	tmp_cpsr = (tmp_cpsr & ~MODE_MASK) | new_mode;
	tmp_cpsr &= ~PSR_T_BIT; /* ARM MODE */
	tmp_cpsr |= PSR_I_BIT; /* disable interrupts */
	kvm_cpsr_write(vcpu, tmp_cpsr);

	vcpu_reg(vcpu, 15) = kvm_guest_vector_base(vcpu) + vector_offset;

	/*
	 * Check if the host exception base is different from
	 * where we are about to execute guest exception handler.
	 */
	if (host_high == guest_high) {
		kvm_msg("switching vectors...");
		ret = kvm_switch_host_vectors(vcpu, guest_high ? 0 : 1);
		if (ret)
			return ret;
	}


	/* Check if the guest handler is mapped in, otherwise map it in */
	//XXX Needs some refactoring of other code for this to be effective
	// but it's essentially an optimization



	return 0;
}

static int inject_guest_exception(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_regs *regs = vcpu->arch.regs;

	/*
	 * The order is important here, as it follows the architecture defined
	 * exception priority.
	 */
	if (vcpu->arch.exception_pending & EXCEPTION_RESET) {
		/* Reset exception not supported */
		return -EINVAL;
	}

	if (vcpu->arch.exception_pending & EXCEPTION_SOFTWARE) {
		//kvm_msg("inject swi: 0x%08x", vcpu_reg(vcpu, 15));
		vcpu_reg_m(vcpu, 14, MODE_SVC) = vcpu_reg(vcpu, 15) + 4;
		vcpu_spsr_m(vcpu, MODE_SVC) = regs->cpsr;

		vcpu->arch.exception_pending &= ~EXCEPTION_SOFTWARE;
		return emulate_exception(vcpu, SVC_MODE, 0x8);
	}

	if (vcpu->arch.exception_pending & EXCEPTION_PREFETCH) {
		//kvm_msg("inject prefetch abort: 0x%08x", vcpu_reg(vcpu, 15));
		vcpu_reg_m(vcpu, 14, MODE_ABORT) = vcpu_reg(vcpu, 15) + 4;
		vcpu_spsr_m(vcpu, MODE_ABORT) = regs->cpsr;

		vcpu->arch.exception_pending &= ~EXCEPTION_PREFETCH;
		return emulate_exception(vcpu, ABT_MODE, 0x0c);
	}

	if (vcpu->arch.exception_pending & EXCEPTION_DATA) {
		//kvm_msg("inject data abort: 0x%08x", vcpu_reg(vcpu, 15));
		vcpu_reg_m(vcpu, 14, MODE_ABORT) = vcpu_reg(vcpu, 15) + 8;
		vcpu_spsr_m(vcpu, MODE_ABORT) = regs->cpsr;

		vcpu->arch.exception_pending &= ~EXCEPTION_DATA;
		return emulate_exception(vcpu, ABT_MODE, 0x10);
	}

	if (vcpu->arch.exception_pending & EXCEPTION_IRQ) {
		if ((regs->cpsr & PSR_I_BIT) || irq_suppress)
			return 0;

		vcpu_reg_m(vcpu, 14, MODE_IRQ) = vcpu_reg(vcpu, 15) + 4;
		vcpu_spsr_m(vcpu, MODE_IRQ) = regs->cpsr;

		return emulate_exception(vcpu, IRQ_MODE, 0x18);
	}

	if (vcpu->arch.exception_pending & EXCEPTION_FIQ) {
		kvm_msg("inject fiq: 0x%08x", vcpu_reg(vcpu, 15));
		if (regs->cpsr & PSR_F_BIT)
			return 0;

		KVMARM_NOT_IMPLEMENTED();
		return -EINVAL;
	}

	return 0;
}


static int pre_guest_switch(struct kvm_vcpu *vcpu)
{
	struct shared_page *shared = vcpu->arch.shared_page;
	kvm_shadow_pgtable *shadow = vcpu->arch.shadow_pgtable;
	int ret;

	if (vcpu->run->exit_reason == KVM_EXIT_MMIO) {
		handle_mmio_return(vcpu, vcpu->run);
	}

	if (vcpu->arch.exception_pending) {
		ret = inject_guest_exception(vcpu);
		if (ret)
			return ret;
	}

	/* Copy only the COND bits over to the execution CPSR */
	shared->execution_CPSR = (shared->execution_CPSR & ~0xf1000000) |
					(vcpu->arch.regs->cpsr &  0xf1000000);

#ifdef CONFIG_CPU_HAS_ASID
		/* Set the shadow ASID and copy the TTBR */
		if (unlikely((shadow->id ^ cpu_last_asid) >> ASID_BITS))
			shadow->id = __new_asid();
		shared->guest_asid = shadow->id;
		shared->host_asid = current->mm->context.id;
#endif
	shared->shadow_ttbr = shadow->pa;

	/* Make sure that interrupts are enabled and guest is in user mode */
	shared->execution_CPSR &= ~PSR_I_BIT;
	shared->execution_CPSR |= PSR_F_BIT;
	shared->execution_CPSR &= ~MODE_MASK;
	shared->execution_CPSR |= USR_MODE;

	/*
	 * Make sure the special domain for shared page and irq vector
	 * always use the client setting.
	 */
	shared->guest_dac = (vcpu->arch.cp15.c3_DACR & 0x3fffffff)
		| domain_val(DOMAIN_KVM, DOMAIN_CLIENT);

	kvm_trace_activity(1, "before vcpu->arch.run(vcpu)");
	kvm_arm_count_event(EVENT_GUEST_ENTER);

	trace_ws_enter(vcpu_reg(vcpu, 15));

	return 0;
}

static void post_guest_switch(struct kvm_vcpu *vcpu, u32 excpt_idx)
{
	struct shared_page *shared = vcpu->arch.shared_page;

	kvm_trace_activity(2, "after vcpu->arch.run(vcpu)");
	kvm_arm_count_event(EVENT_GUEST_ENTER);

	/* Copy only the condition bits for now */
	vcpu->arch.regs->cpsr = (vcpu->arch.regs->cpsr & ~0xf1000000) |
					(shared->execution_CPSR & 0xf1000000);

	trace_ws_exit(vcpu_reg(vcpu, 15), excpt_idx);
}

void debug_exit_print(struct kvm_vcpu *vcpu, u32 interrupt)
{
	switch (interrupt) {
	case ARM_EXCEPTION_UNDEFINED: {
		__kvm_print_msg("UNDEFINED (0x%08x)\n", vcpu_reg(vcpu, 15));
		kvm_msg("undefined instr: %08x",
				vcpu->arch.shared_page->guest_instr);
		break;
	}
	case ARM_EXCEPTION_SOFTWARE: {
		__kvm_print_msg("SWI (0x%08x)\n", vcpu_reg(vcpu, 15));
		break;
	}
	case ARM_EXCEPTION_PREF_ABORT:
		__kvm_print_msg("PREFETCH ABT (0x%08x)\n", vcpu_reg(vcpu, 15));
		break;
	case ARM_EXCEPTION_DATA_ABORT:
		__kvm_print_msg("DATA ABT (0x%08x)\n", vcpu_reg(vcpu, 15));
		break;
	case ARM_EXCEPTION_IRQ:
		__kvm_print_msg("IRQ (0x%08x)\n", vcpu_reg(vcpu, 15));
		break;
	default:
		__kvm_print_msg("BAD EXCPTN (0x%08x)\n", vcpu_reg(vcpu, 15));
		break;
	}

	return;
}

#if 0
int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg)
{
	/*
	 * This test implementation is not stable as it doesn't consider
	 * user space enabling several breakpoints and thereby doesn't save
	 * the original instructions and doesn't support disabling the
	 * breakpoints again - if that at all is the idea between the ioctl!
	 */

	int ret;
	u32 guest_instr;
	gva_t gva = (gva_t)(dbg->arch.bp);
	gfn_t gfn;
	gpa_t gpa;

	/*
	 * For some reason it's necessary to clean the entire D-cache before
	 * we start reading guest page table entries - even though the guest
	 * kernel should flush the write.
	 */
	kvm_dcache_clean();
	ret = gva_to_gfn(vcpu, gva, &gfn, 0, NULL);
	if (ret < 0) {
		kvm_err(ret, "could not translate breakpoing address");
		return ret;
	}

	if (!kvm_is_visible_gfn(vcpu->kvm, gfn)) {
		kvm_err(-EINVAL, "invalid breakpoint address");
		return -EINVAL;
	}

	gpa = (gfn << PAGE_SHIFT) | (gva & ~PAGE_MASK);

	if (kvm_debug_enabled && !dbg->arch.enabled)
	ret = kvm_write_guest(vcpu->kvm, gpa, &bp_instr, 4);
	if (ret) {
		kvm_err(ret, "could not write guest breakpoint!");
		return ret;
	}
	return 0;
}
#endif

static void set_section_ng_bits(pmd_t *pmd, unsigned int val)
{
	if (val == 0) {
		*pmd &= (~PMD_SECT_nG);
	} else {
		*pmd |= PMD_SECT_nG;
	}
}

static void set_table_ng_bits(pmd_t *pmd, unsigned long start, unsigned int val)
{
	pte_t *pte;
	unsigned long addr = start;

	while (addr < (start + PMD_SIZE)) {
		pte = pte_offset_kernel(pmd, addr);
		if (!pte_none(pte) && (addr != SHARED_PAGE_BASE))
			set_pte_ext(pte, *pte, (val) ? PTE_EXT_NG : 0);
		addr = addr + PAGE_SIZE;
	}
}

void set_host_kernel_ng(struct kvm_vcpu *vcpu, unsigned int val)
{
	unsigned long irq_flags;
	unsigned long addr;
	pgd_t *pgd;
	pmd_t *pmd;

	val = (val) ? 1 : 0;
	local_irq_save(irq_flags);
	current->mm->kvm_flags = val;

	addr = TASK_SIZE;
	while (addr <= 0xffe00000 && addr > 0x0) {
		pgd = pgd_offset(current->mm, addr);
		pmd = pmd_offset(pgd, addr);

		do {
			if ((*pmd & PMD_TYPE_MASK) == PMD_TYPE_SECT)
				set_section_ng_bits(pmd, val);
			else if ((*pmd & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
				set_table_ng_bits(pmd, addr, val);
		} while (pmd++ == pmd_offset(pgd, addr));

		addr = (addr + PMD_SIZE) & PMD_MASK;
	}

	/*
	 * TODO: Consider if it's more effective only to flush the kernel
	 * range here
	 */
	asm __volatile__("mcr p15, 0, %[zero], c7, c10, 0": : [zero] "r" (0));
	flush_tlb_all();
	local_irq_restore(irq_flags);
}


int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret = 0;
	int excpt_idx;
	int pending_write = 0;
	unsigned long irq_flags;

	vcpu_load(vcpu);

	vcpu->arch.kvm_run = run;
	flush_dcache_page(virt_to_page(run));

	if (run->exit_reason == KVM_EXIT_IRQ_WINDOW_OPEN)
		run->exit_reason = KVM_EXIT_UNKNOWN;

	for (;;) {
		if (vcpu->arch.wait_for_interrupts) {
			kvm_trace_activity(10, "skip guest_enter (WFI)");
			goto wait_for_interrupts;
		}

		ret = pre_guest_switch(vcpu);
		if (ret < 0)
			break;

		run->exit_reason = KVM_EXIT_UNKNOWN;

		if (guest_debug) {
			__kvm_msg("ENTER VCPU: %08x -->  ", vcpu_reg(vcpu, 15));
			pending_write = 1;
		}

		kvm_guest_enter();
		raw_local_irq_save(irq_flags);

		/*
		 * vcpu->arch.run(...) function pointer value is setup in
		 * kvm_arch_vcpu_create(...)
		 */
		excpt_idx = vcpu->arch.run(vcpu);

		raw_local_irq_restore(irq_flags);
		kvm_guest_exit();

		vcpu->arch.guest_exception = excpt_idx;
		post_guest_switch(vcpu, excpt_idx);

		if (pending_write) {
			debug_exit_print(vcpu, excpt_idx);
			pending_write = 0;
		}

		ret = handle_exit(vcpu, excpt_idx);
		if (ret) {
			break;
		}

		if (run->exit_reason == KVM_EXIT_MMIO)
			break;

		if (need_resched()) {
			kvm_arm_count_event(EVENT_VCPU_BLOCK);
			vcpu_put(vcpu);
			schedule();
			vcpu_load(vcpu);
		}
wait_for_interrupts:
		if (vcpu->arch.wait_for_interrupts) {
			kvm_arm_count_event(EVENT_VCPU_BLOCK);
			kvm_trace_activity(11, "before kvm_vcpu_block(vcpu)");
			kvm_vcpu_block(vcpu);
			kvm_trace_activity(12, "after kvm_vcpu_block(vcpu)");
		}

		if (signal_pending(current) && !(run->exit_reason)) {
			kvm_arm_count_event(EVENT_IRQ_WINDOW);
			kvm_trace_activity(20, "exit KVM_EXIT_IRQ_WINDOW_OPEN");
			run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
			break;
		}
	}

	if (ret < 0)
		run->exit_reason = KVM_EXIT_EXCEPTION;

	flush_dcache_page(virt_to_page(run));
	vcpu_put(vcpu);

	return ret;
}

static inline int handle_undefined(struct kvm_vcpu *vcpu)
{
	int ret;
	u32 instr;

	instr = vcpu->arch.shared_page->guest_instr;

	ret = kvm_handle_undefined(vcpu, instr);
	return ret;
}

static inline int handle_swi(struct kvm_vcpu *vcpu)
{
	gva_t addr;
	hva_t hva;
	u32 instr, orig_instr;
	int ret;

	addr = vcpu_reg(vcpu, 15);

	instr = vcpu->arch.shared_page->guest_instr;
	if ((instr & 0xffff) == 0xdead || (instr & 0xffff) == 0xbabe ||
	    (instr & 0xffff) == 0xcafe || (instr & 0xffff) == 0xbeef ||
	    ((instr & 0xffff) >= 0xde00 && (instr & 0xffff) < 0xef00)) {

		/*kvm_msg("swi instr: 0x%08x at 0x%08x",
				(unsigned int)instr,
				(unsigned int)addr);*/


		if ((instr & 0xffff) == 0xdead) {
			kvm_msg("XXXXXXXXXXX    Exit point found    XXXXXXXXXXXXX!");
			return -EINVAL;
		} else if ((instr & 0xffff) >= 0xde00 && (instr & 0xffff) < 0xef00) {
			kvm_msg("instr: swi%x: ", (instr & 0xffff));
		} else if ((instr & 0xffff) == 0xcafe) {
			kvm_msg("register 7 on 0xcafe: %d", vcpu_reg(vcpu, 7));
		} else if ((instr & 0xffff) == 0xbabe) {
			/* 0xbabe toggles debugging on/off */
			guest_debug ^= 0x1;
			kvm_msg("debugging %s", (guest_debug) ? "on" : "off");
		} else if ((instr & 0xffff) == 0xbeef) {
			irq_suppress ^= 1;
			kvm_msg("IRQ injection is not %s",
					(irq_suppress) ? "off" : "on");
		}

		/* Proceed to next instruction */
		vcpu_reg(vcpu, 15) += 4;
		return 0;
	}

	if ((instr & 0xffff) != 0xaaaa || VCPU_MODE(vcpu) == MODE_USER) {
		/* This is an actual guest SWI instruction */
		vcpu->arch.exception_pending |= EXCEPTION_SOFTWARE;
		if (guest_debug)
			kvm_msg("Guest needs SWI at: 0x%08x\n", vcpu_reg(vcpu, 15));
		vcpu->arch.exception_pending |= EXCEPTION_SOFTWARE;
	} else {
		/* An instruction that needs to be emulated */
		orig_instr = vcpu->arch.shared_page->orig_instr;
		if (orig_instr != 0)
			goto skip_copy_in;

		/* Load the orig. instruction directly from memory */
		/*
		 * For some reason it's necessary to clean the entire D-cache before
		 * we start reading guest page table entries - even though the guest
		 * kernel should flush the write.
		 */
		kvm_dcache_clean();
		hva = gva_to_hva(vcpu, addr + 4, 0);
		if (kvm_is_error_hva(hva)) {
			kvm_err(-EINVAL, "Instruction generated at "
					 "bad address: %08x",
					vcpu_reg(vcpu, 15));
			return -EINVAL;
		}
		/*
		 * Since the instruction is readily a part of the instruction
		 * stream, we can copy from the guest without having to clean
		 * any cache entries, as long as we invalidate cache entries on
		 * our side.
		 */
		kvm_cache_inv_user((void *)hva, sizeof(u32));
		ret = copy_from_user(&orig_instr, (void *)hva, sizeof(u32));
		if (ret)
			return -EFAULT;

skip_copy_in:
		ret = kvm_emulate_sensitive(vcpu, orig_instr);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 * Handle a fault which the guest maps to a physical address belonging
 * to user allocated memory.
 */
static inline int user_mem_abort(struct kvm_vcpu *vcpu,
			  gva_t instr_addr,
			  gva_t fault_addr,
			  gfn_t gfn,
			  struct kvm_memory_slot *memslot,
			  struct map_info *map_info)
{
	int ret;
	pfn_t pfn;

	pfn = gfn_to_pfn(vcpu->kvm, gfn);

	if (pfn == bad_pfn) {
		kvm_err(-EFAULT, "Guest gfn %u (0x%08x) does not have "
				"corresponding host mapping",
				(unsigned int)gfn,
				(unsigned int)gfn << PAGE_SHIFT);
		kvm_release_pfn_clean(pfn);
		return -EFAULT;
	}

	/* Check if we have a domain conflict */
	if (map_info->domain_number == DOMAIN_KVM) {
		/* Could be solved with AP's */
		KVMARM_NOT_IMPLEMENTED();
	}

	map_info->ap = convert_guest_to_shadow_ap(vcpu, map_info->ap);
	ret = __map_gva_to_pfn(vcpu,
			       vcpu->arch.shadow_pgtable->pgd,
			       fault_addr,
			       pfn,
			       map_info->domain_number,
			       map_info->ap,
			       map_info->apx,
			       map_info->xn,
			       map_info->cache_bits);
	if (ret) {
		kvm_release_pfn_clean(pfn);
		return ret;
	}

	/*
	 * If it was merely a question of a translation fault, it
	 * should always be possible to map the correct addresses
	 * in the shadow page table and repeat the instruction.
	 */
	vcpu_reg(vcpu, 15) = instr_addr;
	return 0;
}

/*
 * Handle a fault which the guest maps to a physical area not belonging
 * to user allocated memory, such as MMIO requests. We must trap to the
 * user space application for emulation in this case.
 */
static inline int io_mem_abort(struct kvm_vcpu *vcpu,
			       gva_t instr_addr,
			       gva_t fault_addr,
			       gfn_t gfn)
{
	u32 fault_instr;
	gpa_t mmio_addr;
	u8 rd;
	u32 len;
	int write = 0;

	fault_instr = vcpu->arch.shared_page->guest_instr;
#if 0
	ret = get_exception_instr(vcpu, instr_addr, &fault_instr);
	if (ret) {
		kvm_err(ret, "could not get exception instr");
		return ret;
	}
#endif

	write = kvm_ls_is_write(vcpu, fault_instr);
	rd = kvm_ls_get_rd(vcpu, fault_instr);
	kvm_ls_emulate_writeback(vcpu, fault_instr);

	mmio_addr = (gfn << PAGE_SHIFT) + (fault_addr % PAGE_SIZE);
	len = kvm_ls_length(vcpu, fault_instr);

	vcpu->run->mmio.is_write = write;
	vcpu->run->mmio.phys_addr = mmio_addr;
	vcpu->run->mmio.len = len;

	vcpu->run->exit_reason = KVM_EXIT_MMIO;
	vcpu->arch.mmio_rd = rd;

	if (write) {
		memcpy(vcpu->run->mmio.data, &vcpu_reg(vcpu, rd), len);
	}

	/*
	 * The MMIO instruction is emulated and should not be re-executed
	 * in the guest.
	 */
	vcpu_reg(vcpu, 15) = instr_addr + 4;
	return 0;
}


static inline int handle_shadow_fault(struct kvm_vcpu *vcpu,
				      gva_t fault_addr, gva_t instr_addr)
{
	gfn_t gfn;
	int fault;
	struct kvm_memory_slot *memslot;
	struct map_info map_info;
	u8 uaccess;

	uaccess = VCPU_MODE_PRIV(vcpu) ? 0 : 1;

	/*
	 * For some reason it's necessary to clean the entire D-cache before
	 * we start reading guest page table entries - even though the guest
	 * kernel should flush the write.
	 */
	kvm_dcache_clean();
	fault = gva_to_gfn(vcpu, fault_addr, &gfn, uaccess, &map_info);
	if (fault < 0)
		return fault;

	BUG_ON(vcpu == NULL);
	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	if (!memslot) {
		/*
		 * All accesses to non-registered guest physical memory should
		 * go to QEMU. However, if the access would have generated a
		 * fault, we simply inject that fault to the guest.
		 */
		if (fault > 0) {
			kvm_generate_mmu_fault(vcpu, fault_addr, fault,
					       map_info.domain_number);
			return 0;
		} else {
			return io_mem_abort(vcpu, instr_addr, fault_addr, gfn);
		}
	} else {
		/*
		 * The guest physical address belongs to a registered memory
		 * region and we create the right mapping.
		 */
		BUG_ON(!memslot->user_alloc);
		return user_mem_abort(vcpu, instr_addr, fault_addr,
				      gfn, memslot, &map_info);
	}
}

int handle_shadow_perm(struct kvm_vcpu *vcpu,
				      gva_t fault_addr, gva_t instr_addr)
{
	int high;
	gfn_t gfn;
	u8 uaccess;
	struct map_info map_info;
	int ret = 0;
	u32 fsr;

	if (!vcpu->arch.host_vectors_high &&
		(fault_addr >> PAGE_SHIFT) == (0xffff0000 >> PAGE_SHIFT) &&
		VCPU_MODE_PRIV(vcpu)) {

		kvm_msg("Privileged mode cannot access vector page. "
			"Guest must be broken or we have a bug.");
		kvm_msg("    guest PC was: 0x%08x", vcpu_reg(vcpu, 15));
		kvm_msg("    fault_addr:   0x%08x", fault_addr);

		fsr = vcpu->arch.host_ifsr;
		kvm_msg("    ifsr: 0x%08x", fsr);
		fsr = vcpu->arch.host_fsr;
		kvm_msg("    fsr: 0x%08x", fsr);

		kvm_msg("    guest_exception: %d", vcpu->arch.guest_exception);
		vcpu_put(vcpu);
		kvm_dump_vcpu_state();
		vcpu_load(vcpu);

		/********** Print guest mapping info *********/
		kvm_msg("\n");
		kvm_msg("Guest mapping info:");

		/*
		 * For some reason it's necessary to clean the entire D-cache before
		 * we start reading guest page table entries - even though the guest
		 * kernel should flush the write.
		 */
		kvm_dcache_clean();
		trace_gva_to_gfn = true;
		ret = gva_to_gfn(vcpu, fault_addr, &gfn, 0, &map_info);
		trace_gva_to_gfn = false;

		if (kvm_is_visible_gfn(vcpu->kvm, gfn))
			kvm_msg("     gfn: %u", gfn);
		else
			kvm_msg("     gfn: invisible");

		kvm_msg("\n");
		kvm_msg("Shadow mapping info:");
		print_shadow_mapping(vcpu, fault_addr);

		kvm_msg("     return val: %d", ret);
		/*********************************************/
		return -EINVAL;
	}

	if ((fault_addr >> PAGE_SHIFT) ==
		(kvm_host_vector_base(vcpu) >> PAGE_SHIFT)) {

		/* The guest tried to access the host interrupt page */
		high = vcpu->arch.host_vectors_high ? 0 : 1;
		kvm_msg("switching vectors...");
		ret = kvm_switch_host_vectors(vcpu, high);
		if (ret)
			goto out;
		ret = handle_shadow_fault(vcpu, fault_addr, instr_addr);
		if (ret)
			kvm_msg("error in handle_shadow_fault");
		goto out;
	}

	/* Guest should never access the shared page */
	if ((fault_addr >> PAGE_SHIFT) == (SHARED_PAGE_BASE >> PAGE_SHIFT)) {
		kvm_msg("guest accesses shared page at: 0x%08x", vcpu_reg(vcpu, 15));
		return -EINVAL;
	}

	uaccess = VCPU_MODE_PRIV(vcpu) ? 0 : 1;

	/*
	 * For some reason it's necessary to clean the entire D-cache before
	 * we start reading guest page table entries - even though the guest
	 * kernel should flush the write.
	 */
	kvm_dcache_clean();
	ret = gva_to_gfn(vcpu, fault_addr, &gfn, uaccess, &map_info);
	if (ret < 0) {
		kvm_msg("error in gva_to_gfn");
		goto out;
	}
	//BUG_ON(!write && ret == 0); //Why did we take a permission fault then?

	/* So this should of course only happen if the guest actually
	 * should take a fault here! */
	kvm_generate_mmu_fault(vcpu, fault_addr, vcpu->arch.host_fsr,
			       map_info.domain_number);
	ret = 0;
out:
	if (ret) {
		kvm_err(ret, "error handling shadow page table permissions");
		BUG();
	}
	return ret;
}

static inline int handle_abort(struct kvm_vcpu *vcpu, u32 interrupt)
{
	int ret;
	gva_t fault_addr;
	gva_t instr_addr;
	u32 fsr;

	if (interrupt == ARM_EXCEPTION_DATA_ABORT) {
		fault_addr = vcpu->arch.host_far;
		instr_addr = vcpu_reg(vcpu, 15);
		fsr = vcpu->arch.host_fsr;
	} else {
		/*
		 * WARNING: The Android emulator stores the reason for a fault
		 * in the IFSR, but that's actually implementation defined
		 * before ARMv6, so if we plan on continue support for this
		 * older architecture, this logic should really be based on
		 * something else (like checking the shadow page table
		 * entry)
		 */
		fsr = vcpu->arch.host_ifsr;
		instr_addr = fault_addr = vcpu_reg(vcpu, 15);
	}

	switch (fsr & FSR_TYPE_MASK) {
	case (FSR_ALIGN_FAULT):
		ret = -EINVAL;
		kvm_err(ret, "Modified virtual address alignment fault\n");
		return ret;
	case (FSR_PERM_SEC):
	case (FSR_PERM_PAGE):
		ret = handle_shadow_perm(vcpu, fault_addr, instr_addr);
		break;
	case (FSR_DOMAIN_SEC):
	case (FSR_DOMAIN_PAG):
		ret = handle_shadow_perm(vcpu, fault_addr, instr_addr);
		break;
	case (FSR_TRANS_SEC):
	case (FSR_TRANS_PAGE):
		/*
		 * This would be caused by a missing shadow page table entry
		 */
		ret =  handle_shadow_fault(vcpu, fault_addr, instr_addr);
		break;
	case (FSR_EXT_ABORT_L1):
	case (FSR_EXT_ABORT_L2):
		ret = -EINVAL;
		kvm_err(ret, "External abort: Not supported");
		return ret;
	default:
		ret = -EINVAL;
		kvm_msg("Unknown data abort reason: FSR: 0x%08x\n",
				  (unsigned int) fsr);
	}

	return ret;
}

static u32 handle_exit(struct kvm_vcpu *vcpu, u32 interrupt)
{
	int ret;

	switch (interrupt) {
	case ARM_EXCEPTION_UNDEFINED: {
		ret = handle_undefined(vcpu);
		if (ret)
			return ret;
		break;
	}
	case ARM_EXCEPTION_SOFTWARE: {
		ret = handle_swi(vcpu);
		if (ret < 0)
			return ret;
		break;
	}
	case ARM_EXCEPTION_PREF_ABORT:
		ret = handle_abort(vcpu, interrupt);
		if (ret)
			return ret;
		break;
	case ARM_EXCEPTION_DATA_ABORT:
		ret = handle_abort(vcpu, interrupt);
		if (ret)
			return ret;
		break;
	case ARM_EXCEPTION_IRQ:
		if (vcpu_reg(vcpu, 15) > 0x00368800 &&
		    vcpu_reg(vcpu, 15) < 0x003688ff) {
			kvm_msg("irq at: 0x%08x", vcpu_reg(vcpu, 15));
		}
		break;
	default:
		kvm_err(-EINVAL, "VCPU: Bad exception code: %d", interrupt);
		return -EINVAL;
	}

	if (ret < 0)
		return ret;
	return 0;
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

	if (intr->raise) {
		if (mask == EXCEPTION_IRQ)
			kvm_trace_activity(101, "raise IRQ");
		else if (mask == EXCEPTION_FIQ)
			kvm_trace_activity(102, "raise FIQ");
		vcpu->arch.exception_pending |= mask;
		vcpu->arch.wait_for_interrupts = 0;
	} else {
		if (mask == EXCEPTION_IRQ)
			kvm_trace_activity(103, "lower IRQ");
		else if (mask == EXCEPTION_FIQ)
			kvm_trace_activity(104, "lower FIQ");

		vcpu->arch.exception_pending &= ~mask;
	}

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

int kvm_arch_init(void *opaque)
{
	return 0;
}

void kvm_arch_exit(void)
{
}

static int k_show(struct seq_file *m, void *v)
{
	print_kvm_debug_info(&seq_printf, m);
	return 0;
}

static void *k_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *k_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void k_stop(struct seq_file *m, void *v)
{
}

static const struct seq_operations kvmproc_op = {
	.start	= k_start,
	.next	= k_next,
	.stop	= k_stop,
	.show	= k_show
};

static int kvm_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &kvmproc_op);
}

static const struct file_operations proc_kvm_operations = {
	.open		= kvm_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int arm_init(void)
{
	int rc = kvm_init(NULL, sizeof(struct kvm_vcpu), THIS_MODULE);
	if (rc == 0)
		proc_create("kvm", 0, NULL, &proc_kvm_operations);
	return rc;
}

static void __exit arm_exit(void)
{
	kvm_exit();
}

module_init(arm_init);
module_exit(arm_exit)

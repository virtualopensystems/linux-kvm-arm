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

#include <linux/autoconf.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/jiffies.h>
#include <linux/kfifo.h>
#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <asm/mman.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>

u8 guest_debug = 1;
u8 page_debug = 0;
u32 irq_return = 0;
u32 irq_suppress = 0;

static u32        handle_exit(struct kvm_vcpu *vcpu, u32 interrupt);
static int        pre_guest_switch(struct kvm_vcpu *vcpu);
static void       post_guest_switch(struct kvm_vcpu *vcpu);
static inline int handle_shadow_fault(struct kvm_vcpu *vcpu,
				      gva_t fault_addr, gva_t instr_addr);

#define TMP_LOG_LEN 512
static char __tmp_log_data[TMP_LOG_LEN];
DEFINE_MUTEX(__tmp_log_lock);

static const u32 bp_instr = 0xef00babe;
static unsigned int bp_offset = 4;


extern void print_guest_mapping(struct kvm_vcpu *vcpu, gva_t gva);

void __kvm_print_msg(char *fmt, ...)
{
	va_list ap;
	int ret = 0;
	unsigned int size;

	mutex_lock(&__tmp_log_lock);

	va_start(ap, fmt);
	size = vsnprintf(__tmp_log_data, TMP_LOG_LEN, fmt, ap);
	va_end(ap);

	if (size >= TMP_LOG_LEN)
		printk(KERN_ERR "kvm_msg exceeded possible temporary buffer size\n");
	else
		printk(KERN_ERR "%s", __tmp_log_data);

	mutex_unlock(&__tmp_log_lock);
}

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

static int guest_wrote_vec = 0;

gfn_t unalias_gfn(struct kvm *kvm, gfn_t gfn)
{
	return gfn;
}

int kvm_cpu_has_interrupt(struct kvm_vcpu *v)
{
	return 1;
}

int kvm_arch_vcpu_runnable(struct kvm_vcpu *v)
{
	return 1;
}

void kvm_arch_hardware_enable(void *garbage)
{
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

static int dump_kvm_log(void __user *buffer)
{
	int size, ret;
	
	if (kfifo_len(__kvm_log) == 0) {
		ret = wait_event_interruptible(__kvm_log_wait_queue,
					       kfifo_len(__kvm_log) > 0);
		if (ret < 0)
			return ret;
	}

	size = kfifo_get(__kvm_log, __tmp_log, KVM_LOG_LEN);
	ret = copy_to_user(buffer, __tmp_log, size);
	if (ret)
		return -EFAULT;

	return size;
}

long kvm_arch_dev_ioctl(struct file *filp,
                        unsigned int ioctl, unsigned long arg)
{
	int ret = 0;

	switch (ioctl) {
	case KVM_ARM_DEBUG_GUEST:
		//guest_debug = guest_debug ? 0 : 1;
		bp_offset = arg;
		ret = bp_offset;
		break;
	case KVM_ARM_DUMP_LOG:
		ret = dump_kvm_log((void *) arg);
		break;
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

struct kvm_vcpu *kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	int err;
	pfn_t pfn;
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu_arch *arch;
	struct shared_page *shared;
	int shared_code_len;
	int vcpu_run_offset, exception_return_offset;

	guest_wrote_vec = 0;

	vcpu = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	if (!vcpu) {
		err = -ENOMEM;
		goto out;
	}

	err = kvm_vcpu_init(vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	arch = &vcpu->arch; //alias to make code shorter

#ifdef KVMARM_BIN_TRANSLATE 
	/*
	 * Init translation structures
	 */
	INIT_LIST_HEAD(&arch->trans_head);
	INIT_LIST_HEAD(&arch->trans_orig);
#endif

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
	 * Copy kernel IRQ handler to shared page to make code relocatable
	 */
	__copy_irq_svc_address();

	/*
	 * Relocate code to shared page and setup pointers.
	 */
	arch->shared_page = (struct shared_page*)SHARED_PAGE_BASE;
	memcpy(arch->shared_page, &__shared_page_start, shared_code_len);
	shared = arch->shared_page;

	shared->shared_sp = (u32)((u32 *)arch->shared_page
			+ (PAGE_SIZE / sizeof(u32)));
	exception_return_offset = &__exception_return - &__shared_page_start;
	shared->return_ptr = (u32)((u32 *)arch->shared_page
			+ exception_return_offset);
	vcpu_run_offset = &__vcpu_run - &__shared_page_start;
	arch->run = (int(*)(void *))((u32 *)arch->shared_page + vcpu_run_offset);

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

	err = kvm_init_l1_shadow(vcpu, arch->shadow_pgtable->pgd);
	if (err)
		goto free_shadow;

	/*
	 * Init execution CPSR
	 */
	shared->guest_CPSR = USR_MODE | (vcpu->arch.cpsr 
			     & ~(MODE_MASK | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT));

	/*
	 * Start with guest debugging disabled
	 */
	guest_debug = 0;

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
 * Helper function to do what's needed when switching modes
 */
static inline int kvm_switch_mode(struct kvm_vcpu *vcpu, u8 new_cpsr)
{
	u8 new_mode;
	u8 old_mode = vcpu->arch.mode;
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
	BUG_ON(new_mode == old_mode);

	if (new_mode == MODE_USER || old_mode == MODE_USER) {
		/* Switch btw. priv. and non-priv. */
		ret = kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable->pgd);
	}
	vcpu->arch.mode = new_mode;

	if (new_mode == MODE_USER) {
		//printk(KERN_ERR "    warning: Guest switched to user mode!\n");
		//guest_debug = 1;
	} else if (new_mode != MODE_USER && old_mode == MODE_USER) {
		//printk(KERN_ERR "    warning: Guest switched to privileged mode!\n");
	}

	return ret;
}

/*
 * Write to the virtual CPSR.
 * The CPSR should NEVER be written directly!
 */
void kvm_cpsr_write(struct kvm_vcpu *vcpu, u32 new_cpsr)
{
	if ((new_cpsr & MODE_MASK) != (vcpu->arch.cpsr & MODE_MASK)) {
		BUG_ON(kvm_switch_mode(vcpu, new_cpsr));
	}

	BUG_ON((new_cpsr & PSR_N_BIT) && (new_cpsr & PSR_Z_BIT));

	vcpu->arch.cpsr = new_cpsr;
}

static void handle_mmio_return(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	void *dest;
	int len;

	if (!run->mmio.is_write) {
		dest = kvm_vcpu_reg(&vcpu->arch, vcpu->arch.mmio_rd);
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
	tmp_cpsr = vcpu->arch.cpsr;
	tmp_cpsr = (tmp_cpsr & ~MODE_MASK) | new_mode;
	tmp_cpsr &= ~PSR_T_BIT; /* ARM MODE */
	tmp_cpsr |= PSR_I_BIT; /* disable interrupts */
	kvm_cpsr_write(vcpu, tmp_cpsr);

	vcpu->arch.regs[15] = kvm_guest_vector_base(vcpu) + vector_offset;

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
	/*
	 * The order is important here, as it follows the architecture defined
	 * exception priority.
	 */

	/*
	if (guest_debug) {
		irq_return = vcpu->arch.regs[15];
		guest_debug = 0;
		irq_suppress = 1;
	}
	*/

	if (vcpu->arch.exception_pending & EXCEPTION_RESET) {
		/* Reset exception not supported */
		return -EINVAL;
	}

	if (vcpu->arch.exception_pending & EXCEPTION_SOFTWARE) {
		//kvm_msg("inject swi");
		vcpu->arch.banked_r14[MODE_SVC] = vcpu->arch.regs[15] + 4;
		vcpu->arch.banked_spsr[MODE_SVC] = vcpu->arch.cpsr;

		vcpu->arch.exception_pending &= ~EXCEPTION_SOFTWARE;
		return emulate_exception(vcpu, SVC_MODE, 0x8);
	}
	
	if (vcpu->arch.exception_pending & EXCEPTION_PREFETCH) {
<<<<<<< HEAD
		kvm_msg("inject prefetch abort");
=======
		u32 l2_pte;

		//kvm_msg("inject prefetch abort");
		l2_pte = get_shadow_l2_entry(vcpu, 0xffff0000);
		//kvm_msg("    l2_pte: 0x%08x\n", l2_pte);
>>>>>>> 3605bc3... Changed debugging back to simple printk
		vcpu->arch.banked_r14[MODE_ABORT] = vcpu->arch.regs[15] + 4;
		vcpu->arch.banked_spsr[MODE_ABORT] = vcpu->arch.cpsr;

		vcpu->arch.exception_pending &= ~EXCEPTION_PREFETCH;
		return emulate_exception(vcpu, ABT_MODE, 0x0c);
	}

	if (vcpu->arch.exception_pending & EXCEPTION_DATA) {
		//kvm_msg("inject data abort");
		vcpu->arch.banked_r14[MODE_ABORT] = vcpu->arch.regs[15] + 8;
		vcpu->arch.banked_spsr[MODE_ABORT] = vcpu->arch.cpsr;

		vcpu->arch.exception_pending &= ~EXCEPTION_DATA;
		return emulate_exception(vcpu, ABT_MODE, 0x10);
	}

	if (vcpu->arch.exception_pending & EXCEPTION_IRQ) {
		kvm_msg("inject irq");
		//if ((vcpu->arch.cpsr & PSR_I_BIT) || guest_debug || irq_suppress)
		if (vcpu->arch.cpsr & PSR_I_BIT) {
			return 0;
		}
		
		vcpu->arch.banked_r14[MODE_IRQ] = vcpu->arch.regs[15] + 4;
		vcpu->arch.banked_spsr[MODE_IRQ] = vcpu->arch.cpsr;

		return emulate_exception(vcpu, IRQ_MODE, 0x18);
	}

	if (vcpu->arch.exception_pending & EXCEPTION_FIQ) {
		kvm_msg("inject fiq");
		if (vcpu->arch.cpsr & PSR_F_BIT)
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
	u32 ttbr_cr;
	int ret;
#ifdef KVMARM_BIN_TRANSLATE 

	/* Look for sensitive instructions when executing in privileged mode */
	if (vcpu->arch.mode != MODE_USER) 
	{
		ret = kvmarm_translate(vcpu, vcpu->arch.regs[15]);
		if (ret < 0) 
			return ret;
	}
#endif
	if (vcpu->run->exit_reason == KVM_EXIT_MMIO) {
		handle_mmio_return(vcpu, vcpu->run);
	}

	if (vcpu->arch.exception_pending) {
		ret = inject_guest_exception(vcpu);
		if (ret)
			return ret;
	}

	/*
	 * Copy registers to shared page, which will be loaded to the cpu
	 */
	memcpy(shared->guest_regs, vcpu->arch.regs, sizeof(u32) * 16);
	if (vcpu->arch.mode == MODE_FIQ) {
		memcpy(shared->guest_regs + 8, vcpu->arch.fiq_regs, sizeof(u32) * 5);
	}
	if (vcpu->arch.mode != MODE_USER) {
		shared->guest_regs[13] = vcpu->arch.banked_r13[vcpu->arch.mode];
		shared->guest_regs[14] = vcpu->arch.banked_r14[vcpu->arch.mode];
	}

	/* Copy only the COND bits over to the execution CPSR */
	shared->guest_CPSR = (shared->guest_CPSR & ~0xf1000000) |
		                (vcpu->arch.cpsr &  0xf1000000);

#ifdef CONFIG_CPU_HAS_ASID
		/* Set the shadow ASID and copy the TTBR */
		if (unlikely((shadow->id ^ cpu_last_asid) >> ASID_BITS))
			shadow->id = __new_asid();
		shared->guest_asid = shadow->id;
		shared->host_asid = current->mm->context.id;
#endif
	shared->shadow_ttbr = shadow->pa;

	/* Make sure that interrupts are enabled and guest is in user mode */
	shared->guest_CPSR &= ~PSR_I_BIT;
	shared->guest_CPSR |= PSR_F_BIT;
	shared->guest_CPSR &= ~MODE_MASK;
	shared->guest_CPSR |= USR_MODE;

	/* 
	 * Make sure the special domain for shared page and irq vector
	 * always use the client setting.
	 */
	shared->guest_dac = (vcpu->arch.cp15.c3_DACR & 0x3fffffff)
		| domain_val(KVM_SPECIAL_DOMAIN, DOMAIN_CLIENT);

	/*
	 * TODO: Handle ARMv6 TTBR multiple registers and TTBR CR!
	 */
	if (cpu_architecture() >= CPU_ARCH_ARMv6) {
		asm ("mrc	p15, 0, %[res], c2, c0, 2": [res] "=r" (ttbr_cr));
		BUG_ON(ttbr_cr != 0);
	}

	/*
	if (guest_debug) {
		printk(KERN_ERR "  ********0xffff0000 l2 mapping: 0x%08x\n",
			get_shadow_l2_entry(vcpu, 0xffff0000));
	}
	*/

	return 0;
}

static void post_guest_switch(struct kvm_vcpu *vcpu)
{
	struct shared_page *shared = vcpu->arch.shared_page;

	/*
	 * Copy registers from tmp_regs, which was copied from exception exit
	 */
	//XXX TODO BUG, we will overwrite usr regs 8-14 when in FIQ mode
	memcpy(vcpu->arch.regs, shared->guest_regs, sizeof(u32) * 13);
	if (vcpu->arch.mode == MODE_FIQ) {
		memcpy(vcpu->arch.fiq_regs,
		       shared->guest_regs + 8,
		       sizeof(u32) * 5);
	}
	if (vcpu->arch.mode == MODE_USER) {
		vcpu->arch.regs[13] = shared->guest_regs[13];
		vcpu->arch.regs[14] = shared->guest_regs[14];
	} else {
		vcpu->arch.banked_r13[vcpu->arch.mode] = shared->guest_regs[13];
		vcpu->arch.banked_r14[vcpu->arch.mode] = shared->guest_regs[14];
	}
	vcpu->arch.regs[15] = shared->guest_regs[15];

	/* Copy only the condition bits for now */
	vcpu->arch.cpsr =    (vcpu->arch.cpsr & ~0xf1000000) |
			  (shared->guest_CPSR &  0xf1000000);
}

void debug_exit_print(struct kvm_vcpu *vcpu, u32 interrupt)
{
	switch (interrupt) {
	case ARM_EXCEPTION_UNDEFINED: {
		__kvm_print_msg("UNDEFINED (0x%08x)\n", vcpu->arch.regs[15]);
		break;
	}
	case ARM_EXCEPTION_SOFTWARE: {
		__kvm_print_msg("SWI (0x%08x)\n", vcpu->arch.regs[15]);
		break;
	}
	case ARM_EXCEPTION_PREF_ABORT:
		__kvm_print_msg("PREFETCH ABT (0x%08x)\n", vcpu->arch.regs[15]);
		break;
	case ARM_EXCEPTION_DATA_ABORT:
		__kvm_print_msg("DATA ABT (0x%08x)\n", vcpu->arch.regs[15]);
		break;
	case ARM_EXCEPTION_IRQ:
		__kvm_print_msg("IRQ (0x%08x)\n", vcpu->arch.regs[15]);
		break;
	default:
		__kvm_print_msg("BAD EXCPTN (0x%08x)\n", vcpu->arch.regs[15]);
		break;
	}

	return;
}

static inline int insert_breakpoint(struct kvm_vcpu *vcpu, gva_t gva)
{
	int ret;
	gfn_t gfn;
	gpa_t gpa;

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
	ret = kvm_write_guest(vcpu->kvm, gpa, &bp_instr, 4);
	if (ret) {
		kvm_err(ret, "could not write guest breakpoint!");
		return ret;
	}

	return 0;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int ret = 0;
	int excpt_idx;
	int pending_write = 0;
	unsigned long irq_flags;

	vcpu->arch.kvm_run = run;
	flush_dcache_page(virt_to_page(run));

	if (run->exit_reason == KVM_EXIT_IRQ_WINDOW_OPEN)
		run->exit_reason = KVM_EXIT_UNKNOWN;

	for (;;) {
		if (vcpu->arch.wait_for_interrupts)
			goto wait_for_interrupts;

		ret = pre_guest_switch(vcpu);
		if (ret < 0)
			break;

		run->exit_reason = KVM_EXIT_UNKNOWN;

		/*
		if (irq_suppress && irq_return == vcpu->arch.regs[15]) {
			guest_debug = 1;
			irq_suppress = 0;
		}
		*/

		if (guest_debug) {
			__kvm_msg("ENTER VCPU: %08x ---->  ", vcpu->arch.regs[15]);
			pending_write = 1;
		}


		/*
		 * vcpu->arch.run(...) function pointer value is setup in
		 * kvm_arch_vcpu_create(...)
		 */
		kvm_guest_enter();
		if ((vcpu->arch.shared_page->guest_CPSR & MODE_MASK)
				!= USR_MODE) {
			kvm_err(-EINVAL, "Trying to execute guest in priv. mode");
			return -EINVAL;
		}
		raw_local_irq_save(irq_flags);
		excpt_idx = vcpu->arch.run(vcpu);
		raw_local_irq_restore(irq_flags);
		kvm_guest_exit();

		vcpu->arch.guest_exception = excpt_idx;
		post_guest_switch(vcpu); 

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

		if (need_resched())
			schedule();
wait_for_interrupts:
		while (vcpu->arch.wait_for_interrupts && !signal_pending(current))
			schedule();

		if (signal_pending(current) && !(run->exit_reason)) {
			run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
			break;
		}
	}

	if (ret < 0)
		run->exit_reason = KVM_EXIT_EXCEPTION;

	flush_dcache_page(virt_to_page(run));
	return ret;
}

static inline int handle_undefined(struct kvm_vcpu *vcpu)
{
	int ret;
	u32 instr;

	instr = vcpu->arch.shared_page->guest_instr;
	//ret = get_exception_instr(vcpu, vcpu->arch.regs[15], &instr);
	//if (ret) 
	//	return ret;

	ret = kvm_handle_undefined(vcpu, instr);
	return ret;
}

static inline int handle_swi(struct kvm_vcpu *vcpu)
{
	gva_t addr;
	u32 instr, orig_instr;
	int ret;
	gfn_t gfn;
	u32 val;

	addr = vcpu->arch.regs[15];

	instr = vcpu->arch.shared_page->guest_instr;
#if 0
	ret = get_exception_instr(vcpu, addr, &instr);
	if (ret) {
		if (guest_debug)
			kvm_err(ret, "could not get_excp_instr!");
		return ret;
	}
#endif
	if (guest_debug) kvm_msg("instr: 0x%08x", instr);
#ifdef KVMARM_BIN_TRANSLATE 
	orig_instr = get_orig_instr(vcpu, addr);
#endif
	if ((instr & 0xffff) == 0xdead || (instr & 0xffff) == 0xbabe ||
	    (instr & 0xffff) == 0xcafe || (instr & 0xffff) == 0xbeef ||
	    ((instr & 0xffff) >= 0xde00 && (instr & 0xffff) < 0xdf00)) {

		kvm_msg("swi instr: 0x%08x at 0x%08x",
				(unsigned int)instr,
				(unsigned int)addr);


		if ((instr & 0xffff) == 0xdead) {
			kvm_msg("XXXXXXXXXXX    Exit point found    XXXXXXXXXXXXX!");

			ret = gva_to_gfn(vcpu, (gva_t)0xffff0000, &gfn, 0, NULL);
			if (ret)
				return ret;
			if (!kvm_is_visible_gfn(vcpu->kvm, gfn))
				return -EINVAL;

			ret = kvm_read_guest(vcpu->kvm, gfn << PAGE_SHIFT, &val, 4);
			if (ret)
				return ret;

			kvm_msg("guest value: 0x%08x", val);
			return -EINVAL;
		//} else if ((instr & 0xffff) >= 0xde00 && (instr & 0xffff) < 0xdf00) {

		} else if ((instr & 0xffff) == 0xcafe) {
			kvm_switch_host_vectors(vcpu, 0);
		} else if ((instr & 0xffff) == 0xbabe) {
			return -EINVAL;
		} else if ((instr & 0xffff) == 0xbeef) {
			guest_debug = 0;
		}

		/* Proceed to next instruction */
		vcpu->arch.regs[15] += 4;
		return 0;
	}

#ifdef KVMARM_BIN_TRANSLATE 
	if (instr == orig_instr || vcpu->arch.mode == MODE_USER) {
#else
	if ((instr & 0xffff) != 0xaaaa || vcpu->arch.mode == MODE_USER) {
#endif
		/* This is an actual guest SWI instruction */
		vcpu->arch.exception_pending |= EXCEPTION_SOFTWARE;
		if (guest_debug)
			kvm_msg("Guest needs SWI at: 0x%08x\n", vcpu->arch.regs[15]);
		vcpu->arch.exception_pending |= EXCEPTION_SOFTWARE;
	} else {
		/* An instruction that needs to be emulated */
		hva_t hva = gva_to_hva(vcpu, addr + 4, 0);
		if (kvm_is_error_hva(hva)) {
			kvm_err(-EINVAL, "Instruction generated at "
					 "bad address: %08x", vcpu->arch.regs[15]);
			return -EINVAL;
		}

		if (copy_from_user(&orig_instr, (void *)hva, sizeof(u32)))
			return -EFAULT;

		/*printk(KERN_ERR "Emulating instruction %08x (at 0x%08x)\n",
				  orig_instr, (unsigned int)addr + 4);*/

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

	down_write(&current->mm->mmap_sem);
	pfn = gfn_to_pfn(vcpu->kvm, gfn);
	up_write(&current->mm->mmap_sem);

	if (pfn == bad_pfn) {
		kvm_err(-EFAULT, "Guest gfn %u (0x%08x) does not have "
				"corresponding host mapping",
				(unsigned int)gfn,
				(unsigned int)gfn << PAGE_SHIFT);
		return -EFAULT;
	}

	/* Check if we have a domain conflict */
	if (map_info->domain_number == KVM_SPECIAL_DOMAIN) {
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
#if __LINUX_ARM_ARCH__ >= 6
			       map_info->apx,
			       map_info->xn);
#else
			       0,
			       0);
#endif
	if (ret) {
		kvm_release_pfn_clean(pfn);
		return ret;
	}

	/*
	 * If it was merely a question of a translation fault, it
	 * should always be possible to map the correct addresses
	 * in the shadow page table and repeat the instruction.
	 */
	vcpu->arch.regs[15] = instr_addr;
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
		memcpy(vcpu->run->mmio.data, &VCPU_REG(vcpu, rd), len);
	}
	
	/*
	 * The MMIO instruction is emulated and should not be re-executed
	 * in the guest.
	 */
	vcpu->arch.regs[15] = instr_addr + 4;
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
	fault = gva_to_gfn(vcpu, fault_addr, &gfn, uaccess, &map_info);
	if (fault < 0)
		return fault;

	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	if (!memslot) {
		/*
		 * All accesses to non-registered guest physical memory should
		 * go to QEMU. However, if the access would have generated a
		 * fault, we simply inject that fault to the guest.
		 */
		if (fault > 0) {
			kvm_msg("mapping to io address without permissions?");
			kvm_msg("        happened at: 0x%08x", instr_addr);
			kvm_msg("        address:     0x%08x", fault_addr);
			kvm_msg("        fault:       %d", fault);
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

static inline int handle_shadow_perm(struct kvm_vcpu *vcpu,
				      gva_t fault_addr, gva_t instr_addr)
{
	int high;
	gfn_t gfn;
	u8 uaccess;
	struct map_info map_info;
	int ret = 0;

	if (!vcpu->arch.host_vectors_high &&
		(fault_addr >> PAGE_SHIFT) == (0xffff0000 >> PAGE_SHIFT) &&
		VCPU_MODE_PRIV(vcpu)) {
		kvm_msg("Privileged mode cannot access vector page. "
			"Guest must be broken or we have a bug");
		//XXX Try to map page again.....
		ret = handle_shadow_fault(vcpu, fault_addr, instr_addr);
		goto out;
	}

	if ((fault_addr >> PAGE_SHIFT) ==
		(kvm_host_vector_base(vcpu) >> PAGE_SHIFT)) {

		/* The guest tried to access the host interrupt page */
		high = vcpu->arch.host_vectors_high ? 0 : 1;
		kvm_msg("switching vectors...");
		kvm_switch_host_vectors(vcpu, high);
		kvm_msg("handling shadow fault...");
		ret = handle_shadow_fault(vcpu, fault_addr, instr_addr);
		goto out;
	}

	/* Guest should never access the shared page */
	if ((fault_addr >> PAGE_SHIFT) == (SHARED_PAGE_BASE >> PAGE_SHIFT)) {
		BUG();
	}

	/* Check that the guest vector location is available */
	BUG_ON(gva_to_gfn(vcpu, VCPU_GUEST_EXCP_BASE(vpcu), &gfn, 0, NULL));

	uaccess = VCPU_MODE_PRIV(vcpu) ? 0 : 1;
	ret = gva_to_gfn(vcpu, fault_addr, &gfn, uaccess, &map_info);
	if (ret < 0) {
		goto out;
	}
	//BUG_ON(!write && ret == 0); //Why did we take a permission fault then?

	/* So this should of course only happen if the guest actually
	 * should take a fault here! */
	kvm_generate_mmu_fault(vcpu, fault_addr, vcpu->arch.host_fsr,
			       map_info.domain_number);
out:
	if (ret)
		kvm_err(ret, "error handling shadow page table permissions");
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
		instr_addr = vcpu->arch.regs[15];
		fsr = vcpu->arch.host_fsr;
	} else {
		if (cpu_architecture() >= CPU_ARCH_ARMv6)
			fsr = vcpu->arch.host_ifsr;
		else
			fsr = vcpu->arch.host_fsr;
		instr_addr = fault_addr = vcpu->arch.regs[15];
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
		vcpu->arch.exception_pending |= mask;
		vcpu->arch.wait_for_interrupts = 0;
	} else {
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

static int arm_init(void)
{
	int rc = kvm_init(NULL, sizeof(struct kvm_vcpu), THIS_MODULE);
	__kvm_log = kfifo_alloc(KVM_LOG_LEN, GFP_KERNEL, &__kvm_log_lock);
	return rc;
}

static void __exit arm_exit(void)
{
	kvm_exit();
}

module_init(arm_init);
module_exit(arm_exit)

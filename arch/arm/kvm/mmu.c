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

#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <linux/io.h>
#include <trace/events/kvm.h>
#include <asm/idmap.h>
#include <asm/pgalloc.h>
#include <asm/cacheflush.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/mach/map.h>
#include <trace/events/kvm.h>

#include "trace.h"

static DEFINE_MUTEX(kvm_hyp_pgd_mutex);
static pgd_t *hyp_pgd;

static void kvm_tlb_flush_vmid(struct kvm *kvm)
{
	kvm_call_hyp(__kvm_tlb_flush_vmid, kvm);
}

static int mmu_topup_memory_cache(struct kvm_mmu_memory_cache *cache,
				  int min, int max)
{
	void *page;

	BUG_ON(max > KVM_NR_MEM_OBJS);
	if (cache->nobjs >= min)
		return 0;
	while (cache->nobjs < max) {
		page = (void *)__get_free_page(PGALLOC_GFP);
		if (!page)
			return -ENOMEM;
		cache->objects[cache->nobjs++] = page;
	}
	return 0;
}

static void mmu_free_memory_cache(struct kvm_mmu_memory_cache *mc)
{
	while (mc->nobjs)
		free_page((unsigned long)mc->objects[--mc->nobjs]);
}

static void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc)
{
	void *p;

	BUG_ON(!mc || !mc->nobjs);
	p = mc->objects[--mc->nobjs];
	return p;
}

static void free_ptes(pmd_t *pmd, unsigned long addr)
{
	pte_t *pte;
	unsigned int i;

	for (i = 0; i < PTRS_PER_PMD; i++, addr += PMD_SIZE) {
		if (!pmd_none(*pmd) && pmd_table(*pmd)) {
			pte = pte_offset_kernel(pmd, addr);
			pte_free_kernel(NULL, pte);
		}
		pmd++;
	}
}

/**
 * free_hyp_pmds - free a Hyp-mode level-2 tables and child level-3 tables
 *
 * Assumes this is a page table used strictly in Hyp-mode and therefore contains
 * only mappings in the kernel memory area, which is above PAGE_OFFSET.
 */
void free_hyp_pmds(void)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long addr;

	mutex_lock(&kvm_hyp_pgd_mutex);
	for (addr = PAGE_OFFSET; addr != 0; addr += PGDIR_SIZE) {
		pgd = hyp_pgd + pgd_index(addr);
		pud = pud_offset(pgd, addr);

		if (pud_none(*pud))
			continue;
		BUG_ON(pud_bad(*pud));

		pmd = pmd_offset(pud, addr);
		free_ptes(pmd, addr);
		pmd_free(NULL, pmd);
		pud_clear(pud);
	}
	mutex_unlock(&kvm_hyp_pgd_mutex);
}

/*
 * Create a HYP pte mapping.
 *
 * If pfn_base is NULL, we map kernel pages into HYP with the virtual
 * address. Otherwise, this is considered an I/O mapping and we map
 * the physical region starting at *pfn_base to [start, end[.
 */
static void create_hyp_pte_mappings(pmd_t *pmd, unsigned long start,
				    unsigned long end, unsigned long *pfn_base)
{
	pte_t *pte;
	unsigned long addr;
	pgprot_t prot;

	if (pfn_base)
		prot = PAGE_HYP_DEVICE;
	else
		prot = PAGE_HYP;

	for (addr = start & PAGE_MASK; addr < end; addr += PAGE_SIZE) {
		pte = pte_offset_kernel(pmd, addr);
		if (pfn_base) {
			BUG_ON(pfn_valid(*pfn_base));
			set_pte_ext(pte, pfn_pte(*pfn_base, prot), 0);
			(*pfn_base)++;
		} else {
			struct page *page;
			BUG_ON(!virt_addr_valid(addr));
			page = virt_to_page(addr);
			set_pte_ext(pte, mk_pte(page, prot), 0);
		}

	}
}

static int create_hyp_pmd_mappings(pud_t *pud, unsigned long start,
				   unsigned long end, unsigned long *pfn_base)
{
	pmd_t *pmd;
	pte_t *pte;
	unsigned long addr, next;

	for (addr = start; addr < end; addr = next) {
		pmd = pmd_offset(pud, addr);

		BUG_ON(pmd_sect(*pmd));

		if (pmd_none(*pmd)) {
			pte = pte_alloc_one_kernel(NULL, addr);
			if (!pte) {
				kvm_err("Cannot allocate Hyp pte\n");
				return -ENOMEM;
			}
			pmd_populate_kernel(NULL, pmd, pte);
		}

		next = pmd_addr_end(addr, end);
		create_hyp_pte_mappings(pmd, addr, next, pfn_base);
	}

	return 0;
}

static int __create_hyp_mappings(void *from, void *to, unsigned long *pfn_base)
{
	unsigned long start = (unsigned long)from;
	unsigned long end = (unsigned long)to;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long addr, next;
	int err = 0;

	BUG_ON(start > end);
	if (start < PAGE_OFFSET)
		return -EINVAL;

	mutex_lock(&kvm_hyp_pgd_mutex);
	for (addr = start; addr < end; addr = next) {
		pgd = hyp_pgd + pgd_index(addr);
		pud = pud_offset(pgd, addr);

		if (pud_none_or_clear_bad(pud)) {
			pmd = pmd_alloc_one(NULL, addr);
			if (!pmd) {
				kvm_err("Cannot allocate Hyp pmd\n");
				err = -ENOMEM;
				goto out;
			}
			pud_populate(NULL, pud, pmd);
		}

		next = pgd_addr_end(addr, end);
		err = create_hyp_pmd_mappings(pud, addr, next, pfn_base);
		if (err)
			goto out;
	}
out:
	mutex_unlock(&kvm_hyp_pgd_mutex);
	return err;
}

/**
 * create_hyp_mappings - map a kernel virtual address range in Hyp mode
 * @from:	The virtual kernel start address of the range
 * @to:		The virtual kernel end address of the range (exclusive)
 *
 * The same virtual address as the kernel virtual address is also used in
 * Hyp-mode mapping to the same underlying physical pages.
 *
 * Note: Wrapping around zero in the "to" address is not supported.
 */
int create_hyp_mappings(void *from, void *to)
{
	return __create_hyp_mappings(from, to, NULL);
}

/**
 * create_hyp_io_mappings - map a physical IO range in Hyp mode
 * @from:	The virtual HYP start address of the range
 * @to:		The virtual HYP end address of the range (exclusive)
 * @addr:	The physical start address which gets mapped
 */
int create_hyp_io_mappings(void *from, void *to, phys_addr_t addr)
{
	unsigned long pfn = __phys_to_pfn(addr);
	return __create_hyp_mappings(from, to, &pfn);
}

/**
 * kvm_alloc_stage2_pgd - allocate level-1 table for stage-2 translation.
 * @kvm:	The KVM struct pointer for the VM.
 *
 * Allocates the 1st level table only of size defined by PGD2_ORDER (can
 * support either full 40-bit input addresses or limited to 32-bit input
 * addresses). Clears the allocated pages.
 *
 * Note we don't need locking here as this is only called when the VM is
 * created, which can only be done once.
 */
int kvm_alloc_stage2_pgd(struct kvm *kvm)
{
	pgd_t *pgd;

	if (kvm->arch.pgd != NULL) {
		kvm_err("kvm_arch already initialized?\n");
		return -EINVAL;
	}

	pgd = (pgd_t *)__get_free_pages(GFP_KERNEL, PGD2_ORDER);
	if (!pgd)
		return -ENOMEM;

	memset(pgd, 0, PTRS_PER_PGD2 * sizeof(pgd_t));
	clean_dcache_area(pgd, PTRS_PER_PGD2 * sizeof(pgd_t));
	kvm->arch.pgd = pgd;

	return 0;
}

static void free_guest_pages(pte_t *pte, unsigned long addr)
{
	unsigned int i;
	struct page *pte_page;

	pte_page = virt_to_page(pte);

	for (i = 0; i < PTRS_PER_PTE; i++) {
		if (pte_present(*pte))
			put_page(pte_page);
		pte++;
	}

	WARN_ON(page_count(pte_page) != 1);
}

static void free_stage2_ptes(pmd_t *pmd, unsigned long addr)
{
	unsigned int i;
	pte_t *pte;
	struct page *pmd_page;

	pmd_page = virt_to_page(pmd);

	for (i = 0; i < PTRS_PER_PMD; i++, addr += PMD_SIZE) {
		BUG_ON(pmd_sect(*pmd));
		if (!pmd_none(*pmd) && pmd_table(*pmd)) {
			pte = pte_offset_kernel(pmd, addr);
			free_guest_pages(pte, addr);
			pte_free_kernel(NULL, pte);

			put_page(pmd_page);
		}
		pmd++;
	}

	WARN_ON(page_count(pmd_page) != 1);
}

/**
 * kvm_free_stage2_pgd - free all stage-2 tables
 * @kvm:	The KVM struct pointer for the VM.
 *
 * Walks the level-1 page table pointed to by kvm->arch.pgd and frees all
 * underlying level-2 and level-3 tables before freeing the actual level-1 table
 * and setting the struct pointer to NULL.
 *
 * Note we don't need locking here as this is only called when the VM is
 * destroyed, which can only be done once.
 */
void kvm_free_stage2_pgd(struct kvm *kvm)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long long i, addr;
	struct page *pud_page;

	if (kvm->arch.pgd == NULL)
		return;

	/*
	 * We do this slightly different than other places, since we need more
	 * than 32 bits and for instance pgd_addr_end converts to unsigned long.
	 */
	addr = 0;
	for (i = 0; i < PTRS_PER_PGD2; i++) {
		addr = i * (unsigned long long)PGDIR_SIZE;
		pgd = kvm->arch.pgd + i;
		pud = pud_offset(pgd, addr);
		pud_page = virt_to_page(pud);

		if (pud_none(*pud))
			continue;

		BUG_ON(pud_bad(*pud));

		pmd = pmd_offset(pud, addr);
		free_stage2_ptes(pmd, addr);
		pmd_free(NULL, pmd);
		put_page(pud_page);
	}

	WARN_ON(page_count(pud_page) != 1);
	free_pages((unsigned long)kvm->arch.pgd, PGD2_ORDER);
	kvm->arch.pgd = NULL;
}

/**
 * stage2_clear_pte -- Clear a stage-2 PTE.
 * @kvm:  The VM pointer
 * @addr: The physical address of the PTE
 *
 * Clear a stage-2 PTE, lowering the various ref-counts. Also takes
 * care of invalidating the TLBs.  Must be called while holding
 * mmu_lock, otherwise another faulting VCPU may come in and mess
 * things behind our back.
 */
static void stage2_clear_pte(struct kvm *kvm, phys_addr_t addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct page *page;

	pgd = kvm->arch.pgd + pgd_index(addr);
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud))
		return;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return;

	pte = pte_offset_kernel(pmd, addr);
	set_pte_ext(pte, __pte(0), 0);

	page = virt_to_page(pte);
	put_page(page);
	if (page_count(page) != 1) {
		kvm_tlb_flush_vmid(kvm);
		return;
	}

	/* Need to remove pte page */
	pmd_clear(pmd);
	pte_free_kernel(NULL, (pte_t *)((unsigned long)pte & PAGE_MASK));

	page = virt_to_page(pmd);
	put_page(page);
	if (page_count(page) != 1) {
		kvm_tlb_flush_vmid(kvm);
		return;
	}

	pud_clear(pud);
	pmd_free(NULL, (pmd_t *)((unsigned long)pmd & PAGE_MASK));

	page = virt_to_page(pud);
	put_page(page);
	kvm_tlb_flush_vmid(kvm);
}

static void stage2_set_pte(struct kvm *kvm, struct kvm_mmu_memory_cache *cache,
			   phys_addr_t addr, const pte_t *new_pte)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte, old_pte;

	/* Create 2nd stage page table mapping - Level 1 */
	pgd = kvm->arch.pgd + pgd_index(addr);
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud)) {
		if (!cache)
			return; /* ignore calls from kvm_set_spte_hva */
		pmd = mmu_memory_cache_alloc(cache);
		pud_populate(NULL, pud, pmd);
		pmd += pmd_index(addr);
		get_page(virt_to_page(pud));
	} else
		pmd = pmd_offset(pud, addr);

	/* Create 2nd stage page table mapping - Level 2 */
	if (pmd_none(*pmd)) {
		if (!cache)
			return; /* ignore calls from kvm_set_spte_hva */
		pte = mmu_memory_cache_alloc(cache);
		clean_pte_table(pte);
		pmd_populate_kernel(NULL, pmd, pte);
		pte += pte_index(addr);
		get_page(virt_to_page(pmd));
	} else
		pte = pte_offset_kernel(pmd, addr);

	/* Create 2nd stage page table mapping - Level 3 */
	old_pte = *pte;
	set_pte_ext(pte, *new_pte, 0);
	if (pte_present(old_pte))
		kvm_tlb_flush_vmid(kvm);
	else
		get_page(virt_to_page(pte));
}

/**
 * kvm_phys_addr_ioremap - map a device range to guest IPA
 *
 * @kvm:	The KVM pointer
 * @guest_ipa:	The IPA at which to insert the mapping
 * @pa:		The physical address of the device
 * @size:	The size of the mapping
 */
int kvm_phys_addr_ioremap(struct kvm *kvm, phys_addr_t guest_ipa,
			  phys_addr_t pa, unsigned long size)
{
	phys_addr_t addr, end;
	int ret = 0;
	unsigned long pfn;
	struct kvm_mmu_memory_cache cache = { 0, };

	end = (guest_ipa + size + PAGE_SIZE - 1) & PAGE_MASK;
	pfn = __phys_to_pfn(pa);

	for (addr = guest_ipa; addr < end; addr += PAGE_SIZE) {
		pte_t pte = pfn_pte(pfn, PAGE_S2_DEVICE | L_PTE_S2_RDWR);

		ret = mmu_topup_memory_cache(&cache, 2, 2);
		if (ret)
			goto out;
		spin_lock(&kvm->mmu_lock);
		stage2_set_pte(kvm, &cache, addr, &pte);
		spin_unlock(&kvm->mmu_lock);

		pfn++;
	}

out:
	mmu_free_memory_cache(&cache);
	return ret;
}

static void coherent_icache_guest_page(struct kvm *kvm, gfn_t gfn)
{
	/*
	 * If we are going to insert an instruction page and the icache is
	 * either VIPT or PIPT, there is a potential problem where the host
	 * (or another VM) may have used this page at the same virtual address
	 * as this guest, and we read incorrect data from the icache.  If
	 * we're using a PIPT cache, we can invalidate just that page, but if
	 * we are using a VIPT cache we need to invalidate the entire icache -
	 * damn shame - as written in the ARM ARM (DDI 0406C - Page B3-1384)
	 */
	if (icache_is_pipt()) {
		unsigned long hva = gfn_to_hva(kvm, gfn);
		__cpuc_coherent_user_range(hva, hva + PAGE_SIZE);
	} else if (!icache_is_vivt_asid_tagged()) {
		/* any kind of VIPT cache */
		__flush_icache_all();
	}
}

static int user_mem_abort(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			  gfn_t gfn, struct kvm_memory_slot *memslot,
			  bool is_iabt, unsigned long fault_status)
{
	pte_t new_pte;
	pfn_t pfn;
	int ret;
	bool write_fault, writable;
	unsigned long mmu_seq;
	struct kvm_mmu_memory_cache *memcache = &vcpu->arch.mmu_page_cache;

	if (is_iabt)
		write_fault = false;
	else if ((vcpu->arch.hsr & HSR_ISV) && !(vcpu->arch.hsr & HSR_WNR))
		write_fault = false;
	else
		write_fault = true;

	if (fault_status == FSC_PERM && !write_fault) {
		kvm_err("Unexpected L2 read permission error\n");
		return -EFAULT;
	}

	/* We need minimum second+third level pages */
	ret = mmu_topup_memory_cache(memcache, 2, KVM_NR_MEM_OBJS);
	if (ret)
		return ret;

	mmu_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();

	pfn = gfn_to_pfn_prot(vcpu->kvm, gfn, write_fault, &writable);
	if (is_error_pfn(pfn))
		return -EFAULT;

	new_pte = pfn_pte(pfn, PAGE_S2);
	coherent_icache_guest_page(vcpu->kvm, gfn);

	spin_lock(&vcpu->kvm->mmu_lock);
	if (mmu_notifier_retry(vcpu, mmu_seq))
		goto out_unlock;
	if (writable) {
		pte_val(new_pte) |= L_PTE_S2_RDWR;
		kvm_set_pfn_dirty(pfn);
	}
	stage2_set_pte(vcpu->kvm, memcache, fault_ipa, &new_pte);

out_unlock:
	spin_unlock(&vcpu->kvm->mmu_lock);
	/*
	 * XXX TODO FIXME:
-        * This is _really_ *weird* !!!
-        * We should be calling the _clean version, because we set the pfn dirty
	 * if we map the page writable, but this causes memory failures in
	 * guests under heavy memory pressure on the host and heavy swapping.
	 */
	kvm_release_pfn_dirty(pfn);
	return 0;
}

/**
 * kvm_handle_mmio_return -- Handle MMIO loads after user space emulation
 * @vcpu: The VCPU pointer
 * @run:  The VCPU run struct containing the mmio data
 *
 * This should only be called after returning from userspace for MMIO load
 * emulation.
 */
int kvm_handle_mmio_return(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	int *dest;
	unsigned int len;
	int mask;

	if (!run->mmio.is_write) {
		dest = vcpu_reg(vcpu, vcpu->arch.mmio.rd);
		memset(dest, 0, sizeof(int));

		len = run->mmio.len;
		if (len > 4)
			return -EINVAL;

		memcpy(dest, run->mmio.data, len);

		trace_kvm_mmio(KVM_TRACE_MMIO_READ, len, run->mmio.phys_addr,
				*((u64 *)run->mmio.data));

		if (vcpu->arch.mmio.sign_extend && len < 4) {
			mask = 1U << ((len * 8) - 1);
			*dest = (*dest ^ mask) - mask;
		}
	}

	return 0;
}

static u64 kvm_va_to_pa(struct kvm_vcpu *vcpu, u32 va, bool priv)
{
	return kvm_call_hyp(__kvm_va_to_pa, vcpu, va, priv);
}

/**
 * copy_from_guest_va - copy memory from guest (very slow!)
 * @vcpu:	vcpu pointer
 * @dest:	memory to copy into
 * @gva:	virtual address in guest to copy from
 * @len:	length to copy
 * @priv:	use guest PL1 (ie. kernel) mappings
 *              otherwise use guest PL0 mappings.
 *
 * Returns true on success, false on failure (unlikely, but retry).
 */
static bool copy_from_guest_va(struct kvm_vcpu *vcpu,
			       void *dest, unsigned long gva, size_t len,
			       bool priv)
{
	u64 par;
	phys_addr_t pc_ipa;
	int err;

	BUG_ON((gva & PAGE_MASK) != ((gva + len) & PAGE_MASK));
	par = kvm_va_to_pa(vcpu, gva & PAGE_MASK, priv);
	if (par & 1) {
		kvm_err("IO abort from invalid instruction address"
			" %#lx!\n", gva);
		return false;
	}

	BUG_ON(!(par & (1U << 11)));
	pc_ipa = par & PAGE_MASK & ((1ULL << 32) - 1);
	pc_ipa += gva & ~PAGE_MASK;


	err = kvm_read_guest(vcpu->kvm, pc_ipa, dest, len);
	if (unlikely(err))
		return false;

	return true;
}

/* Just ensure we're not running the guest. */
static void do_nothing(void *info)
{
}

/*
 * We have to be very careful copying memory from a running (ie. SMP) guest.
 * Another CPU may remap the page (eg. swap out a userspace text page) as we
 * read the instruction.  Unlike normal hardware operation, to emulate an
 * instruction we map the virtual to physical address then read that memory
 * as separate steps, thus not atomic.
 *
 * Fortunately this is so rare (we don't usually need the instruction), we
 * can go very slowly and noone will mind.
 */
static bool copy_current_insn(struct kvm_vcpu *vcpu, unsigned long *instr)
{
	int i;
	bool ret;
	struct kvm_vcpu *v;
	bool is_thumb;
	size_t instr_len;

	/* Don't cross with IPIs in kvm_main.c */
	spin_lock(&vcpu->kvm->mmu_lock);

	/* Tell them all to pause, so no more will enter guest. */
	kvm_for_each_vcpu(i, v, vcpu->kvm)
		v->arch.pause = true;

	/* Set ->pause before we read ->mode */
	smp_mb();

	/* Kick out any which are still running. */
	kvm_for_each_vcpu(i, v, vcpu->kvm) {
		/* Guest could exit now, making cpu wrong. That's OK. */
		if (kvm_vcpu_exiting_guest_mode(v) == IN_GUEST_MODE)
			smp_call_function_single(v->cpu, do_nothing, NULL, 1);
	}


	is_thumb = !!(*vcpu_cpsr(vcpu) & PSR_T_BIT);
	instr_len = (is_thumb) ? 2 : 4;

	BUG_ON(!is_thumb && *vcpu_pc(vcpu) & 0x3);

	/* Now guest isn't running, we can va->pa map and copy atomically. */
	ret = copy_from_guest_va(vcpu, instr, *vcpu_pc(vcpu), instr_len,
				 vcpu_mode_priv(vcpu));
	if (!ret)
		goto out;

	/* A 32-bit thumb2 instruction can actually go over a page boundary! */
	if (is_thumb && is_wide_instruction(*instr)) {
		*instr = *instr << 16;
		ret = copy_from_guest_va(vcpu, instr, *vcpu_pc(vcpu) + 2, 2,
					 vcpu_mode_priv(vcpu));
	}

out:
	/* Release them all. */
	kvm_for_each_vcpu(i, v, vcpu->kvm)
		v->arch.pause = false;

	spin_unlock(&vcpu->kvm->mmu_lock);

	return ret;
}

/**
 * invalid_io_mem_abort -- Handle I/O aborts ISV bit is clear
 *
 * @vcpu:      The vcpu pointer
 * @fault_ipa: The IPA that caused the 2nd stage fault
 * @mmio:      Pointer to struct to hold decode information
 *
 * Some load/store instructions cannot be emulated using the information
 * presented in the HSR, for instance, register write-back instructions are not
 * supported. We therefore need to fetch the instruction, decode it, and then
 * emulate its behavior.
 */
static int invalid_io_mem_abort(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
				struct kvm_exit_mmio *mmio)
{
	unsigned long instr = 0;

	/* If it fails (SMP race?), we reenter guest for it to retry. */
	if (!copy_current_insn(vcpu, &instr))
		return 1;

	return kvm_emulate_mmio_ls(vcpu, fault_ipa, instr, mmio);
}

static int decode_hsr(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
		      struct kvm_exit_mmio *mmio)
{
	unsigned long rd, len;
	bool is_write, sign_extend;

	if ((vcpu->arch.hsr >> 8) & 1) {
		/* cache operation on I/O addr, tell guest unsupported */
		kvm_inject_dabt(vcpu, vcpu->arch.hxfar);
		return 1;
	}

	if ((vcpu->arch.hsr >> 7) & 1) {
		/* page table accesses IO mem: tell guest to fix its TTBR */
		kvm_inject_dabt(vcpu, vcpu->arch.hxfar);
		return 1;
	}

	switch ((vcpu->arch.hsr >> 22) & 0x3) {
	case 0:
		len = 1;
		break;
	case 1:
		len = 2;
		break;
	case 2:
		len = 4;
		break;
	default:
		kvm_err("Hardware is weird: SAS 0b11 is reserved\n");
		return -EFAULT;
	}

	is_write = vcpu->arch.hsr & HSR_WNR;
	sign_extend = vcpu->arch.hsr & HSR_SSE;
	rd = (vcpu->arch.hsr & HSR_SRT_MASK) >> HSR_SRT_SHIFT;

	if (rd == 15) {
		/* IO memory trying to read/write pc */
		kvm_inject_pabt(vcpu, vcpu->arch.hxfar);
		return 1;
	}

	mmio->is_write = is_write;
	mmio->phys_addr = fault_ipa;
	mmio->len = len;
	vcpu->arch.mmio.sign_extend = sign_extend;
	vcpu->arch.mmio.rd = rd;

	/*
	 * The MMIO instruction is emulated and should not be re-executed
	 * in the guest.
	 */
	kvm_skip_instr(vcpu, (vcpu->arch.hsr >> 25) & 1);
	return 0;
}

static int io_mem_abort(struct kvm_vcpu *vcpu, struct kvm_run *run,
			phys_addr_t fault_ipa, struct kvm_memory_slot *memslot)
{
	struct kvm_exit_mmio mmio;
	unsigned long rd;
	int ret;

	/*
	 * Prepare MMIO operation. First stash it in a private
	 * structure that we can use for in-kernel emulation. If the
	 * kernel can't handle it, copy it into run->mmio and let user
	 * space do its magic.
	 */

	if (vcpu->arch.hsr & HSR_ISV)
		ret = decode_hsr(vcpu, fault_ipa, &mmio);
	else
		ret = invalid_io_mem_abort(vcpu, fault_ipa, &mmio);

	if (ret != 0)
		return ret;

	rd = vcpu->arch.mmio.rd;
	trace_kvm_mmio((mmio.is_write) ? KVM_TRACE_MMIO_WRITE :
					 KVM_TRACE_MMIO_READ_UNSATISFIED,
			mmio.len, fault_ipa,
			(mmio.is_write) ? *vcpu_reg(vcpu, rd) : 0);

	if (mmio.is_write)
		memcpy(mmio.data, vcpu_reg(vcpu, rd), mmio.len);

	if (vgic_handle_mmio(vcpu, run, &mmio))
		return 1;

	kvm_prepare_mmio(run, &mmio);
	return 0;
}

/**
 * kvm_handle_guest_abort - handles all 2nd stage aborts
 * @vcpu:	the VCPU pointer
 * @run:	the kvm_run structure
 *
 * Any abort that gets to the host is almost guaranteed to be caused by a
 * missing second stage translation table entry, which can mean that either the
 * guest simply needs more memory and we must allocate an appropriate page or it
 * can mean that the guest tried to access I/O memory, which is emulated by user
 * space. The distinction is based on the IPA causing the fault and whether this
 * memory region has been registered as standard RAM by user space.
 */
int kvm_handle_guest_abort(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	unsigned long hsr_ec;
	unsigned long fault_status;
	phys_addr_t fault_ipa;
	struct kvm_memory_slot *memslot = NULL;
	bool is_iabt;
	gfn_t gfn;
	int ret;

	hsr_ec = vcpu->arch.hsr >> HSR_EC_SHIFT;
	is_iabt = (hsr_ec == HSR_EC_IABT);
	fault_ipa = ((phys_addr_t)vcpu->arch.hpfar & HPFAR_MASK) << 8;

	trace_kvm_guest_fault(*vcpu_pc(vcpu), vcpu->arch.hsr,
			      vcpu->arch.hxfar, fault_ipa);

	/* Check the stage-2 fault is trans. fault or write fault */
	fault_status = (vcpu->arch.hsr & HSR_FSC_TYPE);
	if (fault_status != FSC_FAULT && fault_status != FSC_PERM) {
		kvm_err("Unsupported fault status: EC=%#lx DFCS=%#lx\n",
			hsr_ec, fault_status);
		return -EFAULT;
	}

	gfn = fault_ipa >> PAGE_SHIFT;
	if (!kvm_is_visible_gfn(vcpu->kvm, gfn)) {
		if (is_iabt) {
			/* Prefetch Abort on I/O address */
			kvm_inject_pabt(vcpu, vcpu->arch.hxfar);
			return 1;
		}

		if (fault_status != FSC_FAULT) {
			kvm_err("Unsupported fault status on io memory: %#lx\n",
				fault_status);
			return -EFAULT;
		}

		/* Adjust page offset */
		fault_ipa |= vcpu->arch.hxfar & ~PAGE_MASK;
		return io_mem_abort(vcpu, run, fault_ipa, memslot);
	}

	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	if (!memslot->user_alloc) {
		kvm_err("non user-alloc memslots not supported\n");
		return -EINVAL;
	}

	ret = user_mem_abort(vcpu, fault_ipa, gfn, memslot,
			     is_iabt, fault_status);
	return ret ? ret : 1;
}

static void handle_hva_to_gpa(struct kvm *kvm,
			      unsigned long start,
			      unsigned long end,
			      void (*handler)(struct kvm *kvm,
					      gpa_t gpa, void *data),
			      void *data)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;

	slots = kvm_memslots(kvm);

	/* we only care about the pages that the guest sees */
	kvm_for_each_memslot(memslot, slots) {
		unsigned long hva_start, hva_end;
		gfn_t gfn, gfn_end;

		hva_start = max(start, memslot->userspace_addr);
		hva_end = min(end, memslot->userspace_addr +
					(memslot->npages << PAGE_SHIFT));
		if (hva_start >= hva_end)
			continue;

		/*
		 * {gfn(page) | page intersects with [hva_start, hva_end)} =
		 * {gfn_start, gfn_start+1, ..., gfn_end-1}.
		 */
		gfn = hva_to_gfn_memslot(hva_start, memslot);
		gfn_end = hva_to_gfn_memslot(hva_end + PAGE_SIZE - 1, memslot);

		for (; gfn < gfn_end; ++gfn) {
			gpa_t gpa = gfn << PAGE_SHIFT;
			handler(kvm, gpa, data);
		}
	}
}

static void kvm_unmap_hva_handler(struct kvm *kvm, gpa_t gpa, void *data)
{
	stage2_clear_pte(kvm, gpa);
}

int kvm_unmap_hva(struct kvm *kvm, unsigned long hva)
{
	unsigned long end = hva + PAGE_SIZE;

	if (!kvm->arch.pgd)
		return 0;

	trace_kvm_unmap_hva(hva);
	handle_hva_to_gpa(kvm, hva, end, &kvm_unmap_hva_handler, NULL);
	return 0;
}

int kvm_unmap_hva_range(struct kvm *kvm,
			unsigned long start, unsigned long end)
{
	if (!kvm->arch.pgd)
		return 0;

	trace_kvm_unmap_hva_range(start, end);
	handle_hva_to_gpa(kvm, start, end, &kvm_unmap_hva_handler, NULL);
	return 0;
}

static void kvm_set_spte_handler(struct kvm *kvm, gpa_t gpa, void *data)
{
	pte_t *pte = (pte_t *)data;

	stage2_set_pte(kvm, NULL, gpa, pte);
}


void kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	unsigned long end = hva + PAGE_SIZE;
	pte_t stage2_pte;

	if (!kvm->arch.pgd)
		return;

	trace_kvm_set_spte_hva(hva);
	stage2_pte = pfn_pte(pte_pfn(pte), PAGE_S2);
	handle_hva_to_gpa(kvm, hva, end, &kvm_set_spte_handler, &stage2_pte);
}

void kvm_mmu_free_memory_caches(struct kvm_vcpu *vcpu)
{
	mmu_free_memory_cache(&vcpu->arch.mmu_page_cache);
}

unsigned long kvm_mmu_get_httbr(void)
{
	return virt_to_phys(hyp_pgd);
}

int kvm_mmu_init(void)
{
	hyp_pgd = kzalloc(PTRS_PER_PGD * sizeof(pgd_t), GFP_KERNEL);
	if (!hyp_pgd)
		return -ENOMEM;

	hyp_idmap_setup(hyp_pgd);
	return 0;
}

void kvm_mmu_exit(void)
{
	hyp_idmap_teardown(hyp_pgd);
}

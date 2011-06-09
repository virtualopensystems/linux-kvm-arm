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

#include <linux/mman.h>
#include <linux/kvm_host.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/pgalloc.h>

#include "debug.h"

pgd_t *kvm_hyp_pgd = NULL;

static void free_hyp_ptes(pmd_t *hyp_pmd, unsigned long addr)
{
	pmd_t *pmd;
	pte_t *pte;
	unsigned int i;

	for (i = 0; i < PTRS_PER_PMD; i++, addr += PMD_SIZE) {
		pmd = hyp_pmd + i;
		if (!pmd_none(*pmd) && pmd_table(*pmd)) {
			pte = pte_offset_kernel(hyp_pmd, addr);
			pte_free_kernel(NULL, pte);
		}
	}
}

/*
 * Free a Hyp-mode level-2 tables and child level-3 tables.
 */
void free_hyp_pmds(pgd_t *hyp_pgd)
{
	pgd_t *pgd;
	pmd_t *pmd;
	unsigned long addr, next, end;

	addr = PAGE_OFFSET;
	end = ~0;
	do {
		next = pgd_addr_end(addr, (~0));
		pgd = hyp_pgd + pgd_index(addr);

		BUG_ON(pgd_bad(*pgd));

		if (pgd_none(*pgd))
			continue;

		pmd = pmd_offset(pgd, addr);
		free_hyp_ptes(pmd, addr);
		pmd_free(NULL, pmd);
	} while (addr = next, addr != end);
}

static void remove_hyp_pte_mappings(pmd_t *pmd, unsigned long addr,
						unsigned long end)
{
	pte_t *pte;

	do {
		pte = pte_offset_kernel(pmd, addr);
		pte_clear(NULL, addr, pte);
	} while (addr += PAGE_SIZE, addr < end);
}

static void remove_hyp_pmd_mappings(pgd_t *pgd, unsigned long addr,
					       unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	do {
		next = pmd_addr_end(addr, end);
		pmd = pmd_offset(pgd, addr);

		BUG_ON(pmd_sect(*pmd));

		if (!pmd_none(*pmd))
			remove_hyp_pte_mappings(pmd, addr, next);
	} while (addr = next, addr < end);
}

/*
 * Clear hypervisor mappings from specified range (doesn't actually free the
 * page tables.
 */
void remove_hyp_mappings(pgd_t *hyp_pgd, unsigned long start,
					 unsigned long end)
{
	pgd_t *pgd;
	unsigned long addr, next;

	BUG_ON(start > end);
	BUG_ON(start < PAGE_OFFSET);

	addr = start;
	do {
		next = pgd_addr_end(addr, end);
		pgd = hyp_pgd + pgd_index(addr);

		BUG_ON(pgd_bad(*pgd));

		if (pgd_none(*pgd))
			continue;

		remove_hyp_pmd_mappings(pgd, addr, next);
	} while (addr = next, addr < end);
}

extern unsigned long __kvm_hyp_vector, __kvm_hyp_vector_end;

static void create_hyp_pte_mappings(pmd_t *pmd, unsigned long addr,
						unsigned long end)
{
	pte_t *pte;
	struct page *page;

	addr &= PAGE_MASK;
	do {
		pte = pte_offset_kernel(pmd, addr);
		BUG_ON(!virt_addr_valid(addr));
		page = virt_to_page(addr);

		set_pte_ext(pte, mk_pte(page, PAGE_HYP), 0);
	} while (addr += PAGE_SIZE, addr < end);
}

static int create_hyp_pmd_mappings(pgd_t *pgd, unsigned long addr,
					       unsigned long end)
{
	pmd_t *pmd;
	pte_t *pte;
	unsigned long next;

	do {
		next = pmd_addr_end(addr, end);
		pmd = pmd_offset(pgd, addr);

		BUG_ON(pmd_sect(*pmd));

		if (pmd_none(*pmd)) {
			pte = pte_alloc_one_kernel(NULL, addr);
			if (!pte) {
				kvm_err(-ENOMEM, "Cannot allocate Hyp pte");
				return -ENOMEM;
			}
			pmd_populate_kernel(NULL, pmd, pte);
		}

		create_hyp_pte_mappings(pmd, addr, next);
	} while (addr = next, addr < end);

	return 0;
}

/*
 * Map the requested kernel virtual address range to their corresponing physical
 * addresses in the hyp table.
 *
 * @hyp_pgd: The allocated hypervisor level-1 table
 * @start:   The virtual kernel start address of the range
 * @end:     The virtual kernel end address of the range
 */
int create_hyp_mappings(pgd_t *hyp_pgd, unsigned long start, unsigned long end)
{
	pgd_t *pgd;
	pmd_t *pmd;
	unsigned long addr, next;
	int err = 0;

	BUG_ON(start > end);
	if (start < PAGE_OFFSET)
		return -EINVAL;

	addr = start;
	do {
		next = pgd_addr_end(addr, end);
		pgd = hyp_pgd + pgd_index(addr);

		if (pgd_none_or_clear_bad(pgd)) {
			pmd = pmd_alloc_one(NULL, addr);
			if (!pmd) {
				kvm_err(-ENOMEM, "Cannot allocate Hyp pmd");
				return -ENOMEM;
			}
			pgd_populate(NULL, pgd, pmd);
		}

		err = create_hyp_pmd_mappings(pgd, addr, next);
		if (err)
			return err;
	} while (addr = next, addr < end);

	return err;
}

/*
 * Allocate level-1 translation table for stage-2 translation.
 */
int kvm_alloc_stage2_pgd(struct kvm *kvm)
{
	pgd_t *pgd;

	if (kvm->arch.pgd != NULL) {
		kvm_err(-EINVAL, "kvm_arch already initialized?\n");
		return -EINVAL;
	}

	pgd = (pgd_t *)__get_free_pages(GFP_KERNEL, PGD2_ORDER);
	if (!pgd)
		return -ENOMEM;

	memset(pgd, 0, PTRS_PER_PGD2 * sizeof(pgd_t));
	kvm->arch.pgd = pgd;

	return 0;
}

/*
 * Free level-1 translation table for stage-2 translation and all belonging
 * level-2 and level-3 tables.
 */
void kvm_free_stage2_pgd(struct kvm *kvm)
{
	if (kvm->arch.pgd == NULL)
		return;

	free_pages((unsigned long)kvm->arch.pgd, PGD2_ORDER);
	kvm->arch.pgd = NULL;

	/* TODO: Free child tables */
	KVMARM_NOT_IMPLEMENTED();
}

static int user_mem_abort(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			  gfn_t gfn, struct kvm_memory_slot *memslot)
{
	pfn_t pfn;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte, new_pte;

	pfn = gfn_to_pfn(vcpu->kvm, gfn);

	if (is_error_pfn(pfn)) {
		kvm_err(-EFAULT, "Guest gfn %u (0x%08lx) does not have "
				"corresponding host mapping",
				gfn, gfn << PAGE_SHIFT);
		return -EFAULT;
	}

	/* Create 2nd stage page table mapping - Level 1 */
	pgd = vcpu->kvm->arch.pgd + pgd_index(fault_ipa);
	if (pgd_none(*pgd)) {
		pmd = pmd_alloc_one(NULL, fault_ipa);
		if (!pmd) {
			kvm_err(-ENOMEM, "Cannot allocate 2nd stage pmd");
			return -ENOMEM;
		}
		pgd_populate(NULL, pgd, pmd);
		pmd += pmd_index(fault_ipa);
	} else
		pmd = pmd_offset(pgd, fault_ipa);

	/* Create 2nd stage page table mapping - Level 2 */
	if (pmd_none(*pmd)) {
		pte = pte_alloc_one_kernel(NULL, fault_ipa);
		if (!pte) {
			kvm_err(-ENOMEM, "Cannot allocate 2nd stage pte");
			return -ENOMEM;
		}
		pmd_populate_kernel(NULL, pmd, pte);
		pte += pte_index(fault_ipa);
	} else
		pte = pte_offset_kernel(pmd, fault_ipa);

	/* Create 2nd stage page table mapping - Level 3 */
	new_pte = pfn_pte(pfn, PAGE_KVM_GUEST);
	set_pte_ext(pte, new_pte, 0);

	return 0;
}

#define HSR_ABT_FS	(0x3f)
#define HPFAR_MASK	(~0xf)
int kvm_handle_guest_abort(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	unsigned long hsr_ec;
	unsigned long fault_status;
	phys_addr_t fault_ipa;
	struct kvm_memory_slot *memslot = NULL;
	bool is_iabt;
	gfn_t gfn;

	hsr_ec = vcpu->arch.hsr >> HSR_EC_SHIFT;
	is_iabt = (hsr_ec == HSR_EC_IABT);

	/* Check that the second stage fault is a translation fault */
	fault_status = vcpu->arch.hsr & HSR_ABT_FS;
	if ((fault_status & 0x3c) != 0x4) {
		kvm_err(-EFAULT, "Unsupported fault status: %x",
				fault_status & 0x3c);
		return -EFAULT;
	}

	fault_ipa = ((phys_addr_t)vcpu->arch.hpfar & HPFAR_MASK) << 8;

	gfn = fault_ipa >> PAGE_SHIFT;
	if (!kvm_is_visible_gfn(vcpu->kvm, gfn)) {
		if (is_iabt) {
			kvm_err(-EFAULT, "Inst. abort on I/O address");
			return -EFAULT;
		}

		kvm_msg("I/O address abort...");
		KVMARM_NOT_IMPLEMENTED();
		return -EINVAL;
	}

	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	if (!memslot->user_alloc) {
		kvm_err(-EINVAL, "non user-alloc memslots not supported");
		return -EINVAL;
	}

	return user_mem_abort(vcpu, fault_ipa, gfn, memslot);
}

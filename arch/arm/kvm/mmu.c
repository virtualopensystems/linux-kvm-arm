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
#include <asm/pgalloc.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_asm.h>

pgd_t *kvm_hyp_pgd;
DEFINE_MUTEX(kvm_hyp_pgd_mutex);

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
 * @hypd_pgd:	The Hyp-mode page table pointer
 *
 * Assumes this is a page table used strictly in Hyp-mode and therefore contains
 * only mappings in the kernel memory area, which is above PAGE_OFFSET.
 */
void free_hyp_pmds(pgd_t *hyp_pgd)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	unsigned long addr;

	mutex_lock(&kvm_hyp_pgd_mutex);
	for (addr = PAGE_OFFSET; addr != 0; addr += PGDIR_SIZE) {
		pgd = hyp_pgd + pgd_index(addr);
		pud = pud_offset(pgd, addr);

		BUG_ON(pud_bad(*pud));

		if (pud_none(*pud))
			continue;

		pmd = pmd_offset(pud, addr);
		free_ptes(pmd, addr);
		pmd_free(NULL, pmd);
	}
	mutex_unlock(&kvm_hyp_pgd_mutex);
}

static void create_hyp_pte_mappings(pmd_t *pmd, unsigned long start,
						unsigned long end)
{
	pte_t *pte;
	struct page *page;
	unsigned long addr;

	for (addr = start & PAGE_MASK; addr < end; addr += PAGE_SIZE) {
		pte = pte_offset_kernel(pmd, addr);
		BUG_ON(!virt_addr_valid(addr));
		page = virt_to_page(addr);

		set_pte_ext(pte, mk_pte(page, PAGE_HYP), 0);
	}
}

static int create_hyp_pmd_mappings(pud_t *pud, unsigned long start,
					       unsigned long end)
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
		create_hyp_pte_mappings(pmd, addr, next);
	}

	return 0;
}

/**
 * create_hyp_mappings - map a kernel virtual address range in Hyp mode
 * @hyp_pgd:	The allocated hypervisor level-1 table
 * @from:	The virtual kernel start address of the range
 * @to:		The virtual kernel end address of the range (exclusive)
 *
 * The same virtual address as the kernel virtual address is also used in
 * Hyp-mode mapping to the same underlying physical pages.
 *
 * Note: Wrapping around zero in the "to" address is not supported.
 */
int create_hyp_mappings(pgd_t *hyp_pgd, void *from, void *to)
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
		err = create_hyp_pmd_mappings(pud, addr, next);
		if (err)
			goto out;
	}
out:
	mutex_unlock(&kvm_hyp_pgd_mutex);
	return err;
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
 * destroyed, which can only be done once.
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
	kvm->arch.pgd = pgd;

	return 0;
}

static void free_guest_pages(pte_t *pte, unsigned long addr)
{
	unsigned int i;
	struct page *page;

	for (i = 0; i < PTRS_PER_PTE; i++, addr += PAGE_SIZE) {
		if (!pte_present(*pte))
			goto next_page;
		page = pfn_to_page(pte_pfn(*pte));
		put_page(page);
next_page:
		pte++;
	}
}

static void free_stage2_ptes(pmd_t *pmd, unsigned long addr)
{
	unsigned int i;
	pte_t *pte;
	struct page *page;

	for (i = 0; i < PTRS_PER_PMD; i++, addr += PMD_SIZE) {
		BUG_ON(pmd_sect(*pmd));
		if (!pmd_none(*pmd) && pmd_table(*pmd)) {
			pte = pte_offset_kernel(pmd, addr);
			free_guest_pages(pte, addr);
			page = virt_to_page((void *)pte);
			WARN_ON(atomic_read(&page->_count) != 1);
			pte_free_kernel(NULL, pte);
		}
		pmd++;
	}
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

		if (pud_none(*pud))
			continue;

		BUG_ON(pud_bad(*pud));

		pmd = pmd_offset(pud, addr);
		free_stage2_ptes(pmd, addr);
		pmd_free(NULL, pmd);
	}

	free_pages((unsigned long)kvm->arch.pgd, PGD2_ORDER);
	kvm->arch.pgd = NULL;
}

static const pte_t null_pte;

static int stage2_set_pte(struct kvm *kvm, phys_addr_t addr, const pte_t *new_pte)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* Create 2nd stage page table mapping - Level 1 */
	pgd = kvm->arch.pgd + pgd_index(addr);
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud)) {
		BUG_ON(new_pte == &null_pte);
		pmd = pmd_alloc_one(NULL, addr);
		if (!pmd) {
			kvm_err("Cannot allocate 2nd stage pmd\n");
			return -ENOMEM;
		}
		pud_populate(NULL, pud, pmd);
		pmd += pmd_index(addr);
	} else
		pmd = pmd_offset(pud, addr);

	/* Create 2nd stage page table mapping - Level 2 */
	if (pmd_none(*pmd)) {
		BUG_ON(new_pte == &null_pte);
		pte = pte_alloc_one_kernel(NULL, addr);
		if (!pte) {
			kvm_err("Cannot allocate 2nd stage pte\n");
			return -ENOMEM;
		}
		pmd_populate_kernel(NULL, pmd, pte);
		pte += pte_index(addr);
	} else
		pte = pte_offset_kernel(pmd, addr);

	/* Create 2nd stage page table mapping - Level 3 */
	set_pte_ext(pte, *new_pte, 0);

	return 0;
}

static int user_mem_abort(struct kvm_vcpu *vcpu, phys_addr_t fault_ipa,
			  gfn_t gfn, struct kvm_memory_slot *memslot)
{
	pte_t new_pte;
	pfn_t pfn;
	int ret;

	pfn = gfn_to_pfn(vcpu->kvm, gfn);

	if (is_error_pfn(pfn)) {
		put_page(pfn_to_page(pfn));
		kvm_err("Guest gfn %u (0x%08x) does not have \n"
				"corresponding host mapping",
				(unsigned int)gfn,
				(unsigned int)gfn << PAGE_SHIFT);
		return -EFAULT;
	}

	mutex_lock(&vcpu->kvm->arch.pgd_mutex);
	new_pte = pfn_pte(pfn, PAGE_KVM_GUEST);
	ret = stage2_set_pte(vcpu->kvm, fault_ipa, &new_pte);
	if (ret)
		put_page(pfn_to_page(pfn));
	mutex_unlock(&vcpu->kvm->arch.pgd_mutex);

	return ret;
}

#define HSR_ABT_FS	(0x3f)
#define HPFAR_MASK	(~0xf)

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

	hsr_ec = vcpu->arch.hsr >> HSR_EC_SHIFT;
	is_iabt = (hsr_ec == HSR_EC_IABT);

	/* Check that the second stage fault is a translation fault */
	fault_status = vcpu->arch.hsr & HSR_ABT_FS;
	if ((fault_status & 0x3c) != 0x4) {
		kvm_err("Unsupported fault status: %lx\n",
				fault_status & 0x3c);
		return -EFAULT;
	}

	fault_ipa = ((phys_addr_t)vcpu->arch.hpfar & HPFAR_MASK) << 8;

	gfn = fault_ipa >> PAGE_SHIFT;
	if (!kvm_is_visible_gfn(vcpu->kvm, gfn)) {
		if (is_iabt) {
			kvm_err("Inst. abort on I/O address %08lx\n",
				(unsigned long)fault_ipa);
			return -EFAULT;
		}

		kvm_pr_unimpl("I/O address abort...");
		return 0;
	}

	memslot = gfn_to_memslot(vcpu->kvm, gfn);
	if (!memslot->user_alloc) {
		kvm_err("non user-alloc memslots not supported\n");
		return -EINVAL;
	}

	return user_mem_abort(vcpu, fault_ipa, gfn, memslot);
}

int kvm_unmap_hva(struct kvm *kvm, unsigned long hva)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int needs_stage2_flush = 0;

	slots = kvm_memslots(kvm);

	/* we only care about the pages that the guest sees */
	kvm_for_each_memslot(memslot, slots) {
		unsigned long start = memslot->userspace_addr;
		unsigned long end;

		end = start + (memslot->npages << PAGE_SHIFT);
		if (hva >= start && hva < end) {
			gpa_t gpa_offset = hva - start;
			gpa_t gpa = (memslot->base_gfn << PAGE_SHIFT) + gpa_offset;

			stage2_set_pte(kvm, gpa, &null_pte);
			needs_stage2_flush = 1;
		}
	}

	if (needs_stage2_flush)
		__kvm_tlb_flush_vmid(kvm);

	return 0;
}

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
#include <asm/idmap.h>
#include <asm/pgalloc.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <asm/mach/map.h>

static DEFINE_MUTEX(kvm_hyp_pgd_mutex);
static pgd_t *hyp_pgd;

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

int kvm_handle_guest_abort(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return -EINVAL;
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

/*
 * arch/arm/mm/hugetlbpage-2level.c
 *
 * Copyright (C) 2002, Rohit Seth <rohit.seth@intel.com>
 * Copyright (C) 2012 ARM Ltd
 * Copyright (C) 2012 Bill Carson.
 *
 * Based on arch/x86/include/asm/hugetlb.h and Bill Carson's patches
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/err.h>
#include <linux/sysctl.h>
#include <asm/mman.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>

int huge_pmd_unshare(struct mm_struct *mm, unsigned long *addr, pte_t *ptep)
{
	return 0;
}

pte_t *huge_pte_alloc(struct mm_struct *mm,
			unsigned long addr, unsigned long sz)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);

	return (pte_t *)pmd; /* our huge pte is actually a pmd */
}

struct page *follow_huge_pmd(struct mm_struct *mm, unsigned long address,
			     pmd_t *pmd, int write)
{
	struct page *page;
	unsigned long pfn;

	BUG_ON((pmd_val(*pmd) & PMD_TYPE_MASK) != PMD_TYPE_SECT);
	pfn = ((pmd_val(*pmd) & HPAGE_MASK) >> PAGE_SHIFT);
	page = pfn_to_page(pfn);
	return page;
}

pte_t huge_ptep_get(pte_t *ptep)
{
	pmd_t *pmdp = (pmd_t*)ptep;
	pmdval_t pmdval = pmd_val(*pmdp);
	pteval_t retval;

	if (!pmdval)
		return __pte(0);

	retval = (pteval_t) (pmdval & HPAGE_MASK);
	HPMD_XLATE(retval, pmdval, PMD_SECT_XN, L_PTE_XN);
	HPMD_XLATE(retval, pmdval, PMD_SECT_S, L_PTE_SHARED);
	HPMD_XLATE(retval, pmdval, PMD_DSECT_AF, L_PTE_YOUNG);
	HPMD_XLATE(retval, pmdval, PMD_DSECT_DIRTY, L_PTE_DIRTY);

	/* preserve bits C & B */
	retval |= (pmdval & (3 << 2));

	/* PMD TEX bit 0 corresponds to Linux PTE bit 4 */
	HPMD_XLATE(retval, pmdval, PMD_SECT_TEX(1), 1 << 4);

	if (pmdval & PMD_SECT_AP_WRITE)
		retval &= ~L_PTE_RDONLY;
	else
		retval |= L_PTE_RDONLY;

	if ((pmdval & PMD_TYPE_MASK) == PMD_TYPE_SECT)
		retval |= L_PTE_VALID;

	/* we assume all hugetlb pages are user */
	retval |= L_PTE_USER;

	return __pte(retval);
}

void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
				   pte_t *ptep, pte_t pte)
{
	pmdval_t pmdval = (pmdval_t) pte_val(pte);
	pmd_t *pmdp = (pmd_t*) ptep;

	pmdval &= HPAGE_MASK;
	pmdval |= PMD_SECT_AP_READ | PMD_SECT_nG | PMD_TYPE_SECT;
	pmdval = pmd_val(pmd_modify(__pmd(pmdval), __pgprot(pte_val(pte))));

	__sync_icache_dcache(pte);

	set_pmd_at(mm, addr, pmdp, __pmd(pmdval));
}

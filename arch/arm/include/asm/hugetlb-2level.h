/*
 * arch/arm/include/asm/hugetlb-2level.h
 *
 * Copyright (C) 2012 ARM Ltd.
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

#ifndef _ASM_ARM_HUGETLB_2LEVEL_H
#define _ASM_ARM_HUGETLB_2LEVEL_H


pte_t huge_ptep_get(pte_t *ptep);

void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
				   pte_t *ptep, pte_t pte);

static inline pte_t pte_mkhuge(pte_t pte) { return pte; }

static inline void huge_ptep_clear_flush(struct vm_area_struct *vma,
					 unsigned long addr, pte_t *ptep)
{
	flush_tlb_range(vma, addr, addr + HPAGE_SIZE);
}

static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	pmd_t *pmdp = (pmd_t *) ptep;
	set_pmd_at(mm, addr, pmdp, pmd_wrprotect(*pmdp));
}


static inline pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
					    unsigned long addr, pte_t *ptep)
{
	pmd_t *pmdp = (pmd_t *)ptep;
	pte_t pte = huge_ptep_get(ptep);
	pmd_clear(pmdp);

	return pte;
}

static inline int huge_ptep_set_access_flags(struct vm_area_struct *vma,
					     unsigned long addr, pte_t *ptep,
					     pte_t pte, int dirty)
{
	int changed = !pte_same(huge_ptep_get(ptep), pte);

	if (changed) {
		set_huge_pte_at(vma->vm_mm, addr, ptep, pte);
		huge_ptep_clear_flush(vma, addr, &pte);
	}

	return changed;
}

#endif /* _ASM_ARM_HUGETLB_2LEVEL_H */

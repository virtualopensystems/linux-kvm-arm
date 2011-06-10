#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>

#include <asm/cputype.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

static void idmap_add_pmd(pgd_t *pgd, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pmd_t *pmd;

#ifdef CONFIG_ARM_LPAE
	if (pgd_none_or_clear_bad(pgd) || (pgd_val(*pgd) & L_PGD_SWAPPER)) {
		pmd = pmd_alloc_one(NULL, addr);
		if (!pmd) {
			pr_warning("Failed to allocate identity pmd.\n");
			return;
		}
		pgd_populate(NULL, pgd, pmd);
		pmd += pmd_index(addr);
	} else
#endif
		pmd = pmd_offset(pgd, addr);

	addr = (addr & PMD_MASK) | prot;
	pmd[0] = __pmd(addr);
#ifndef CONFIG_ARM_LPAE
	addr += SECTION_SIZE;
	pmd[1] = __pmd(addr);
#endif
	flush_pmd_entry(pmd);
}

static void __identity_mapping_add(pgd_t *pgd, unsigned long addr,
				   unsigned long end, bool hyp_mapping)
{
	unsigned long prot, next;

	prot = PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AF;

	if (hyp_mapping)
		prot |= PMD_SECT_AP1;

	if (cpu_architecture() <= CPU_ARCH_ARMv5TEJ && !cpu_is_xscale())
		prot |= PMD_BIT4;

	do {
		next = pmd_addr_end(addr, end);
		idmap_add_pmd(pgd + pgd_index(addr), addr, next, prot);
	} while (addr = next, addr < end);
}

void identity_mapping_add(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	__identity_mapping_add(pgd, addr, end, false);
}


#ifdef CONFIG_SMP
static void idmap_del_pmd(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	pmd_t *pmd;

	if (pgd_none_or_clear_bad(pgd))
		return;
	pmd = pmd_offset(pgd, addr);
	pmd_clear(pmd);
}

void identity_mapping_del(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	unsigned long next;

	do {
		next = pmd_addr_end(addr, end);
		idmap_del_pmd(pgd + pgd_index(addr), addr, next);
	} while (addr = next, addr < end);
}
#endif

#ifdef CONFIG_KVM_ARM_HOST
void hyp_identity_mapping_add(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	__identity_mapping_add(pgd, addr, end, true);
}
EXPORT_SYMBOL_GPL(hyp_identity_mapping_add);

static void hyp_idmap_del_pmd(pgd_t *pgd, unsigned long addr)
{
	pmd_t *pmd;

	pmd = pmd_offset(pgd, addr);
	pmd_free(NULL, pmd);
}

/*
 * This version actually frees the underlying pmds for all pgds in range and
 * clear the pgds themselves afterwards.
 */
void hyp_identity_mapping_del(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	unsigned long next;
	pgd_t *next_pgd;

	do {
		next = pgd_addr_end(addr, end);
		next_pgd = pgd + pgd_index(addr);
		if (!pgd_none_or_clear_bad(next_pgd)) {
			hyp_idmap_del_pmd(next_pgd, addr);
			pgd_clear(next_pgd);
		}
	} while (addr = next, addr < end);
}
EXPORT_SYMBOL_GPL(hyp_identity_mapping_del);
#endif

/*
 * In order to soft-boot, we need to insert a 1:1 mapping in place of
 * the user-mode pages.  This will then ensure that we have predictable
 * results when turning the mmu off
 */
void setup_mm_for_reboot(char mode)
{
	/*
	 * We need to access to user-mode page tables here. For kernel threads
	 * we don't have any user-mode mappings so we use the context that we
	 * "borrowed".
	 */
	identity_mapping_add(current->active_mm->pgd, 0, TASK_SIZE);
	local_flush_tlb_all();
}

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include <asm/cputype.h>
#include <asm/idmap.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/sections.h>
#include <asm/system_info.h>
#include <asm/virt.h>

pgd_t *idmap_pgd;

#ifdef CONFIG_ARM_LPAE
static void idmap_add_pmd(pud_t *pud, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pmd_t *pmd;
	unsigned long next;

	if (pud_none_or_clear_bad(pud) || (pud_val(*pud) & L_PGD_SWAPPER)) {
		pmd = pmd_alloc_one(&init_mm, addr);
		if (!pmd) {
			pr_warning("Failed to allocate identity pmd.\n");
			return;
		}
		pud_populate(&init_mm, pud, pmd);
		pmd += pmd_index(addr);
	} else
		pmd = pmd_offset(pud, addr);

	do {
		next = pmd_addr_end(addr, end);
		*pmd = __pmd((addr & PMD_MASK) | prot);
		flush_pmd_entry(pmd);
	} while (pmd++, addr = next, addr != end);
}
#else	/* !CONFIG_ARM_LPAE */
static void idmap_add_pmd(pud_t *pud, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pmd_t *pmd = pmd_offset(pud, addr);

	addr = (addr & PMD_MASK) | prot;
	pmd[0] = __pmd(addr);
	addr += SECTION_SIZE;
	pmd[1] = __pmd(addr);
	flush_pmd_entry(pmd);
}
#endif	/* CONFIG_ARM_LPAE */

static void idmap_add_pud(pgd_t *pgd, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		idmap_add_pmd(pud, addr, next, prot);
	} while (pud++, addr = next, addr != end);
}

static void identity_mapping_add(pgd_t *pgd, const char *text_start,
				 const char *text_end, unsigned long prot)
{
	unsigned long addr, end;
	unsigned long next;

	addr = virt_to_phys(text_start);
	end = virt_to_phys(text_end);

	pr_info("Setting up static %sidentity map for 0x%llx - 0x%llx\n",
		prot ? "HYP " : "",
		(long long)addr, (long long)end);
	prot |= PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AF;

	if (cpu_architecture() <= CPU_ARCH_ARMv5TEJ && !cpu_is_xscale())
		prot |= PMD_BIT4;

	pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		idmap_add_pud(pgd, addr, next, prot);
	} while (pgd++, addr = next, addr != end);
}

extern char  __idmap_text_start[], __idmap_text_end[];

static int __init init_static_idmap(void)
{
	idmap_pgd = pgd_alloc(&init_mm);
	if (!idmap_pgd)
		return -ENOMEM;

	identity_mapping_add(idmap_pgd, __idmap_text_start,
			     __idmap_text_end, 0);

	return 0;
}
early_initcall(init_static_idmap);

#if defined(CONFIG_ARM_VIRT_EXT) && defined(CONFIG_ARM_LPAE)
pgd_t *hyp_pgd;
EXPORT_SYMBOL_GPL(hyp_pgd);

static void hyp_idmap_del_pmd(pgd_t *pgd, unsigned long addr)
{
	pud_t *pud;
	pmd_t *pmd;

	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	pud_clear(pud);
	clean_pmd_entry(pmd);
	pmd_free(NULL, (pmd_t *)((unsigned long)pmd & PAGE_MASK));
}

extern char  __hyp_idmap_text_start[], __hyp_idmap_text_end[];

/*
 * This version actually frees the underlying pmds for all pgds in range and
 * clear the pgds themselves afterwards.
 */
void hyp_idmap_teardown(void)
{
	unsigned long addr, end;
	unsigned long next;
	pgd_t *pgd = hyp_pgd;

	addr = virt_to_phys(__hyp_idmap_text_start);
	end = virt_to_phys(__hyp_idmap_text_end);

	pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		if (!pgd_none_or_clear_bad(pgd))
			hyp_idmap_del_pmd(pgd, addr);
	} while (pgd++, addr = next, addr < end);
}
EXPORT_SYMBOL_GPL(hyp_idmap_teardown);

void hyp_idmap_setup(void)
{
	identity_mapping_add(hyp_pgd, __hyp_idmap_text_start,
			     __hyp_idmap_text_end, PMD_SECT_AP1);
}
EXPORT_SYMBOL_GPL(hyp_idmap_setup);

static int __init hyp_init_static_idmap(void)
{
	if (!is_hyp_mode_available())
		return 0;

	hyp_pgd = kzalloc(PTRS_PER_PGD * sizeof(pgd_t), GFP_KERNEL);
	if (!hyp_pgd)
		return -ENOMEM;

	hyp_idmap_setup();

	return 0;
}
early_initcall(hyp_init_static_idmap);
#endif

/*
 * In order to soft-boot, we need to switch to a 1:1 mapping for the
 * cpu_reset functions. This will then ensure that we have predictable
 * results when turning off the mmu.
 */
void setup_mm_for_reboot(void)
{
	/* Clean and invalidate L1. */
	flush_cache_all();

	/* Switch to the identity mapping. */
	cpu_switch_mm(idmap_pgd, &init_mm);

	/* Flush the TLB. */
	local_flush_tlb_all();
}

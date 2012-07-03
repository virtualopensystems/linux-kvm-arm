#ifndef __ASM_IDMAP_H
#define __ASM_IDMAP_H

#include <linux/compiler.h>
#include <asm/pgtable.h>

/* Tag a function as requiring to be executed via an identity mapping. */
#define __idmap __section(.idmap.text) noinline notrace

extern pgd_t *idmap_pgd;

void setup_mm_for_reboot(void);

#ifdef CONFIG_ARM_VIRT_EXT
extern pgd_t *hyp_pgd;

void hyp_idmap_teardown(void);
void hyp_idmap_setup(void);
#endif

#endif	/* __ASM_IDMAP_H */

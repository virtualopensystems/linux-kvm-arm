#ifndef __EXYNOS4_CORE_H
#define __EXYNOS4_CORE_H

#include <asm/soc.h>

extern struct arm_soc_smp_init_ops	exynos4_soc_smp_init_ops;
extern struct arm_soc_smp_ops		exynos4_soc_smp_ops;
extern struct arm_soc_desc		exynos4_soc_desc;

extern int  exynos4_cpu_kill(unsigned int cpu);
extern void exynos4_cpu_die(unsigned int cpu);
extern int  exynos4_cpu_disable(unsigned int cpu);

#endif /* __EXYNOS4_CORE_H */

#include <asm/soc.h>

extern struct arm_soc_smp_init_ops	msm_soc_smp_init_ops;
extern struct arm_soc_smp_ops		msm_soc_smp_ops;
extern struct arm_soc_desc		msm_soc_desc;

extern int  msm_cpu_kill(unsigned int cpu);
extern void msm_cpu_die(unsigned int cpu);
extern int  msm_cpu_disable(unsigned int cpu);

#ifndef __ASM_ARM_KVM_ARCH_TIMER_H
#define __ASM_ARM_KVM_ARCH_TIMER_H

#include <linux/clocksource.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>

struct arch_timer_kvm {
#ifdef CONFIG_KVM_ARM_TIMER
	bool			enabled;
	union {
		cycle_t		cntvoff;
		struct {
			u32	cntvoff_high; /* Restored only */
			u32	cntvoff_low;  /* Restored only */
		} cntvoff32;
	};
#endif
};

struct arch_timer_cpu {
#ifdef CONFIG_KVM_ARM_TIMER
	struct hrtimer		timer;
	struct work_struct	expired;
	cycle_t			cval;
	bool			armed;

	/* Registers */
	u32			cntv_ctl;	/* Saved/restored */
	u32			cntv_cval_high;	/* Saved/restored */
	u32			cntv_cval_low;	/* Saved/restored */
#endif
};

#ifdef CONFIG_KVM_ARM_TIMER
int kvm_timer_hyp_init(void);
int kvm_timer_init(struct kvm *kvm);
void kvm_timer_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_timer_sync_to_cpu(struct kvm_vcpu *vcpu);
void kvm_timer_sync_from_cpu(struct kvm_vcpu *vcpu);
void kvm_timer_vcpu_terminate(struct kvm_vcpu *vcpu);
#else
static inline int kvm_timer_hyp_init(void)
{
	return 0;
};

static inline int kvm_timer_init(struct kvm *kvm)
{
	return 0;
}

static inline void kvm_timer_vcpu_init(struct kvm_vcpu *vcpu) {}
static inline void kvm_timer_sync_to_cpu(struct kvm_vcpu *vcpu) {}
static inline void kvm_timer_sync_from_cpu(struct kvm_vcpu *vcpu) {}
static inline void kvm_timer_vcpu_terminate(struct kvm_vcpu *vcpu) {}
#endif

#endif

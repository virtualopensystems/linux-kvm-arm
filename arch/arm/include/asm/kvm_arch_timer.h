#ifndef __ASM_ARM_KVM_ARCH_TIMER_H
#define __ASM_ARM_KVM_ARCH_TIMER_H

struct arch_timer_kvm {
};

struct arch_timer_cpu {
};

#ifndef CONFIG_KVM_ARM_TIMER
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

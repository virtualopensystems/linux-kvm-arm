#ifndef __ASM_ARM_KVM_VGIC_H
#define __ASM_ARM_KVM_VGIC_H

struct vgic_dist {
};

struct vgic_cpu {
};

struct kvm;
struct kvm_vcpu;
struct kvm_run;
struct kvm_exit_mmio;

#ifdef CONFIG_KVM_ARM_VGIC
int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run,
		     struct kvm_exit_mmio *mmio);
#else
static inline int kvm_vgic_hyp_init(void)
{
	return 0;
}

static inline int kvm_vgic_init(struct kvm *kvm)
{
	return 0;
}

static inline void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu) {}
static inline void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu) {}
static inline void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu) {}

static inline int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run,
				   struct kvm_exit_mmio *mmio)
{
	return KVM_EXIT_MMIO;
}

static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return 0;
}
#endif

#endif

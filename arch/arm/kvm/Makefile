#
# Makefile for Kernel-based Virtual Machine module
#

ccflags-y += -Ivirt/kvm -Iarch/arm/kvm
CFLAGS_arm.o := -I.

EXTRA_CFLAGS += -Ivirt/kvm -Iarch/arm/kvm
AFLAGS_arm_interrupts.o := -I$(obj)

obj-$(CONFIG_KVM_ARM_HOST) += arm_init.o arm_interrupts.o arm_exports.o

kvm-arm-y += $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o)

kvm-arm-y += arm.o arm_guest.o arm_mmu.o arm_emulate.o debug.o

obj-$(CONFIG_KVM) += kvm-arm.o

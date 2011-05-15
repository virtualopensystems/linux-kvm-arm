#
# Makefile for Kernel-based Virtual Machine module
#

EXTRA_CFLAGS += -Ivirt/kvm -Iarch/arm/kvm
AFLAGS_arm_interrupts.o := -I$(obj)

kvm-arm-y += $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o)

kvm-arm-y += arm.o arm_guest.o arm_interrupts.o arm_mmu.o arm_emulate.o \
		trace.o

obj-$(CONFIG_KVM) += kvm-arm.o

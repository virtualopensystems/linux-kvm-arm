#
# Makefile for Kernel-based Virtual Machine module
#

EXTRA_CFLAGS += -Ivirt/kvm -Iarch/arm/kvm

common-objs = $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o)

kvm-objs := $(common-objs)
obj-$(CONFIG_KVM) += kvm.o

AFLAGS_arm_interrupts.o := -I$(obj)

kvm-arm-objs := arm.o arm_guest.o arm_interrupts.o arm_mmu.o arm_emulate.o \
		trace.o
obj-$(CONFIG_KVM_ARM_HOST) += kvm-arm.o

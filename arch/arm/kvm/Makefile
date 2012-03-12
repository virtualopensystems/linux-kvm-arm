#
# Makefile for Kernel-based Virtual Machine module
#

ccflags-y += -Ivirt/kvm -Iarch/arm/kvm
CFLAGS_arm.o     := -I.
CFLAGS_mmu.o := -I.

AFLAGS_interrupts.o := -I$(obj)

obj-$(CONFIG_KVM_ARM_HOST) += init.o interrupts.o exports.o

kvm-arm-y += $(addprefix ../../../virt/kvm/, kvm_main.o coalesced_mmio.o)

kvm-arm-y += arm.o guest.o mmu.o emulate.o

obj-$(CONFIG_KVM) += kvm-arm.o

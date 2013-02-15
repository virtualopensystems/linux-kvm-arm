/*
 * guest-driver - start fake VM and test MMIO operations
 * Copyright (C) 2012 Christoffer Dall <cdall@cs.columbia.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <err.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <asm/kvm.h>
#include <elf.h>
#include <err.h>
#include <getopt.h>
#include <stddef.h>
 
#include "io_common.h"
#include "guest-driver.h"

static int sys_fd;
static int vm_fd;
static int vcpu_fd;
static struct kvm_run *kvm_run;
static void *code_base;
static struct kvm_userspace_memory_region code_mem;

static void create_vm(void)
{
	vm_fd = ioctl(sys_fd, KVM_CREATE_VM, 0);
	if (vm_fd < 0)
		err(EXIT_SETUPFAIL, "kvm_create_vm failed");
}

static void create_vcpu(void)
{
	int mmap_size;
	struct kvm_vcpu_init init = { KVM_ARM_TARGET_CORTEX_A15, { 0 } };

	vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
	if (vcpu_fd < 0)
		err(EXIT_SETUPFAIL, "kvm_create_vcpu failed");

	if (ioctl(vcpu_fd, KVM_ARM_VCPU_INIT, &init) != 0)
		err(EXIT_SETUPFAIL, "KVM_ARM_VCPU_INIT failed");

	mmap_size = ioctl(sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size < 0)
		err(EXIT_SETUPFAIL, "KVM_GET_VCPU_MMAP_SIZE failed");

	kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		       vcpu_fd, 0);
	if (kvm_run == MAP_FAILED)
		err(EXIT_SETUPFAIL, "mmap VCPU run failed!");
}

static void kvm_register_mem(int id, void *addr, unsigned long base,
			    struct kvm_userspace_memory_region *mem)
{
	int ret;

	mem->slot = id;
	mem->guest_phys_addr = base;
	mem->memory_size = RAM_SIZE;
	mem->userspace_addr = (unsigned long)addr;
	mem->flags = 0;

	ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, mem);
	if (ret < 0)
		err(EXIT_SETUPFAIL, "error registering region: %d", id);
}

static void register_memregions(void)
{
	code_base = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, 0, CODE_PHYS_BASE);
	if (code_base == MAP_FAILED) {
		err(EXIT_SETUPFAIL, "mmap RAM region failed");
	} else if ((unsigned long)code_base & ~PAGE_MASK) {
		errx(EXIT_SETUPFAIL, "mmap RAM on non-page boundary: %p",
		     code_base);
	}
	kvm_register_mem(CODE_SLOT, code_base, CODE_PHYS_BASE, &code_mem);
}

static void read_elf(int elf_fd, const Elf32_Ehdr *ehdr)
{
	Elf32_Phdr phdr[ehdr->e_phnum];
	unsigned int i;

	/* We read in all the program headers at once: */
	if (pread(elf_fd, phdr, sizeof(phdr), ehdr->e_phoff) != sizeof(phdr))
		err(EXIT_SETUPFAIL, "Reading program headers");

	/*
	 * Try all the headers: there are usually only three.  A read-only one,
	 * a read-write one, and a "note" section which we don't load.
	 */
	for (i = 0; i < ehdr->e_phnum; i++) {
		void *dest;

		/* If this isn't a loadable segment, we ignore it */
		if (phdr[i].p_type != PT_LOAD)
			continue;

		dest = code_base + phdr[i].p_paddr - CODE_PHYS_BASE;
		if (dest < code_base
		    || dest + phdr[i].p_memsz > code_base + RAM_SIZE) {
			errx(EXIT_SETUPFAIL, "Section %u@%p out of bounds",
			     phdr[i].p_memsz, (void *)phdr[i].p_paddr);
		}

		if (pread(elf_fd, dest, phdr[i].p_memsz, phdr[i].p_offset)
		    != phdr[i].p_memsz) {
			err(EXIT_SETUPFAIL, "Reading in elf section");
		}
	}
}

static unsigned long load_code(const char *code_file)
{
	int fd = open(code_file, O_RDONLY);
	Elf32_Ehdr ehdr;

	if (fd < 0)
		err(EXIT_SETUPFAIL, "cannot open code file %s", code_file);

	/* Read in the first few bytes. */
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
		err(EXIT_SETUPFAIL, "Reading code file %s", code_file);

	/* If it's an ELF file, it starts with "\177ELF" */
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
	    || ehdr.e_type != ET_EXEC
	    || ehdr.e_machine != EM_ARM
	    || ehdr.e_phentsize != sizeof(Elf32_Phdr)
	    || ehdr.e_phnum < 1 || ehdr.e_phnum > 65536U/sizeof(Elf32_Phdr))
		errx(EXIT_SETUPFAIL, "Malformed elf file %s", code_file);

	read_elf(fd, &ehdr);
	close(fd);
	return ehdr.e_entry;
}

static void init_vcpu(unsigned long start)
{
	struct kvm_one_reg reg;
	__u32 lr = CODE_PHYS_BASE + RAM_SIZE;
	__u64 core_id = KVM_REG_ARM | KVM_REG_SIZE_U32 | KVM_REG_ARM_CORE;

	reg.id = core_id | KVM_REG_ARM_CORE_REG(usr_regs.ARM_pc);
	reg.addr = (long)&start;
	if (ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg) != 0)
		err(EXIT_SETUPFAIL, "error setting PC (%#llx)", reg.id);

	reg.id = core_id | KVM_REG_ARM_CORE_REG(svc_regs[2]);
	reg.addr = (long)&lr;
	if (ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg) != 0)
		err(EXIT_SETUPFAIL, "error setting LR");
}

static void init_vgic(void)
{
	struct kvm_arm_device_addr kda;
	int ret;

	ret = ioctl(vm_fd, KVM_CREATE_IRQCHIP, 0);
	if (ret) {
		err(EXIT_SETUPFAIL, "error creating irqchip: %d", errno);
	}

	/* Set Vexpress VGIC base addresses */

	kda.id = KVM_ARM_DEVICE_VGIC_V2 << KVM_ARM_DEVICE_ID_SHIFT;
	kda.id |= KVM_VGIC_V2_ADDR_TYPE_DIST;
	kda.addr = 0x2c000000 + 0x1000;

	ret = ioctl(vm_fd, KVM_ARM_SET_DEVICE_ADDR, &kda);
	if (ret)
		err(EXIT_SETUPFAIL, "error setting dist addr: %d", errno);

	kda.id = KVM_ARM_DEVICE_VGIC_V2 << KVM_ARM_DEVICE_ID_SHIFT;
	kda.id |= KVM_VGIC_V2_ADDR_TYPE_CPU;
	kda.addr = 0x2c000000 + 0x2000;

	ret = ioctl(vm_fd, KVM_ARM_SET_DEVICE_ADDR, &kda);
	if (ret)
		err(EXIT_SETUPFAIL, "error setting cpu addr: %d", errno);
}

/* Returns true to shut down. */
static bool handle_mmio(struct kvm_run *kvm_run,
			bool (*test)(struct kvm_run *kvm_run, int vcpu_fd))
{
	unsigned long phys_addr;
	unsigned char *data;
	bool is_write;

	if (kvm_run->exit_reason != KVM_EXIT_MMIO)
		return false;

	phys_addr = (unsigned long)kvm_run->mmio.phys_addr;
	data = kvm_run->mmio.data;
	is_write = kvm_run->mmio.is_write;

	/* Test if it's a control operation */
	switch (phys_addr) {
	case IO_CTL_STATUS:
		if (!is_write)
			errx(EXIT_SETUPFAIL, "Guest read from IO_CTL_STATUS");
		if (data[0] == 0) {
			printf(".");
			return false;
		} else {
			errx(EXIT_FAILURE, "TEST FAIL");
		}

	case IO_CTL_PRINT:
		if (!is_write)
			errx(EXIT_SETUPFAIL, "Guest read from IO_CTL_PRINT");
		printf("%c", data[0]);
		return false;

	case IO_CTL_EXIT:
		printf("VM shutting down status %i\n", data[0]);
		if (data[0] != 0)
			exit(data[0]);
		return true;

	default:
		/* Let this test handle it. */
		if (test && test(kvm_run, vcpu_fd))
			return false;
		errx(EXIT_FAILURE,
		     "Guest accessed unexisting mem area: %#08lx + %#08x",
		     phys_addr, kvm_run->mmio.len);
	}
}

static void kvm_cpu_exec(bool (*test)(struct kvm_run *kvm_run, int vcpu_fd))
{
	do {
		int ret = ioctl(vcpu_fd, KVM_RUN, 0);

		if (ret == -EINTR || ret == -EAGAIN) {
			continue;
		} else if (ret < 0)
			err(EXIT_SETUPFAIL, "Error running vcpu");
	} while (!handle_mmio(kvm_run, test));
}

/* Linker-generated symbols for GUEST_TEST() macros */
extern struct test __start_tests[], __stop_tests[];


static void usage(int argc, char * const *argv)
{
	struct test *i;
	fprintf(stderr, "Usage: %s <testname>\n\n", argv[0]);
	fprintf(stderr, "Available test:\n");

	for (i = __start_tests; i < __stop_tests; i++)
		fprintf(stderr, " - %s:\n", i->name);

	errx(EXIT_SETUPFAIL, "failed");
}


int main(int argc, char * const *argv)
{
	struct test *i;
	const char *file = NULL;
	bool (*test)(struct kvm_run *kvm_run, int vcpu_fd);
	unsigned long start;
	int opt;
	bool use_vgic = false;
	char *test_name;

	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
		case 'v':
			use_vgic = true;
			break;
		default:
			usage(argc, argv);
		}
	}

	if (optind >= argc)
		usage(argc, argv);

	test_name = argv[optind];
	for (i = __start_tests; i < __stop_tests; i++) {
		if (strcmp(i->name, test_name) == 0) {
			test = i->mmiofn;
			file = i->binname;
			break;
		}
	}
	if (!file)
		errx(EXIT_SETUPFAIL, "Unknown test '%s'", argv[1]);

	printf("Starting VM with code from: %s\n", file);

	sys_fd = open("/dev/kvm", O_RDWR);
	if (sys_fd < 0)
		err(EXIT_SETUPFAIL, "cannot open /dev/kvm - module loaded?");

	create_vm();
	register_memregions();
	if (use_vgic)
		init_vgic();
	start = load_code(file);
	create_vcpu();
	init_vcpu(start);
	kvm_cpu_exec(test);
	return EXIT_SUCCESS;
}

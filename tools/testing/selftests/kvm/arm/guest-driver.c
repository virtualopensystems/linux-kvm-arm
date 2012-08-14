/*
 * guest-driver - start fake VM and test MMIO operations
 * Copyright (C) 2012 Christoffer Dall <cdall@cs.columbia.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.# 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/kvm.h>

#include "io_common.h"
#include "guest-driver.h"

static int sys_fd;
static int vm_fd;
static int vcpu_fd;
static struct kvm_run *kvm_run;
static void *code_base;
static struct kvm_userspace_memory_region code_mem;



static int create_vm(void)
{
	vm_fd = ioctl(sys_fd, KVM_CREATE_VM, 0);
	if (vm_fd < 0) {
		perror("kvm_create_vm failed");
		return -1;
	}

	return 0;
}

static int create_vcpu(void)
{
	int mmap_size;

	vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
	if (vcpu_fd < 0) {
		perror("kvm_create_vcpu failed");
		return -1;
	}

	mmap_size = ioctl(sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size < 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE failed");
		return -1;
	}

	kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		       vcpu_fd, 0);
	if (kvm_run == MAP_FAILED) {
		perror("mmap VCPU run failed!");
		return -1;
	}

	return 0;
}

static int kvm_register_mem(int id, void *addr, unsigned long base,
			    struct kvm_userspace_memory_region *mem)
{
	int ret;

	mem->slot = id;
	mem->guest_phys_addr = base;
	mem->memory_size = RAM_SIZE;
	mem->userspace_addr = (unsigned long)addr;
	mem->flags = 0;

	ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, mem);
	if (ret < 0) {
		pr_errno("error registering region: %d", id);
		return -1;
	}
	return 0;
}

static int register_memregions(void)
{
	int ret;

	code_base = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, 0, CODE_PHYS_BASE);
	if (code_base == MAP_FAILED) {
		perror("mmap RAM region failed");
		return -1;
	} else if ((unsigned long)code_base & ~PAGE_MASK) {
		pr_err("mmap RAM on non-page boundary: %p", code_base);
		return -1;
	}
	ret = kvm_register_mem(CODE_SLOT, code_base, CODE_PHYS_BASE, &code_mem);
	if (ret)
		return -1;

	return 0;
}

static int load_code(const char *code_file)
{
	int fd = open(code_file, O_RDONLY);
	struct stat stat;
	char *data;

	if (fd < 0) {
		perror("cannot open code file\n");
		return -1;
	}

	if (fstat(fd, &stat) < 0) {
		perror("cannot stat code file\n");
		close(fd);
		return -1;
	}

	if (stat.st_size > RAM_SIZE) {
		pr_err("code file way too large for this tiny VM\n");
		close(fd);
		return -1;
	}

	data = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		perror("cannot stat code file\n");
		close(fd);
		return -1;
	}

	memcpy(code_base, data, stat.st_size);

	munmap(data, stat.st_size);
	close(fd);
	return 0;
}

static int init_vcpu(void)
{
	struct kvm_regs regs;

	if (ioctl(vcpu_fd, KVM_GET_REGS, &regs) < 0) {
		perror("error getting VCPU registers");
		return -1;
	}

	regs.reg15 = CODE_PHYS_BASE;
	regs.reg13[MODE_SVC] = CODE_PHYS_BASE + RAM_SIZE;

	if (ioctl(vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("error setting VCPU registers");
		return -1;
	}
	return 0;
}


static int kvm_cpu_exec(void)
{
	int ret;

	while (1) {
		ret = ioctl(vcpu_fd, KVM_RUN, 0);

		if (ret == -EINTR || ret == -EAGAIN) {
			continue;
		} else if (ret < 0) {
			perror("Error running vcpu");
			return -1;
		}

		if (kvm_run->exit_reason == KVM_EXIT_MMIO) {
			ret = handle_mmio(kvm_run);
			if (ret < 0)
				return -1;
			else if (ret > 0)
				break;
		}
	}

	return 0;
}

static void usage(int argc, const char *argv[])
{
	printf("Usage: %s <binary>\n", argv[0]);
}

int main(int argc, const char *argv[])
{
	int ret;
	const char *file;

	if (argc != 2) {
		usage(argc, argv);
		return EXIT_FAILURE;
	}
	file = argv[1];
	printf("Starting VM with code from: %s\n", file);

	sys_fd = open("/dev/kvm", O_RDWR);
	if (sys_fd < 0) {
		perror("cannot open /dev/kvm - module loaded?");
		return EXIT_FAILURE;
	}

	ret = create_vm();
	if (ret)
		return EXIT_FAILURE;

	ret = register_memregions();
	if (ret)
		return EXIT_FAILURE;

	ret = load_code(file);
	if (ret)
		return EXIT_FAILURE;

	ret = create_vcpu();
	if (ret)
		return EXIT_FAILURE;

	ret = init_vcpu();
	if (ret)
		return EXIT_FAILURE;
	
	ret = kvm_cpu_exec();
	if (ret)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

/*
 * mmio-host - host side of mmio test in guest-driver
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
#include <linux/kvm.h>

#include "guest-driver.h"
#include "vmexit.h"

/* Return false to stop the VM */
static bool vmexit_test(struct kvm_run *kvm_run, int vcpu_fd)
{
	unsigned long phys_addr;
	unsigned long len;
	bool is_write;
	static unsigned long bogus = 0xdeadbeef;
	unsigned long unused;

	phys_addr = (unsigned long)kvm_run->mmio.phys_addr;
	len = kvm_run->mmio.len;
	is_write = kvm_run->mmio.is_write;

	if (phys_addr == VGIC_DIST_BASE && len == 4 && !is_write) {
		memcpy(kvm_run->mmio.data, &bogus, len);
		return true;
	}

	if (phys_addr == FAKE_MMIO && len == 4) {
		if (is_write)
			memcpy(&unused, kvm_run->mmio.data, 4);
		else
			memcpy(kvm_run->mmio.data, &bogus, len);
		return true;
	}


	return false;
}

GUEST_TEST(vmexit, vmexit_test);

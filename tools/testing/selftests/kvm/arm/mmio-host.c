/*
 * mmio-host - host side of mmio test in guest-driver
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

static char *io_data = IO_DATA;

static int check_write(unsigned long offset, void *_data, unsigned long len)
{
	char *data, *host_data;

	data = _data;
	host_data = io_data + offset;

	if (memcmp(data, host_data, len)) {
		printf("ERROR: VM write mismatch:\n"
		       "VM data: %c%c%c%c%c%c%c%c\n"
		       "IO data: %c%c%c%c%c%c%c%c\n"
		       "    len: %lu\n"
		       " offset: %lu\n",
		       data[0], data[1], data[2], data[3],
		       data[4], data[5], data[6], data[7],
		       host_data[0], host_data[1], host_data[2], host_data[3],
		       host_data[4], host_data[5], host_data[6], host_data[7],
		       len, offset);
		return -1;
	}

	return 0;
}

static int do_read(unsigned long offset, void *data, unsigned long len)
{
	char *host_data;

	host_data = io_data + offset;
	memcpy(data, host_data, len);
	return 0;
}

/* Return anything else than 0 to stop the VM */
int handle_mmio(struct kvm_run *kvm_run)
{
	unsigned long phys_addr;
	unsigned char *data;
	unsigned long len;
	bool is_write;
	int ret;

	phys_addr = (unsigned long)kvm_run->mmio.phys_addr;
	data = kvm_run->mmio.data;
	len = kvm_run->mmio.len;
	is_write = kvm_run->mmio.is_write;

	/* Test if we're reading/writing data */
	if (phys_addr >= IO_DATA_BASE &&
	    phys_addr + len < IO_DATA_BASE + strlen(io_data)) {
		if (is_write)
			ret = check_write(phys_addr - IO_DATA_BASE, data, len);
		else
			ret = do_read(phys_addr - IO_DATA_BASE, data, len);
		return ret;
	}

	/* Test if it's a control operation */
	if (phys_addr >= IO_CTL_BASE && len == IO_DATA_SIZE) {
		if (!is_write)
			return -1; /* only writes allowed */
		switch (data[0]) {
		case CTL_OK:
			printf("PASS: Guest reads what it expects\n");
			return 0;
		case CTL_FAIL:
			printf("FAIL: Guest read fail\n");
			return 0;
		case CTL_ERR:
			printf("ERROR: Guest had error\n");
			return 1;
		case CTL_DONE:
			printf("VM shutting down\n");
			return 1;
		default:
			printf("INFO: Guest wrote %d\n", data[0]);
		}
	}

	pr_err("Guest accessed unexisting mem area: %#08lx + %#08lx\n",
	       phys_addr, len);
	return -1;
}

/*
 * vfp-host - host side of vfp test
 * Copyright (C) 2012 Rusty Russell, IBM Corporation.
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
#include <stdbool.h>
#include <string.h>
#include <linux/kvm.h>

#include "guest-driver.h"
#include "vfp_test.h"

/* Return false to stop the VM */
static bool vfp_test(struct kvm_run *kvm_run, int vcpu_fd)
{
	unsigned long phys_addr;
	bool is_write;

	phys_addr = (unsigned long)kvm_run->mmio.phys_addr;
	is_write = kvm_run->mmio.is_write;
	if (is_write)
		return false;

	/* We load 1.0 into the register. */
	switch (phys_addr) {
	case VFP_USE_REG:
		asm volatile("fconstd	d0, #112");
		break;
	case VFP_USE_REG+1:
		asm volatile("fconstd	d1, #112");
		break;
	case VFP_USE_REG+2:
		asm volatile("fconstd	d2, #112");
		break;
	case VFP_USE_REG+3:
		asm volatile("fconstd	d3, #112");
		break;
	case VFP_USE_REG+4:
		asm volatile("fconstd	d4, #112");
		break;
	case VFP_USE_REG+5:
		asm volatile("fconstd	d5, #112");
		break;
	case VFP_USE_REG+6:
		asm volatile("fconstd	d6, #112");
		break;
	case VFP_USE_REG+7:
		asm volatile("fconstd	d7, #112");
		break;
	case VFP_USE_REG+8:
		asm volatile("fconstd	d8, #112");
		break;
	case VFP_USE_REG+9:
		asm volatile("fconstd	d9, #112");
		break;
	case VFP_USE_REG+10:
		asm volatile("fconstd	d10, #112");
		break;
	case VFP_USE_REG+11:
		asm volatile("fconstd	d11, #112");
		break;
	case VFP_USE_REG+12:
		asm volatile("fconstd	d12, #112");
		break;
	case VFP_USE_REG+13:
		asm volatile("fconstd	d13, #112");
		break;
	case VFP_USE_REG+14:
		asm volatile("fconstd	d14, #112");
		break;
	case VFP_USE_REG+15:
		asm volatile("fconstd	d15, #112");
		break;
	case VFP_USE_REG+16:
		asm volatile("fconstd	d16, #112");
		break;
	case VFP_USE_REG+17:
		asm volatile("fconstd	d17, #112");
		break;
	case VFP_USE_REG+18:
		asm volatile("fconstd	d18, #112");
		break;
	case VFP_USE_REG+19:
		asm volatile("fconstd	d19, #112");
		break;
	case VFP_USE_REG+20:
		asm volatile("fconstd	d20, #112");
		break;
	case VFP_USE_REG+21:
		asm volatile("fconstd	d21, #112");
		break;
	case VFP_USE_REG+22:
		asm volatile("fconstd	d22, #112");
		break;
	case VFP_USE_REG+23:
		asm volatile("fconstd	d23, #112");
		break;
	case VFP_USE_REG+24:
		asm volatile("fconstd	d24, #112");
		break;
	case VFP_USE_REG+25:
		asm volatile("fconstd	d25, #112");
		break;
	case VFP_USE_REG+26:
		asm volatile("fconstd	d26, #112");
		break;
	case VFP_USE_REG+27:
		asm volatile("fconstd	d27, #112");
		break;
	case VFP_USE_REG+28:
		asm volatile("fconstd	d28, #112");
		break;
	case VFP_USE_REG+29:
		asm volatile("fconstd	d29, #112");
		break;
	case VFP_USE_REG+30:
		asm volatile("fconstd	d30, #112");
		break;
	case VFP_USE_REG+31:
		asm volatile("fconstd	d31, #112");
		break;
	default:
		return false;
	}
	return true;
}

GUEST_TEST(vfp, vfp_test);

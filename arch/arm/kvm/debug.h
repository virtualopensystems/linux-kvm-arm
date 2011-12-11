/*
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
 *
 *
 * This file contains debugging and tracing functions and definitions
 * for KVM/ARM.
 */
#ifndef __ARM_KVM_TRACE_H__
#define __ARM_KVM_TRACE_H__

#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>

void __kvm_print_msg(char *_fmt, ...);

#define kvm_err(err, fmt, args...) do {			\
	__kvm_print_msg(KERN_ERR "KVM error [%s:%d]: (%d) ", \
			__func__, __LINE__, err); \
	__kvm_print_msg(fmt "\n", ##args); \
} while (0)

#define __kvm_msg(fmt, args...) do {			\
	__kvm_print_msg(KERN_ERR "KVM [%s:%d]: ", __func__, __LINE__); \
	__kvm_print_msg(fmt, ##args); \
} while (0)

#define kvm_msg(__fmt, __args...) __kvm_msg(__fmt "\n", ##__args)


#define KVMARM_NOT_IMPLEMENTED() \
{ \
	printk(KERN_ERR "KVM not implemented [%s:%d] in %s\n", \
			__FILE__, __LINE__, __func__); \
}

#endif  /* __ARM_KVM_TRACE_H__ */

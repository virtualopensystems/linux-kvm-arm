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
 *
 * This file contains debugging and tracing functions and definitions for KVM/ARM.
 *
 */
#ifndef __ARM_KVM_TRACE_H__
#define __ARM_KVM_TRACE_H__

#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>

void kvm_dump_vcpu_state(void);

void debug_ws_enter(u32 guest_pc);
void debug_ws_exit(u32 guest_pc);

#define print_fn_args struct seq_file *, const char *, ...
void print_kvm_debug_info(int (*print_fn)(print_fn_args), struct seq_file *m);

void __kvm_print_msg(char *_fmt, ...);

#define kvm_err(err, fmt, args...) do {			\
	__kvm_print_msg(KERN_ERR "KVM error [%s:%d]: (%d) ", \
			__FUNCTION__, __LINE__, err); \
	__kvm_print_msg(fmt "\n", ##args); \
} while (0)

#define __kvm_msg(fmt, args...) do {			\
	__kvm_print_msg(KERN_ERR "KVM [%s:%d]: ", __FUNCTION__, __LINE__); \
	__kvm_print_msg(fmt, ##args); \
} while (0)

#define kvm_msg(__fmt, __args...) __kvm_msg(__fmt "\n", ##__args)


#define KVMARM_NOT_IMPLEMENTED() \
   { \
	    printk(KERN_ERR "KVM not implemented [%s:%d] in %s \n", \
		   __FILE__, __LINE__, __FUNCTION__); \
   }

void print_ws_trace(void);

void kvm_arm_debugfs_init(void);
void kvm_arm_debugfs_exit(void);

#endif  /* __ARM_KVM_TRACE_H__ */

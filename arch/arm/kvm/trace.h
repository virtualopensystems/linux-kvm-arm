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

#define EVENT_GUEST_ENTER	0
#define EVENT_GUEST_EXIT	1
#define EVENT_VCPU_BLOCK	2
#define EVENT_IRQ_WINDOW	3
#define EVENT_SWITCH_MODE	4
#define EVENT_VCPU_IRQS_ON	5
#define EVENT_VCPU_IRQS_OFF	6
#define EVENT_WFI		7
#define EVENT_FLUSH_SHADOW	8
#define EVENT_MOD_TTBR		9
#define EVENT_READ_GUEST_ENTRY	10
#define EVENT_MAP_GVA_TO_GFN	11
#define EVENT_DACR_CHANGE	12
#define EVENT_SWITCH_PRIV	13
#define EVENT_SWITCH_USER	14
#define EVENT_VCPU_ASID		15
#define EVENT_LS_TRANS		16
#define EVENT_EMUL_MRS		17
#define EVENT_EMUL_MSR		18
#define EVENT_EMUL_CPS		19
#define EVENT_NEED_RESCHED	20
#define EVENT_MCR_7_5_0		21
#define EVENT_MCR_7_5_1		22
#define EVENT_MCR_7_5_2		23
#define EVENT_MCR_7_5_7		24
#define EVENT_MCR_7_6_0		25
#define EVENT_MCR_7_6_1		26
#define EVENT_MCR_7_6_2		27
#define EVENT_MCR_7_7_0		28
#define EVENT_MCR_7_10_0	29
#define EVENT_MCR_7_10_1	30
#define EVENT_MCR_7_10_4	31
#define EVENT_MCR_7_14_0	32
#define EVENT_MCR_7_14_1	33
#define EVENT_MCR_7_15_0	34
#define EVENT_MCR_8_5_X		35
#define EVENT_MCR_8_6_X		36
#define EVENT_MCR_8_7_X		37
#define EVENT_EMUL_LSMULT	38

#define KVM_EVENTC_ITEMS	39

void kvm_arm_init_eventc(void);
void kvm_arm_count_event(unsigned int event);
void kvm_dump_vcpu_state(void);

void trace_ws_enter(u32 guest_pc);
void trace_ws_exit(u32 guest_pc, u32 exit_code);


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

extern bool trace_gva_to_gfn;
void print_shadow_mapping(struct kvm_vcpu *vcpu, gva_t gva);
void print_ws_trace(void);
void kvm_trace_activity(unsigned int activity, char *fmt, ...);

#endif  /* __ARM_KVM_TRACE_H__ */

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
 */
#ifndef __ARM_KVM_ARM_H__
#define __ARM_KVM_ARM_H__

#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <asm/kvm_asm.h>

/*
 * Debugging and tracing functions and definitions
 */

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
		 return -EINVAL; \
   }

extern bool trace_gva_to_gfn;
void print_shadow_mapping(struct kvm_vcpu *vcpu, gva_t gva);
void print_ws_trace(void);
void kvm_trace_activity(unsigned int activity, char *fmt, ...);

/*
 * General KMV-ARM specific global functions
 */
void kvm_cpsr_write(struct kvm_vcpu *vcpu, u32 new_cpsr);

/* MMU Related defines */
#define FSR_TYPE_MASK		0xf
#define FSR_ALIGN_FAULT		0x1
#define FSR_EXT_ABORT_L1	0xc
#define FSR_EXT_ABORT_L2	0xe
#define FSR_TRANS_SEC		0x5
#define FSR_TRANS_PAGE		0x7
#define FSR_DOMAIN_SEC		0x9
#define FSR_DOMAIN_PAG		0xb
#define FSR_PERM_SEC		0xd
#define FSR_PERM_PAGE		0xf

#define FSR_DOMAIN_MASK		0xf0

/* Interrupt handling */
#define EXCEPTION_VECTOR_HIGH 0xffff0000
#define EXCEPTION_VECTOR_LOW  0x00000000

static inline int kvm_guest_high_vectors(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.cp15.c1_CR & CP15_CR_V_BIT)
		return 1;
	else
		return 0;
}

static inline gva_t kvm_guest_vector_base(struct kvm_vcpu *vcpu)
{
	if (kvm_guest_high_vectors(vcpu))
		return EXCEPTION_VECTOR_HIGH;
	else
		return EXCEPTION_VECTOR_LOW;
}

static inline gva_t kvm_host_vector_base(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.host_vectors_high)
		return EXCEPTION_VECTOR_HIGH;
	else
		return EXCEPTION_VECTOR_LOW;
}

#endif /* __ARM_KVM_ARM_H__ */

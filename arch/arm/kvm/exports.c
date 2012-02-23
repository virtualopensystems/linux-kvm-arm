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
 */

#include <linux/module.h>
#include <asm/kvm_asm.h>

EXPORT_SYMBOL_GPL(__kvm_hyp_init);
EXPORT_SYMBOL_GPL(__kvm_hyp_init_end);

EXPORT_SYMBOL_GPL(__kvm_hyp_vector);

EXPORT_SYMBOL_GPL(__kvm_hyp_code_start);
EXPORT_SYMBOL_GPL(__kvm_hyp_code_end);

EXPORT_SYMBOL_GPL(__kvm_vcpu_run);

EXPORT_SYMBOL_GPL(__kvm_flush_vm_context);

EXPORT_SYMBOL_GPL(smp_send_reschedule);

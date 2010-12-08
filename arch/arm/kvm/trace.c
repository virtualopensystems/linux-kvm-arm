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
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>

#include <asm/kvm_arm.h>
#include "trace.h"


/******************************************************************************
 * Simple event counting
 */

struct kvm_event {
	unsigned long long cnt;
	char *descr;
};

static struct kvm_event kvm_eventc_log[KVM_EVENTC_ITEMS] =
{
	{ 0, "switch to guest" },
	{ 0, "exit from guest" },
	{ 0, "Block VCPU" },
	{ 0, "Exit to QEMU for IRQ window" },
	{ 0, "Switch VCPU mode" },
	{ 0, "VCPU IRQs on" },
	{ 0, "VCPU IRQs off" },
	{ 0, "Wait-for-interrupts" },
	{ 0, "Flush shadow page table" },
	{ 0, "Virtual TTBR change" },
	{ 0, "Read guest page table entry" },
	{ 0, "Map GVA to GFN" },
	{ 0, "Virtual DACR change" },
	{ 0, "VCPU switch to privileged mode" },
	{ 0, "VCPU switch from privileged mode" },
	{ 0, "VCPU process ID registers change" },
	{ 0, "Emulate Load/Store with translation" },
	{ 0, "Emulate MRS" },
	{ 0, "Emulate MSR" },
	{ 0, "Emulate CPS" },
	{ 0, "Need reschedule in execution loop" },
	{ 0, "MCR 7,  5, 0 - Invalidate entire I-cache" },
	{ 0, "MCR 7,  5, 1 - Invalidate line in I-cache MVA" },
	{ 0, "MCR 7,  5, 2 - Invalidate line in I-cache set/way" },
	{ 0, "MCR 7,  5, 7 - Flush branch target cache - MVA" },
	{ 0, "MCR 7,  6, 0 - Invalidate entire data cache" },
	{ 0, "MCR 7,  6, 1 - Invalidate data cache line - MVA" },
	{ 0, "MCR 7,  6, 2 - Invalidate data cache line - set/way" },
	{ 0, "MCR 7,  7, 0 - Invalidate D- and I-cache" },
	{ 0, "MCR 7, 10, 0 - Clean entire data cache" },
	{ 0, "MCR 7, 10, 1 - Clean data cache line - MVA" },
	{ 0, "MCR 7, 10, 4 - Data Synchronization Barrier (DSB)" },
	{ 0, "MCR 7, 14, 0 - Clean and invalidate entire D-cache" },
	{ 0, "MCR 7, 14, 1 - Clean and invalidate D-cache line - MVA" },
	{ 0, "MCR 7, 15, 0 - Clean and invalidate unified cache" },
	{ 0, "MCR 8,  5, 0 - Invalidate instruction TLB" },
	{ 0, "MCR 8,  6, 0 - Invalidate data TLB" },
	{ 0, "MCR 8,  7, 0 - Invalidate unified TLB" },
	{ 0, "Emulate Load-Store multiple" },
	{ 0, "MCR 7, 14, 2 - Clean and invalidate D-cache line - set/way" },
	{ 0, "MCR 7, 11, 1 - Clean data cache line by MVA - to PoU" },
	{ 0, "Flush cache full"},
	{ 0, "MCRR - Invalidate Cache Ranges"},
};

void kvm_arm_count_event(unsigned int event)
{
	if (event >= KVM_EVENTC_ITEMS)
		return;

	kvm_eventc_log[event].cnt++;
}

void kvm_arm_init_eventc(void)
{
	unsigned int i;

	for (i = 0; i < KVM_EVENTC_ITEMS; i++)
		kvm_eventc_log[i].cnt = 0;
}

struct kvm_event_order {
	struct kvm_event *event;
	struct kvm_event_order *next;
	struct kvm_event_order *prev;
};
static struct kvm_event_order event_order[KVM_EVENTC_ITEMS];

static struct kvm_event_order *sort_kvm_event_log(void)
{
	unsigned int i;
	struct kvm_event_order *ptr;
	struct kvm_event_order head =
		{ .event = NULL, .next = &head, .prev = &head };

	for (i = 0; i < KVM_EVENTC_ITEMS; i++) {
		event_order[i].event = &kvm_eventc_log[i];
		ptr = head.next;
		while (ptr->event != NULL &&
		       ptr->event->cnt > kvm_eventc_log[i].cnt) {
			ptr = ptr->next;
		}
		ptr->prev->next = &event_order[i];
		event_order[i].prev = ptr->prev;
		event_order[i].next = ptr;
		ptr->prev = &event_order[i];
	}

	head.prev->next = NULL; /* Mark end of linked list */
	return head.next;
}

/******************************************************************************
 * Trace ring-buffer local to KVM/ARM
 */

#define KVM_TRACE_ACTIVITY
#ifndef KVM_TRACE_ACTIVITY
void kvm_trace_activity(unsigned int activity, char *fmt, ...)
{
}
#else

#define ACTIVITY_TRACE_ITEMS 50
#define TRACE_DESCR_LEN 80
static u32 activity_trace[ACTIVITY_TRACE_ITEMS];
static u32 activity_trace_cnt[ACTIVITY_TRACE_ITEMS];
static char activity_trace_descr[ACTIVITY_TRACE_ITEMS][TRACE_DESCR_LEN];
static int activity_trace_index = 0;
static bool trace_init = false;

void kvm_trace_activity(unsigned int activity, char *fmt, ...)
{
	va_list ap;
	unsigned int size;
	unsigned int i;
	char *ptr;

	if (!trace_init) {
		for (i = 0; i < ACTIVITY_TRACE_ITEMS; i++)
			activity_trace_descr[i][0] = '\0';
		trace_init = true;
	}

	if (activity_trace[activity_trace_index] == activity) {
		activity_trace_cnt[activity_trace_index]++;
	} else {
		activity_trace_index = (activity_trace_index + 1)
			% ACTIVITY_TRACE_ITEMS;
		activity_trace[activity_trace_index] = activity;
		activity_trace_cnt[activity_trace_index] = 0;

		ptr = activity_trace_descr[activity_trace_index];
		va_start(ap, fmt);
		size = vsnprintf(ptr, TRACE_DESCR_LEN, fmt, ap);
		va_end(ap);
	}
}
#endif

/******************************************************************************
 * World-switch ring-buffer
 */

#define WS_TRACE_ITEMS 10
static u32 ws_trace_enter[WS_TRACE_ITEMS];
static int ws_trace_enter_index = 0;
static u32 ws_trace_exit[WS_TRACE_ITEMS];
static int ws_trace_exit_index = 0;
static u32 ws_trace_exit_codes[WS_TRACE_ITEMS];
DEFINE_MUTEX(ws_trace_mutex);

void trace_ws_enter(u32 guest_pc)
{
	mutex_lock(&ws_trace_mutex);
	ws_trace_enter[ws_trace_enter_index++] = guest_pc;
	if (ws_trace_enter_index >= WS_TRACE_ITEMS)
		ws_trace_enter_index = 0;
	mutex_unlock(&ws_trace_mutex);
}

void trace_ws_exit(u32 guest_pc, u32 exit_code)
{
	mutex_lock(&ws_trace_mutex);
	ws_trace_exit[ws_trace_exit_index] = guest_pc;
	ws_trace_exit_codes[ws_trace_exit_index++] = exit_code;
	if (ws_trace_exit_index >= WS_TRACE_ITEMS)
		ws_trace_exit_index = 0;
	mutex_unlock(&ws_trace_mutex);
}

void print_ws_trace(void)
{
	int i;
	mutex_lock(&ws_trace_mutex);

	if (ws_trace_enter_index != ws_trace_exit_index) {
		kvm_msg("enter and exit WS trace count differ");
		mutex_unlock(&ws_trace_mutex);
		return;
	}

	/* Avoid potential endless loop */
	if (ws_trace_enter_index < 0 || ws_trace_enter_index >= WS_TRACE_ITEMS) {
		kvm_msg("ws_trace_enter_index out of bounds: %d",
				ws_trace_enter_index);
		mutex_unlock(&ws_trace_mutex);
		return;
	}

	for (i = ws_trace_enter_index - 1; i != ws_trace_enter_index; i--) {
		if (i < 0) {
			i = WS_TRACE_ITEMS;
			continue;
		}

		printk(KERN_ERR "Enter: %08x    Exit: %08x (%d)\n",
			ws_trace_enter[i],
			ws_trace_exit[i],
			ws_trace_exit_codes[i]);
	}
	mutex_unlock(&ws_trace_mutex);
}

/******************************************************************************
 * Dump total debug info, or write to /proc/kvm
 */

struct kvm_vcpu *latest_vcpu = NULL;

void print_kvm_debug_info(int (*print_fn)(print_fn_args), struct seq_file *m)
{
	int i;
	struct kvm_vcpu_regs *regs;
	char *mode = NULL;
	char *exceptions[7];
	struct kvm_vcpu *vcpu = latest_vcpu;
	struct kvm_event_order *ptr;

	print_fn(m, "KVM/ARM runtime info\n");
	print_fn(m, "======================================================");
	print_fn(m, "\n\n");

	if (vcpu == NULL) {
		print_fn(m, "No registered VCPU\n");
		goto print_ws_hist;
	}


	switch (VCPU_MODE(vcpu)) {
		case MODE_USER:   mode = "USR"; break;
		case MODE_FIQ:    mode = "FIQ"; break;
		case MODE_IRQ:    mode = "IRQ"; break;
		case MODE_SVC:    mode = "SVC"; break;
		case MODE_ABORT:  mode = "ABT"; break;
		case MODE_UNDEF:  mode = "UND"; break;
		case MODE_SYSTEM: mode = "SYS"; break;
	}

	vcpu_load(vcpu);
	regs = vcpu->arch.regs;

	print_fn(m, "Virtual CPU state:\n\n");
	print_fn(m, "PC is at: \t%08x\n", vcpu_reg(vcpu, 15));
	print_fn(m, "CPSR:     \t%08x\n(Mode: %s)  (IRQs: %s)  (FIQs: %s) "
		      "  (Vec: %s)\n",
		      regs->cpsr, mode,
		      (regs->cpsr & PSR_I_BIT) ? "off" : "on",
		      (regs->cpsr & PSR_F_BIT) ? "off" : "on",
		      (regs->cpsr & PSR_V_BIT) ? "high" : "low");

	for (i = 0; i <= 12; i++) {
		if ((i % 4) == 0)
			print_fn(m, "\nregs[%u]: ", i);

		print_fn(m, "\t0x%08x", vcpu_reg_m(vcpu, i, MODE_USER));
	}

	print_fn(m, "\n\n");
	print_fn(m, "Banked registers:  \tr13\t\tr14\t\tspsr\n");
	print_fn(m, "-------------------\t--------\t--------\t--------\n");
	print_fn(m, "             USR:  \t%08x\t%08x\t////////\n",
			vcpu_reg_m(vcpu, 13, MODE_USER),
			vcpu_reg_m(vcpu, 14, MODE_USER));
	print_fn(m, "             SVC:  \t%08x\t%08x\t%08x\n",
			vcpu_reg_m(vcpu, 13, MODE_SVC),
			vcpu_reg_m(vcpu, 14, MODE_SVC),
			vcpu_spsr_m(vcpu, MODE_SVC));
	print_fn(m, "             ABT:  \t%08x\t%08x\t%08x\n",
			vcpu_reg_m(vcpu, 13, MODE_ABORT),
			vcpu_reg_m(vcpu, 14, MODE_ABORT),
			vcpu_spsr_m(vcpu, MODE_ABORT));
	print_fn(m, "             UND:  \t%08x\t%08x\t%08x\n",
			vcpu_reg_m(vcpu, 13, MODE_UNDEF),
			vcpu_reg_m(vcpu, 14, MODE_UNDEF),
			vcpu_spsr_m(vcpu, MODE_UNDEF));
	print_fn(m, "             IRQ:  \t%08x\t%08x\t%08x\n",
			vcpu_reg_m(vcpu, 13, MODE_IRQ),
			vcpu_reg_m(vcpu, 14, MODE_IRQ),
			vcpu_spsr_m(vcpu, MODE_IRQ));
	print_fn(m, "             FIQ:  \t%08x\t%08x\t%08x\n",
			vcpu_reg_m(vcpu, 13, MODE_FIQ),
			vcpu_reg_m(vcpu, 14, MODE_FIQ),
			vcpu_spsr_m(vcpu, MODE_FIQ));

	print_fn(m, "\n");
	print_fn(m, "fiq regs:\t%08x\t%08x\t%08x\t%08x\n"
			  "         \t%08x\n",
			regs->fiq_reg[0], regs->fiq_reg[1], regs->fiq_reg[2],
			regs->fiq_reg[3], regs->fiq_reg[4]);

print_ws_hist:
	/*
	 * Print world-switch trace circular buffer
	 */
	print_fn(m, "\n\nWorld switch history:\n");
	print_fn(m, "---------------------\n");
	mutex_lock(&ws_trace_mutex);

	if (ws_trace_enter_index != ws_trace_exit_index ||
			ws_trace_enter_index < 0 ||
			ws_trace_enter_index >= WS_TRACE_ITEMS)
	{
		mutex_unlock(&ws_trace_mutex);
		goto print_trace_activity;
	}

	exceptions[0] = "reset";
	exceptions[1] = "undefined";
	exceptions[2] = "software";
	exceptions[3] = "prefetch abort";
	exceptions[4] = "data abort";
	exceptions[5] = "irq";
	exceptions[6] = "fiq";

	for (i = ws_trace_enter_index - 1; i != ws_trace_enter_index; i--) {
		if (i < 0) {
			i = WS_TRACE_ITEMS;
			continue;
		}

		print_fn(m, "Enter: %08x    Exit: %08x (%s)\n",
			ws_trace_enter[i], ws_trace_exit[i],
			exceptions[ws_trace_exit_codes[i]]);
	}
	mutex_unlock(&ws_trace_mutex);

print_trace_activity:
#ifdef KVM_TRACE_ACTIVITY
	/*
	 * Print activity trace
	 */
	print_fn(m, "\n\nActivity circular buffer:\n");
	print_fn(m, "-----------------------------\n");
	for (i = activity_trace_index - 1; i != activity_trace_index; i--) {
		if (i < 0) {
			i = ACTIVITY_TRACE_ITEMS;
			continue;
		}

		print_fn(m, "%lu: \t %s\n",
				activity_trace_cnt[i],
				activity_trace_descr[i]);
	}
#endif

	/*
	 * Print event counters sorted
	 */
	print_fn(m, "\n\nEvent counters:\n");
	print_fn(m, "-----------------------------\n");
	ptr = sort_kvm_event_log();
	while (ptr != NULL) {
		if (ptr->event->cnt > 0) {
			print_fn(m, "%12llu  #  %s\n", ptr->event->cnt,
							ptr->event->descr);
		}
		ptr = ptr->next;
	}
	print_fn(m, "\n\n");

	if (vcpu != NULL) {
		vcpu_put(vcpu);
	}
}

static int __printk_relay(struct seq_file *m, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintk(fmt, ap);
	va_end(ap);
	return 0;
}

void kvm_dump_vcpu_state(void)
{
	print_kvm_debug_info(&__printk_relay, NULL);
}

/******************************************************************************
 * Printk-log-wrapping functionality
 */

#define TMP_LOG_LEN 512
static char __tmp_log_data[TMP_LOG_LEN];
DEFINE_MUTEX(__tmp_log_lock);
void __kvm_print_msg(char *fmt, ...)
{
	va_list ap;
	unsigned int size;

	mutex_lock(&__tmp_log_lock);

	va_start(ap, fmt);
	size = vsnprintf(__tmp_log_data, TMP_LOG_LEN, fmt, ap);
	va_end(ap);

	if (size >= TMP_LOG_LEN)
		printk("Message exceeded log length!\n");
	else
		printk("%s", __tmp_log_data);

	mutex_unlock(&__tmp_log_lock);
}

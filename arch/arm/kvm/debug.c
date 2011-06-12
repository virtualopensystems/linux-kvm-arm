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
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <asm/kvm_emulate.h>

#include "debug.h"

static struct dentry *vcpu_debugfs_file;
static struct dentry *ws_debugfs_file;

/******************************************************************************
 * World-switch ring-buffer
 */

#define WS_TRACE_ITEMS 10
static u32 ws_trace_enter[WS_TRACE_ITEMS];
static int ws_trace_enter_index = 0;
static u32 ws_trace_exit[WS_TRACE_ITEMS];
static int ws_trace_exit_index = 0;
DEFINE_MUTEX(ws_trace_mutex);

void debug_ws_enter(u32 guest_pc)
{
	mutex_lock(&ws_trace_mutex);
	ws_trace_enter[ws_trace_enter_index++] = guest_pc;
	if (ws_trace_enter_index >= WS_TRACE_ITEMS)
		ws_trace_enter_index = 0;
	mutex_unlock(&ws_trace_mutex);
}

void debug_ws_exit(u32 guest_pc)
{
	mutex_lock(&ws_trace_mutex);
	ws_trace_exit[ws_trace_exit_index++] = guest_pc;
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

		printk(KERN_ERR "Enter: %08x    Exit: %08x\n",
			ws_trace_enter[i],
			ws_trace_exit[i]);
	}
	mutex_unlock(&ws_trace_mutex);
}

/******************************************************************************
 * Dump total debug info, or write to /proc/kvm
 */

struct kvm_vcpu *latest_vcpu = NULL;

void print_kvm_vcpu_info(int (*print_fn)(print_fn_args), struct seq_file *m)
{
	int i;
	struct kvm_vcpu_regs *regs;
	char *mode = NULL;
	struct kvm_vcpu *vcpu = latest_vcpu;

	print_fn(m, "KVM/ARM runtime info\n");
	print_fn(m, "======================================================");
	print_fn(m, "\n\n");

	if (vcpu == NULL) {
		print_fn(m, "No registered VCPU\n");
		goto out;
	}


	switch (vcpu_mode(vcpu)) {
		case MODE_USR:	mode = "USR"; break;
		case MODE_FIQ:	mode = "FIQ"; break;
		case MODE_IRQ:	mode = "IRQ"; break;
		case MODE_SVC:	mode = "SVC"; break;
		case MODE_ABT:	mode = "ABT"; break;
		case MODE_UND:	mode = "UND"; break;
		case MODE_SYS:	mode = "SYS"; break;
	}

	vcpu_load(vcpu);
	regs = &vcpu->arch.regs;

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

		print_fn(m, "\t0x%08x", *kvm_vcpu_reg(vcpu, i, MODE_USR));
	}

	print_fn(m, "\n\n");
	print_fn(m, "Banked registers:  \tr13\t\tr14\t\tspsr\n");
	print_fn(m, "-------------------\t--------\t--------\t--------\n");
	print_fn(m, "             USR:  \t%08x\t%08x\t////////\n",
			*kvm_vcpu_reg(vcpu, 13, MODE_USR),
			*kvm_vcpu_reg(vcpu, 14, MODE_USR));
	print_fn(m, "             SVC:  \t%08x\t%08x\t%08x\n",
			*kvm_vcpu_reg(vcpu, 13, MODE_SVC),
			*kvm_vcpu_reg(vcpu, 14, MODE_SVC),
			*kvm_vcpu_spsr(vcpu, MODE_SVC));
	print_fn(m, "             ABT:  \t%08x\t%08x\t%08x\n",
			*kvm_vcpu_reg(vcpu, 13, MODE_ABT),
			*kvm_vcpu_reg(vcpu, 14, MODE_ABT),
			*kvm_vcpu_spsr(vcpu, MODE_ABT));
	print_fn(m, "             UND:  \t%08x\t%08x\t%08x\n",
			*kvm_vcpu_reg(vcpu, 13, MODE_UND),
			*kvm_vcpu_reg(vcpu, 14, MODE_UND),
			*kvm_vcpu_spsr(vcpu, MODE_UND));
	print_fn(m, "             IRQ:  \t%08x\t%08x\t%08x\n",
			*kvm_vcpu_reg(vcpu, 13, MODE_IRQ),
			*kvm_vcpu_reg(vcpu, 14, MODE_IRQ),
			*kvm_vcpu_spsr(vcpu, MODE_IRQ));
	print_fn(m, "             FIQ:  \t%08x\t%08x\t%08x\n",
			*kvm_vcpu_reg(vcpu, 13, MODE_FIQ),
			*kvm_vcpu_reg(vcpu, 14, MODE_FIQ),
			*kvm_vcpu_spsr(vcpu, MODE_FIQ));

	print_fn(m, "\n");
	print_fn(m, "fiq regs:\t%08x\t%08x\t%08x\t%08x\n"
			  "         \t%08x\n",
			*kvm_vcpu_reg(vcpu, 8, MODE_FIQ),
			*kvm_vcpu_reg(vcpu, 9, MODE_FIQ),
			*kvm_vcpu_reg(vcpu, 10, MODE_FIQ),
			*kvm_vcpu_reg(vcpu, 11, MODE_FIQ),
			*kvm_vcpu_reg(vcpu, 12, MODE_FIQ));

out:
	if (vcpu != NULL) {
		vcpu_put(vcpu);
	}
}

void print_kvm_ws_info(int (*print_fn)(print_fn_args), struct seq_file *m)
{
	int i;

	/*
	 * Print world-switch trace circular buffer
	 */
	print_fn(m, "World switch history:\n");
	print_fn(m, "---------------------\n");
	mutex_lock(&ws_trace_mutex);

	if (ws_trace_enter_index != ws_trace_exit_index ||
			ws_trace_enter_index < 0 ||
			ws_trace_enter_index >= WS_TRACE_ITEMS)
	{
		mutex_unlock(&ws_trace_mutex);
		return;
	}

	for (i = ws_trace_enter_index - 1; i != ws_trace_enter_index; i--) {
		if (i < 0) {
			i = WS_TRACE_ITEMS;
			continue;
		}

		print_fn(m, "Enter: %08x    Exit: %08x\n",
			ws_trace_enter[i], ws_trace_exit[i]);
	}
	mutex_unlock(&ws_trace_mutex);
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
	print_kvm_vcpu_info(&__printk_relay, NULL);
}

void kvm_arm_trace_init(void)
{

}

/******************************************************************************
 * debugfs handling
 */

static int vcpu_debugfs_show(struct seq_file *m, void *v)
{
	print_kvm_vcpu_info(&seq_printf, m);
	return 0;
}

static int ws_debugfs_show(struct seq_file *m, void *v)
{
	print_kvm_ws_info(&seq_printf, m);
	return 0;
}

static void *k_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *k_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void k_stop(struct seq_file *m, void *v)
{
}

static const struct seq_operations vcpu_debugfs_op = {
	.start	= k_start,
	.next	= k_next,
	.stop	= k_stop,
	.show	= vcpu_debugfs_show
};

static const struct seq_operations ws_debugfs_op = {
	.start	= k_start,
	.next	= k_next,
	.stop	= k_stop,
	.show	= ws_debugfs_show
};

static int vcpu_debugfs_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &vcpu_debugfs_op);
}

static int ws_debugfs_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ws_debugfs_op);
}

static const struct file_operations vcpu_debugfs_fops = {
	.owner	 = THIS_MODULE,
	.open	 = vcpu_debugfs_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

static const struct file_operations ws_debugfs_fops = {
	.owner	 = THIS_MODULE,
	.open	 = ws_debugfs_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/**
 * kvm_arm_debugfs_init - create debugfs directory and files
 *
 * Create the debugfs entries for KVM/ARM
 */
void kvm_arm_debugfs_init(void)
{
	struct dentry *file;

	file = debugfs_create_file("vcpu", 0444, kvm_debugfs_dir,
				     NULL, &vcpu_debugfs_fops);
	if (IS_ERR(file) || !file) {
		kvm_err(PTR_ERR(file),
			"cannot create debugfs KVM/ARM vcpu file\n");
		return;
	}
	vcpu_debugfs_file = file;

	file = debugfs_create_file("ws", 0444, kvm_debugfs_dir,
				     NULL, &ws_debugfs_fops);
	if (IS_ERR(file) || !file) {
		kvm_err(PTR_ERR(file),
			"cannot create debugfs KVM/ARM ws file\n");
	}
	ws_debugfs_file = file;
}

void kvm_arm_debugfs_exit(void)
{
	if (vcpu_debugfs_file)
		debugfs_remove(vcpu_debugfs_file);
	if (ws_debugfs_file)
		debugfs_remove(ws_debugfs_file);
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



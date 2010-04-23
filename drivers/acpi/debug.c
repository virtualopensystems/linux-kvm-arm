/*
 * debug.c - ACPI debug interface to userspace.
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <acpi/acpi_drivers.h>

#define _COMPONENT		ACPI_SYSTEM_COMPONENT
ACPI_MODULE_NAME("debug");

struct acpi_dlayer {
	const char *name;
	unsigned long value;
};
struct acpi_dlevel {
	const char *name;
	unsigned long value;
};
#define ACPI_DEBUG_INIT(v)	{ .name = #v, .value = v }

static const struct acpi_dlayer acpi_debug_layers[] = {
	ACPI_DEBUG_INIT(ACPI_UTILITIES),
	ACPI_DEBUG_INIT(ACPI_HARDWARE),
	ACPI_DEBUG_INIT(ACPI_EVENTS),
	ACPI_DEBUG_INIT(ACPI_TABLES),
	ACPI_DEBUG_INIT(ACPI_NAMESPACE),
	ACPI_DEBUG_INIT(ACPI_PARSER),
	ACPI_DEBUG_INIT(ACPI_DISPATCHER),
	ACPI_DEBUG_INIT(ACPI_EXECUTER),
	ACPI_DEBUG_INIT(ACPI_RESOURCES),
	ACPI_DEBUG_INIT(ACPI_CA_DEBUGGER),
	ACPI_DEBUG_INIT(ACPI_OS_SERVICES),
	ACPI_DEBUG_INIT(ACPI_CA_DISASSEMBLER),
	ACPI_DEBUG_INIT(ACPI_COMPILER),
	ACPI_DEBUG_INIT(ACPI_TOOLS),

	ACPI_DEBUG_INIT(ACPI_BUS_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_AC_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_BATTERY_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_BUTTON_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_SBS_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_FAN_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_PCI_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_POWER_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_CONTAINER_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_SYSTEM_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_THERMAL_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_MEMORY_DEVICE_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_VIDEO_COMPONENT),
	ACPI_DEBUG_INIT(ACPI_PROCESSOR_COMPONENT),
};

static const struct acpi_dlevel acpi_debug_levels[] = {
	ACPI_DEBUG_INIT(ACPI_LV_INIT),
	ACPI_DEBUG_INIT(ACPI_LV_DEBUG_OBJECT),
	ACPI_DEBUG_INIT(ACPI_LV_INFO),

	ACPI_DEBUG_INIT(ACPI_LV_INIT_NAMES),
	ACPI_DEBUG_INIT(ACPI_LV_PARSE),
	ACPI_DEBUG_INIT(ACPI_LV_LOAD),
	ACPI_DEBUG_INIT(ACPI_LV_DISPATCH),
	ACPI_DEBUG_INIT(ACPI_LV_EXEC),
	ACPI_DEBUG_INIT(ACPI_LV_NAMES),
	ACPI_DEBUG_INIT(ACPI_LV_OPREGION),
	ACPI_DEBUG_INIT(ACPI_LV_BFIELD),
	ACPI_DEBUG_INIT(ACPI_LV_TABLES),
	ACPI_DEBUG_INIT(ACPI_LV_VALUES),
	ACPI_DEBUG_INIT(ACPI_LV_OBJECTS),
	ACPI_DEBUG_INIT(ACPI_LV_RESOURCES),
	ACPI_DEBUG_INIT(ACPI_LV_USER_REQUESTS),
	ACPI_DEBUG_INIT(ACPI_LV_PACKAGE),

	ACPI_DEBUG_INIT(ACPI_LV_ALLOCATIONS),
	ACPI_DEBUG_INIT(ACPI_LV_FUNCTIONS),
	ACPI_DEBUG_INIT(ACPI_LV_OPTIMIZATIONS),

	ACPI_DEBUG_INIT(ACPI_LV_MUTEX),
	ACPI_DEBUG_INIT(ACPI_LV_THREADS),
	ACPI_DEBUG_INIT(ACPI_LV_IO),
	ACPI_DEBUG_INIT(ACPI_LV_INTERRUPTS),

	ACPI_DEBUG_INIT(ACPI_LV_AML_DISASSEMBLE),
	ACPI_DEBUG_INIT(ACPI_LV_VERBOSE_INFO),
	ACPI_DEBUG_INIT(ACPI_LV_FULL_TABLES),
	ACPI_DEBUG_INIT(ACPI_LV_EVENTS),
};

/* --------------------------------------------------------------------------
                              FS Interface (/sys)
   -------------------------------------------------------------------------- */
static int param_get_debug_layer(char *buffer, struct kernel_param *kp) {
	int result = 0;
	int i;

	result = sprintf(buffer, "%-25s\tHex        SET\n", "Description");

	for(i = 0; i <ARRAY_SIZE(acpi_debug_layers); i++) {
		result += sprintf(buffer+result, "%-25s\t0x%08lX [%c]\n",
					acpi_debug_layers[i].name,
					acpi_debug_layers[i].value,
					(acpi_dbg_layer & acpi_debug_layers[i].value) ? '*' : ' ');
	}
	result += sprintf(buffer+result, "%-25s\t0x%08X [%c]\n", "ACPI_ALL_DRIVERS",
					ACPI_ALL_DRIVERS,
					(acpi_dbg_layer & ACPI_ALL_DRIVERS) ==
					ACPI_ALL_DRIVERS ? '*' : (acpi_dbg_layer &
					ACPI_ALL_DRIVERS) == 0 ? ' ' : '-');
	result += sprintf(buffer+result, "--\ndebug_layer = 0x%08X ( * = enabled)\n", acpi_dbg_layer);

	return result;
}

static int param_get_debug_level(char *buffer, struct kernel_param *kp) {
	int result = 0;
	int i;

	result = sprintf(buffer, "%-25s\tHex        SET\n", "Description");

	for (i = 0; i < ARRAY_SIZE(acpi_debug_levels); i++) {
		result += sprintf(buffer+result, "%-25s\t0x%08lX [%c]\n",
				     acpi_debug_levels[i].name,
				     acpi_debug_levels[i].value,
				     (acpi_dbg_level & acpi_debug_levels[i].
				      value) ? '*' : ' ');
	}
	result += sprintf(buffer+result, "--\ndebug_level = 0x%08X (* = enabled)\n",
			     acpi_dbg_level);

	return result;
}

module_param_call(debug_layer, param_set_uint, param_get_debug_layer, &acpi_dbg_layer, 0644);
module_param_call(debug_level, param_set_uint, param_get_debug_level, &acpi_dbg_level, 0644);

static char trace_method_name[6];
module_param_string(trace_method_name, trace_method_name, 6, 0644);
static unsigned int trace_debug_layer;
module_param(trace_debug_layer, uint, 0644);
static unsigned int trace_debug_level;
module_param(trace_debug_level, uint, 0644);

static int param_set_trace_state(const char *val, struct kernel_param *kp)
{
	int result = 0;

	if (!strncmp(val, "enable", strlen("enable") - 1)) {
		result = acpi_debug_trace(trace_method_name, trace_debug_level,
					  trace_debug_layer, 0);
		if (result)
			result = -EBUSY;
		goto exit;
	}

	if (!strncmp(val, "disable", strlen("disable") - 1)) {
		int name = 0;
		result = acpi_debug_trace((char *)&name, trace_debug_level,
					  trace_debug_layer, 0);
		if (result)
			result = -EBUSY;
		goto exit;
	}

	if (!strncmp(val, "1", 1)) {
		result = acpi_debug_trace(trace_method_name, trace_debug_level,
					  trace_debug_layer, 1);
		if (result)
			result = -EBUSY;
		goto exit;
	}

	result = -EINVAL;
exit:
	return result;
}

static int param_get_trace_state(char *buffer, struct kernel_param *kp)
{
	if (!acpi_gbl_trace_method_name)
		return sprintf(buffer, "disable");
	else {
		if (acpi_gbl_trace_flags & 1)
			return sprintf(buffer, "1");
		else
			return sprintf(buffer, "enable");
	}
	return 0;
}

module_param_call(trace_state, param_set_trace_state, param_get_trace_state,
		  NULL, 0644);

/* --------------------------------------------------------------------------
				DebugFS Interface
   -------------------------------------------------------------------------- */

static ssize_t cm_write(struct file *file, const char __user *user_buf,
			size_t count, loff_t *ppos)
{
	static char *buf;
	static int uncopied_bytes;
	struct acpi_table_header table;
	acpi_status status;

	if (!(*ppos)) {
		/* parse the table header to get the table length */
		if (count <= sizeof(struct acpi_table_header))
			return -EINVAL;
		if (copy_from_user(&table, user_buf,
			sizeof(struct acpi_table_header)))
			return -EFAULT;
		uncopied_bytes = table.length;
		buf = kzalloc(uncopied_bytes, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
	}

	if (uncopied_bytes < count) {
		kfree(buf);
		return -EINVAL;
	}

	if (copy_from_user(buf + (*ppos), user_buf, count)) {
		kfree(buf);
		return -EFAULT;
	}

	uncopied_bytes -= count;
	*ppos += count;

	if (!uncopied_bytes) {
		status = acpi_install_method(buf);
		kfree(buf);
		if (ACPI_FAILURE(status))
			return -EINVAL;
		add_taint(TAINT_OVERRIDDEN_ACPI_TABLE);
	}

	return count;
}

static const struct file_operations cm_fops = {
	.write = cm_write,
};

static int acpi_debugfs_init(void)
{
	struct dentry *acpi_dir, *cm_dentry;

	acpi_dir = debugfs_create_dir("acpi", NULL);
	if (!acpi_dir)
		goto err;

	cm_dentry = debugfs_create_file("custom_method", S_IWUGO,
					acpi_dir, NULL, &cm_fops);
	if (!cm_dentry)
		goto err;

	return 0;

err:
	if (acpi_dir)
		debugfs_remove(acpi_dir);
	return -EINVAL;
}

/* --------------------------------------------------------------------------
                              FS Interface (/proc)
   -------------------------------------------------------------------------- */
#ifdef CONFIG_ACPI_PROCFS
#define ACPI_SYSTEM_FILE_DEBUG_LAYER	"debug_layer"
#define ACPI_SYSTEM_FILE_DEBUG_LEVEL		"debug_level"

static int acpi_system_debug_proc_show(struct seq_file *m, void *v)
{
	unsigned int i;

	seq_printf(m, "%-25s\tHex        SET\n", "Description");

	switch ((unsigned long)m->private) {
	case 0:
		for (i = 0; i < ARRAY_SIZE(acpi_debug_layers); i++) {
			seq_printf(m, "%-25s\t0x%08lX [%c]\n",
				     acpi_debug_layers[i].name,
				     acpi_debug_layers[i].value,
				     (acpi_dbg_layer & acpi_debug_layers[i].
				      value) ? '*' : ' ');
		}
		seq_printf(m, "%-25s\t0x%08X [%c]\n", "ACPI_ALL_DRIVERS",
			     ACPI_ALL_DRIVERS,
			     (acpi_dbg_layer & ACPI_ALL_DRIVERS) ==
			     ACPI_ALL_DRIVERS ? '*' : (acpi_dbg_layer &
						       ACPI_ALL_DRIVERS) ==
			     0 ? ' ' : '-');
		seq_printf(m,
			     "--\ndebug_layer = 0x%08X (* = enabled, - = partial)\n",
			     acpi_dbg_layer);
		break;
	case 1:
		for (i = 0; i < ARRAY_SIZE(acpi_debug_levels); i++) {
			seq_printf(m, "%-25s\t0x%08lX [%c]\n",
				     acpi_debug_levels[i].name,
				     acpi_debug_levels[i].value,
				     (acpi_dbg_level & acpi_debug_levels[i].
				      value) ? '*' : ' ');
		}
		seq_printf(m, "--\ndebug_level = 0x%08X (* = enabled)\n",
			     acpi_dbg_level);
		break;
	}
	return 0;
}

static int acpi_system_debug_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, acpi_system_debug_proc_show, PDE(inode)->data);
}

static ssize_t acpi_system_debug_proc_write(struct file *file,
			const char __user * buffer,
			size_t count, loff_t *pos)
{
	char debug_string[12] = { '\0' };


	if (count > sizeof(debug_string) - 1)
		return -EINVAL;

	if (copy_from_user(debug_string, buffer, count))
		return -EFAULT;

	debug_string[count] = '\0';

	switch ((unsigned long)PDE(file->f_path.dentry->d_inode)->data) {
	case 0:
		acpi_dbg_layer = simple_strtoul(debug_string, NULL, 0);
		break;
	case 1:
		acpi_dbg_level = simple_strtoul(debug_string, NULL, 0);
		break;
	default:
		return -EINVAL;
	}

	return count;
}

static const struct file_operations acpi_system_debug_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= acpi_system_debug_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= acpi_system_debug_proc_write,
};
#endif

int __init acpi_procfs_init(void)
{
#ifdef CONFIG_ACPI_PROCFS
	struct proc_dir_entry *entry;
	int error = 0;
	char *name;

	/* 'debug_layer' [R/W] */
	name = ACPI_SYSTEM_FILE_DEBUG_LAYER;
	entry = proc_create_data(name, S_IFREG | S_IRUGO | S_IWUSR,
				 acpi_root_dir, &acpi_system_debug_proc_fops,
				 (void *)0);
	if (!entry)
		goto Error;

	/* 'debug_level' [R/W] */
	name = ACPI_SYSTEM_FILE_DEBUG_LEVEL;
	entry = proc_create_data(name, S_IFREG | S_IRUGO | S_IWUSR,
				 acpi_root_dir, &acpi_system_debug_proc_fops,
				 (void *)1);
	if (!entry)
		goto Error;

      Done:
	return error;

      Error:
	remove_proc_entry(ACPI_SYSTEM_FILE_DEBUG_LEVEL, acpi_root_dir);
	remove_proc_entry(ACPI_SYSTEM_FILE_DEBUG_LAYER, acpi_root_dir);
	error = -ENODEV;
	goto Done;
#else
	return 0;
#endif
}

int __init acpi_debug_init(void)
{
	acpi_debugfs_init();
	acpi_procfs_init();
	return 0;
}

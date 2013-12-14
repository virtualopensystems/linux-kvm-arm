/*
 * Vosys DMA Engine test module
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>

// test parameters
#define MEM_TO_MEM_CPY		0
#define DEFAULT_TEST_TYPE	MEM_TO_MEM_CPY

#define DEFAULT_BUFFER_SIZE	1024

#define TEST_THREAD_STARTED 	0
#define TEST_THREAD_STOPPED	1
#define TEST_THREAD_DONE_OK	2
#define TEST_THREAD_DONE_ER	3

#define DMATEST_DEBUG		1

#define dmatest_err(fmt, ...) \
	printk(KERN_ERR "%s" pr_fmt(fmt), "vosys dmatest: ", ##__VA_ARGS__)

#ifdef DMATEST_DEBUG 
#define dmatest_debug(fmt, ...) \
	printk(KERN_DEBUG "%s" pr_fmt(fmt), "vosys dmatest: ", ##__VA_ARGS__)
#else
#define dmatest_debug(fmt, ...)
#endif

/*
struct dma_chan {
	struct dma_device *device;
	dma_cookie_t cookie;
	dma_cookie_t completed_cookie;

	// sysfs
	int chan_id;
	struct dma_chan_dev *dev;

	struct list_head device_node;
	struct dma_chan_percpu __percpu *local;
	int client_count;
	int table_count;
	void *private;
};
*/

enum dmatest_error {
	ERROR,	
};

struct dmatest_params {
	unsigned char type;
	unsigned int buffer_size;
};

struct dmatest_info {
	struct dmatest_params	params;

	int 			is_running;

	// debugfs stuff
	struct dentry		*root;

	struct list_head	results;

	// mutex to lock this structure
	struct mutex lock;

	// dma address for source and destination
	dma_addr_t dma_src;
	dma_addr_t dma_dst;
};

static struct dmatest_info info_test;

static void async_tx_done(void *arg)
{
	struct dmatest_info *info = (struct dmatest_info *)arg;
	info->is_running = false;

	dmatest_debug("callback: transfer completed\n");
}

dma_cookie_t cpy_mem_to_mem(struct dma_chan *channel, void *dst,
		void *src, size_t len, dma_async_tx_callback done_callback, struct dmatest_info *info)
{
	struct dma_device *dev = channel->device;
	struct dma_async_tx_descriptor *tx;
	dma_addr_t dma_dst, dma_src;
	dma_cookie_t cookie;
	unsigned long flags;

	dma_src = dma_map_single(dev->dev, src, len, DMA_TO_DEVICE);
	dma_dst = dma_map_single(dev->dev, dst, len, DMA_FROM_DEVICE);

	info->dma_src = dma_src;
	info->dma_dst = dma_dst;

	flags = DMA_CTRL_ACK;

	tx = dev->device_prep_dma_memcpy(channel, dma_dst, dma_src,
			len, flags);
	if (!tx) {
		dma_unmap_single(dev->dev, dma_src, len, DMA_TO_DEVICE);
		dma_unmap_single(dev->dev, dma_dst, len, DMA_FROM_DEVICE);
		return -ENOMEM;
	}

	tx->callback = done_callback;
	tx->callback_param = info;
	cookie = tx->tx_submit(tx);

	preempt_disable();
	__this_cpu_add(channel->local->bytes_transferred, len);
	__this_cpu_inc(channel->local->memcpy_count);
	preempt_enable();

	return cookie;
}

void unmap_mem_to_mem(struct dma_chan *channel, struct dmatest_info *info, size_t len)
{
	struct dma_device *dev = channel->device;

	dma_unmap_single(dev->dev, info->dma_src, len, DMA_TO_DEVICE);
	dma_unmap_single(dev->dev, info->dma_dst, len, DMA_FROM_DEVICE);
}

static bool start_test_thread(struct dmatest_info *info)
{	
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wait);
	dma_cap_mask_t mask;
	struct dma_chan *channel;
	struct dmatest_params *params;
	int i;
	
	struct dma_device *device;
	dma_cookie_t res_cookie;

	enum dma_ctrl_flags flags;
	enum dma_status tx_status;

	int buf_size;

	// test buffer
	u8 *src_buf_ptr;
	u8 *dst_buf_ptr;

	info->is_running = true;
	
	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY, mask);
	channel = dma_request_channel(mask, NULL, NULL);

	// set DMA flags, for now we are not triggering interrupts
	flags = /*DMA_CTRL_ACK | */DMA_PREP_INTERRUPT;
	      /*| DMA_COMPL_SKIP_DEST_UNMAP | DMA_COMPL_SRC_UNMAP_SINGLE;*/

	if (!channel) {
		dmatest_err("no DMA channel available\n");
		return false;
	}

	device = channel->device;

	params = &info->params;
	buf_size = params->buffer_size;

	src_buf_ptr = kmalloc(buf_size, GFP_KERNEL);
	dst_buf_ptr = kmalloc(buf_size , GFP_KERNEL);

	if (!src_buf_ptr || !dst_buf_ptr) {
		dmatest_err("error while allocating buffers\n");
		return false;
	}

	for (i = 0; i < buf_size; i++) {
		*(src_buf_ptr + i*sizeof(u8)) = 0xA;
		*(dst_buf_ptr + i*sizeof(u8)) = 0xB;
	}

	res_cookie = cpy_mem_to_mem(channel, dst_buf_ptr, src_buf_ptr,
			buf_size, async_tx_done, info);

	if (dma_submit_error(res_cookie)) {
		dmatest_err("error during copy\n");
		return -1;
	}

	tx_status = dma_sync_wait(channel, res_cookie);

	switch(tx_status) {
		case DMA_IN_PROGRESS:
			dmatest_err("tx in progress\n");
			break;

		case DMA_PAUSED:
			dmatest_err("tx paused\n");
			break;

		case DMA_ERROR:
			dmatest_err("tx error\n");

		case DMA_COMPLETE:
		default:
			dmatest_debug("tx completed\n");
	}

	// verify if source and destination are the same
	for (i = 0; i < buf_size; i++) {
		if (*(src_buf_ptr + i*sizeof(u8)) != *(dst_buf_ptr + i*sizeof(u8))) {
			dmatest_err("src and destination do not match\n");
			return false;
		}
	}

	dmatest_debug("source and destination match.\n");

	dma_release_channel(channel);
	return true;
}

static bool is_thread_running(struct dmatest_info *info)
{
	return info->is_running;
}

static ssize_t start_read(struct file *file, char __user *user_buf,
		size_t count, loff_t *ppos)
{
	struct dmatest_info *info = file->private_data;
	char ret_buf[3];

	mutex_lock(&info->lock);
	if (is_thread_running(info)) {
		ret_buf[0] = 'Y';
	}
	else {
		ret_buf[0] = 'N';
	}
	mutex_unlock(&info->lock);

	ret_buf[1] = '\n';
	ret_buf[2] = 0x00;

	return simple_read_from_buffer(user_buf, count, ppos, ret_buf, 2);
}

static ssize_t start_write(struct file *file, const char __user *user_buf,
		size_t count, loff_t *ppos)
{
	// why this pointer is not working???
	// struct dmatest_info *info = file->private_data;
	char ret_buf[16];
	bool usr_val;

	if (copy_from_user(ret_buf, user_buf, min(count, (sizeof(ret_buf) - 1)))) {
		return -EFAULT;
	}

	if(strtobool(ret_buf, &usr_val) == 0) {
		if (usr_val && !is_thread_running(&info_test)) {
			// start test thread
			start_test_thread(&info_test);
		}
		else if(!usr_val && !is_thread_running(&info_test)) {
			// stop test thread
		}
	}
	return 1;
}

static const struct file_operations start_test_fops = {
	.read	= start_read,
	.write	= start_write,
	.open	= simple_open,
	.llseek	= default_llseek,
};

static int dmatest_register_dbgfs(struct dmatest_info *info)
{
	struct dentry *d;
	struct dmatest_params *params;

	d = debugfs_create_dir("vosys_dmatest", NULL);
	if (IS_ERR(d))
		return PTR_ERR(d);
	if (!d)
		goto err_root;

	info->root = d;

	/* Run or stop test */
	debugfs_create_file("start", S_IWUSR | S_IRUGO,
			info->root, info, &start_test_fops);

	params = &info->params;
	debugfs_create_u8("type", S_IWUSR | S_IRUGO, 
			info->root, &params->type);
	
	debugfs_create_u32("size", S_IWUSR | S_IRUGO,
			info->root, &params->buffer_size);
	return 0;

err_root:
	dmatest_err("Failed to initialize debugfs\n");
	return -ENOMEM;
}

static int __init dmatest_init(void)
{
	struct dmatest_info *info = &info_test;
	struct dmatest_params *params = &info->params;
	int ret;

	dmatest_debug("vosys dmatest module init\n");

	memset(info, 0, sizeof(*info));

	// info init
	info->is_running = 0;	
	INIT_LIST_HEAD(&info->results);
	mutex_init(&info->lock);

	// default parameters init
	params->type = DEFAULT_TEST_TYPE;
	params->buffer_size = DEFAULT_BUFFER_SIZE;

	ret = dmatest_register_dbgfs(info);
	if (ret) {
		dmatest_err("vosys dmatest module init error\n");
		return ret;
	}

	return 0;
}

late_initcall(dmatest_init);

static void __exit dmatest_exit(void)
{
}
module_exit(dmatest_exit);

MODULE_AUTHOR("VirtualOpenSystems");
MODULE_LICENSE("GPL v2");

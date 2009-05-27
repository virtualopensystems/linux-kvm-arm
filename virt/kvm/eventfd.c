/*
 * kvm eventfd support - use eventfd objects to signal various KVM events
 *
 * Copyright 2009 Novell.  All Rights Reserved.
 *
 * Author:
 *	Gregory Haskins <ghaskins@novell.com>
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <linux/kvm_host.h>
#include <linux/workqueue.h>
#include <linux/syscalls.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/eventfd.h>

/*
 * --------------------------------------------------------------------
 * irqfd: Allows an fd to be used to inject an interrupt to the guest
 *
 * Credit goes to Avi Kivity for the original idea.
 * --------------------------------------------------------------------
 */
struct _irqfd {
	struct kvm               *kvm;
	int                       gsi;
	struct file              *file;
	struct list_head          list;
	poll_table                pt;
	wait_queue_head_t        *wqh;
	wait_queue_t              wait;
	struct work_struct        work;
};

static void
irqfd_inject(struct work_struct *work)
{
	struct _irqfd *irqfd = container_of(work, struct _irqfd, work);
	struct kvm *kvm = irqfd->kvm;

	mutex_lock(&kvm->lock);
	kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 1);
	kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 0);
	mutex_unlock(&kvm->lock);
}

static int
irqfd_wakeup(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct _irqfd *irqfd = container_of(wait, struct _irqfd, wait);

	/*
	 * The wake_up is called with interrupts disabled.  Therefore we need
	 * to defer the IRQ injection until later since we need to acquire the
	 * kvm->lock to do so.
	 */
	schedule_work(&irqfd->work);

	return 0;
}

static void
irqfd_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh,
			poll_table *pt)
{
	struct _irqfd *irqfd = container_of(pt, struct _irqfd, pt);

	irqfd->wqh = wqh;
	add_wait_queue(wqh, &irqfd->wait);
}

static int
kvm_assign_irqfd(struct kvm *kvm, int fd, int gsi)
{
	struct _irqfd *irqfd;
	struct file *file = NULL;
	int ret;

	irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		return -ENOMEM;

	irqfd->kvm = kvm;
	irqfd->gsi = gsi;
	INIT_LIST_HEAD(&irqfd->list);
	INIT_WORK(&irqfd->work, irqfd_inject);

	/*
	 * Embed the file* lifetime in the irqfd.
	 */
	file = eventfd_fget(fd);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto fail;
	}

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd
	 */
	init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);
	init_poll_funcptr(&irqfd->pt, irqfd_ptable_queue_proc);

	ret = file->f_op->poll(file, &irqfd->pt);
	if (ret < 0)
		goto fail;

	irqfd->file = file;

	mutex_lock(&kvm->lock);
	list_add_tail(&irqfd->list, &kvm->irqfds);
	mutex_unlock(&kvm->lock);

	return 0;

fail:
	if (irqfd->wqh)
		remove_wait_queue(irqfd->wqh, &irqfd->wait);

	if (file && !IS_ERR(file))
		fput(file);

	kfree(irqfd);
	return ret;
}

static void
irqfd_release(struct _irqfd *irqfd)
{
	/*
	 * The ordering is important.  We must remove ourselves from the wqh
	 * first to ensure no more event callbacks are issued, and then flush
	 * any previously scheduled work prior to freeing the memory
	 */
	remove_wait_queue(irqfd->wqh, &irqfd->wait);

	flush_work(&irqfd->work);

	fput(irqfd->file);
	kfree(irqfd);
}

static struct _irqfd *
irqfd_remove(struct kvm *kvm, struct file *file, int gsi)
{
	struct _irqfd *irqfd;

	mutex_lock(&kvm->lock);

	/*
	 * linear search isn't brilliant, but this should be an infrequent
	 * slow-path operation, and the list should not grow very large
	 */
	list_for_each_entry(irqfd, &kvm->irqfds, list) {
		if (irqfd->file != file || irqfd->gsi != gsi)
			continue;

		list_del(&irqfd->list);
		mutex_unlock(&kvm->lock);

		return irqfd;
	}

	mutex_unlock(&kvm->lock);

	return NULL;
}

static int
kvm_deassign_irqfd(struct kvm *kvm, int fd, int gsi)
{
	struct _irqfd *irqfd;
	struct file *file;
	int count = 0;

	file = fget(fd);
	if (IS_ERR(file))
		return PTR_ERR(file);

	while ((irqfd = irqfd_remove(kvm, file, gsi))) {
		/*
		 * We remove the item from the list under the lock, but we
		 * free it outside the lock to avoid deadlocking with the
		 * flush_work and the work_item taking the lock
		 */
		irqfd_release(irqfd);
		count++;
	}

	fput(file);

	return count ? count : -ENOENT;
}

void
kvm_irqfd_init(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->irqfds);
}

int
kvm_irqfd(struct kvm *kvm, int fd, int gsi, int flags)
{
	if (flags & KVM_IRQFD_FLAG_DEASSIGN)
		return kvm_deassign_irqfd(kvm, fd, gsi);

	return kvm_assign_irqfd(kvm, fd, gsi);
}

void
kvm_irqfd_release(struct kvm *kvm)
{
	struct _irqfd *irqfd, *tmp;

	/* don't bother with the lock..we are shutting down */
	list_for_each_entry_safe(irqfd, tmp, &kvm->irqfds, list) {
		list_del(&irqfd->list);
		irqfd_release(irqfd);
	}
}

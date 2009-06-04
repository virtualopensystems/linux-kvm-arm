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
#include <linux/srcu.h>

/*
 * --------------------------------------------------------------------
 * irqfd: Allows an fd to be used to inject an interrupt to the guest
 *
 * Credit goes to Avi Kivity for the original idea.
 * --------------------------------------------------------------------
 */
struct _irqfd {
	struct mutex              lock;
	struct srcu_struct        srcu;
	struct kvm               *kvm;
	int                       gsi;
	struct list_head          list;
	poll_table                pt;
	wait_queue_head_t        *wqh;
	wait_queue_t              wait;
	struct work_struct        inject;
};

static void
irqfd_inject(struct work_struct *work)
{
	struct _irqfd *irqfd = container_of(work, struct _irqfd, inject);
	struct kvm *kvm;
	int idx;

	idx = srcu_read_lock(&irqfd->srcu);

	kvm = rcu_dereference(irqfd->kvm);
	if (kvm) {
		mutex_lock(&kvm->irq_lock);
		kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 1);
		kvm_set_irq(kvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 0);
		mutex_unlock(&kvm->irq_lock);
	}

	srcu_read_unlock(&irqfd->srcu, idx);
}

static void
irqfd_disconnect(struct _irqfd *irqfd)
{
	struct kvm *kvm;

	mutex_lock(&irqfd->lock);

	kvm = rcu_dereference(irqfd->kvm);
	rcu_assign_pointer(irqfd->kvm, NULL);

	mutex_unlock(&irqfd->lock);

	if (!kvm)
		return;

	mutex_lock(&kvm->lock);
	list_del(&irqfd->list);
	mutex_unlock(&kvm->lock);

	/*
	 * It is important to not drop the kvm reference until the next grace
	 * period because there might be lockless references in flight up
	 * until then
	 */
	synchronize_srcu(&irqfd->srcu);
	kvm_put_kvm(kvm);
}

static int
irqfd_wakeup(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct _irqfd *irqfd = container_of(wait, struct _irqfd, wait);
	unsigned long flags = (unsigned long)key;

	if (flags & POLLIN)
		/*
		 * The POLLIN wake_up is called with interrupts disabled.
		 * Therefore we need to defer the IRQ injection until later
		 * since we need to acquire the kvm->lock to do so.
		 */
		schedule_work(&irqfd->inject);

	if (flags & POLLHUP) {
		/*
		 * The POLLHUP is called unlocked, so it theoretically should
		 * be safe to remove ourselves from the wqh using the locked
		 * variant of remove_wait_queue()
		 */
		remove_wait_queue(irqfd->wqh, &irqfd->wait);
		flush_work(&irqfd->inject);
		irqfd_disconnect(irqfd);

		cleanup_srcu_struct(&irqfd->srcu);
		kfree(irqfd);
	}

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

int
kvm_irqfd(struct kvm *kvm, int fd, int gsi, int flags)
{
	struct _irqfd *irqfd;
	struct file *file = NULL;
	int ret;

	irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		return -ENOMEM;

	mutex_init(&irqfd->lock);
	init_srcu_struct(&irqfd->srcu);
	irqfd->kvm = kvm;
	irqfd->gsi = gsi;
	INIT_LIST_HEAD(&irqfd->list);
	INIT_WORK(&irqfd->inject, irqfd_inject);

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

	kvm_get_kvm(kvm);

	mutex_lock(&kvm->lock);
	list_add_tail(&irqfd->list, &kvm->irqfds);
	mutex_unlock(&kvm->lock);

	/*
	 * do not drop the file until the irqfd is fully initialized, otherwise
	 * we might race against the POLLHUP
	 */
	fput(file);

	return 0;

fail:
	if (irqfd->wqh)
		remove_wait_queue(irqfd->wqh, &irqfd->wait);

	if (file && !IS_ERR(file))
		fput(file);

	kfree(irqfd);
	return ret;
}

void
kvm_irqfd_init(struct kvm *kvm)
{
	INIT_LIST_HEAD(&kvm->irqfds);
}

void
kvm_irqfd_release(struct kvm *kvm)
{
	struct _irqfd *irqfd, *tmp;

	list_for_each_entry_safe(irqfd, tmp, &kvm->irqfds, list)
		irqfd_disconnect(irqfd);
}

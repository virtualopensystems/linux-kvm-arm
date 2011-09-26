/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 * 
 * This program is free software and is provided to you under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and any use by you of this program is subject to the terms of such GNU licence.
 * 
 * A copy of the licence is included with the program, and can also be obtained from Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 * @file mali_osk_notification.c
 * Implementation of the OS abstraction layer for the kernel device driver
 */

#include "mali_osk.h"
#include "mali_kernel_common.h"

/* needed to detect kernel version specific code */
#include <linux/version.h>

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/semaphore.h>
#else /* pre 2.6.26 the file was in the arch specific location */
#include <asm/semaphore.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
#define LOCK_INIT(x)    sema_init(x,1)
#else
#define LOCK_INIT(x)    init_MUTEX(x)
#endif

/**
 * Declaration of the notification queue object type
 * Contains a linked list of notification pending delivery to user space.
 * It also contains a wait queue of exclusive waiters blocked in the ioctl
 * When a new notification is posted a single thread is resumed.
 */
struct _mali_osk_notification_queue_t_struct
{
	struct semaphore mutex; /**< Mutex protecting the list */
	wait_queue_head_t receive_queue; /**< Threads waiting for new entries to the queue */
	struct list_head head; /**< List of notifications waiting to be picked up */
};

typedef struct _mali_osk_notification_wrapper_t_struct
{
    struct list_head list;           /**< Internal linked list variable */
    _mali_osk_notification_t data;   /**< Notification data */
} _mali_osk_notification_wrapper_t;

_mali_osk_notification_queue_t *_mali_osk_notification_queue_init( void )
{
	_mali_osk_notification_queue_t *	result;

	result = (_mali_osk_notification_queue_t *)kmalloc(sizeof(_mali_osk_notification_queue_t), GFP_KERNEL);
	if (NULL == result) return NULL;

	LOCK_INIT(&result->mutex);
	init_waitqueue_head(&result->receive_queue);
	INIT_LIST_HEAD(&result->head);

	return result;
}

_mali_osk_notification_t *_mali_osk_notification_create( u32 type, u32 size )
{
	/* OPT Recycling of notification objects */
    _mali_osk_notification_wrapper_t *notification;

	notification = (_mali_osk_notification_wrapper_t *)kmalloc( sizeof(_mali_osk_notification_wrapper_t), GFP_KERNEL );
    if (NULL == notification)
    {
		MALI_DEBUG_PRINT(1, ("Failed to create a notification object\n"));
		return NULL;
    }

	/* Init the list */
	INIT_LIST_HEAD(&notification->list);

	/* allocate memory for the buffer requested */
	notification->data.result_buffer = kmalloc( size, GFP_KERNEL );
	if ( NULL == notification->data.result_buffer )
	{
		/* failed to buffer, cleanup */
		MALI_DEBUG_PRINT(1, ("Failed to allocate memory for notification object buffer of size %d\n", size));
		kfree(notification);
		return NULL;
	}
	/* set up the non-allocating fields */
	notification->data.notification_type = type;
	notification->data.result_buffer_size = size;

	/* all ok */
    return &(notification->data);
}

void _mali_osk_notification_delete( _mali_osk_notification_t *object )
{
	_mali_osk_notification_wrapper_t *notification;
	MALI_DEBUG_ASSERT_POINTER( object );

    notification = container_of( object, _mali_osk_notification_wrapper_t, data );

	/* Remove from the list */
	list_del(&notification->list);
	/* Free the buffer */
	kfree(notification->data.result_buffer);
	/* Free the container */
	kfree(notification);
}

void _mali_osk_notification_queue_term( _mali_osk_notification_queue_t *queue )
{
	MALI_DEBUG_ASSERT_POINTER( queue );

	/* not much to do, just free the memory */
	kfree(queue);
}

void _mali_osk_notification_queue_send( _mali_osk_notification_queue_t *queue, _mali_osk_notification_t *object )
{
	_mali_osk_notification_wrapper_t *notification;
	MALI_DEBUG_ASSERT_POINTER( queue );
	MALI_DEBUG_ASSERT_POINTER( object );

    notification = container_of( object, _mali_osk_notification_wrapper_t, data );

	/* lock queue access */
	down(&queue->mutex);
	/* add to list */
	list_add_tail(&notification->list, &queue->head);
	/* unlock the queue */
	up(&queue->mutex);

	/* and wake up one possible exclusive waiter */
	wake_up(&queue->receive_queue);
}

_mali_osk_errcode_t _mali_osk_notification_queue_receive( _mali_osk_notification_queue_t *queue, u32 timeout, _mali_osk_notification_t **result )
{
	_mali_osk_notification_wrapper_t *wrapper_object;
    /* check input */
	MALI_DEBUG_ASSERT_POINTER( queue );
	MALI_DEBUG_ASSERT_POINTER( result );

    /* default result */
	*result = NULL;

	/* lock queue */
	if (down_interruptible(&queue->mutex)) return _MALI_OSK_ERR_RESTARTSYSCALL; /* handle the signal, then retry */

	/* check for a pending notification */
	while (0 != list_empty(&queue->head))
	{
		/* no notification ready, we have to wait for one */
		int schedule_result;
		/* define a wait entry */
		DEFINE_WAIT(wait);

		if( timeout == 0 )
		{
			/* Actually, don't wait for any time when nothing is in the queue */
			up(&queue->mutex);
			return _MALI_OSK_ERR_TIMEOUT;
		}

		/* prepare for exclusive wait, tag as interruptible (accept signals) */
		prepare_to_wait_exclusive(&queue->receive_queue, &wait, TASK_INTERRUPTIBLE);

		/* release the lock before waiting */
		up(&queue->mutex);

		/* if the check fails again schedule (sleep) */
		schedule_result = schedule_timeout(msecs_to_jiffies(timeout));

		/* we're running again, wait finished (or never started) */
		finish_wait(&queue->receive_queue, &wait);

		/* check why we got scheduled */
		if (0 == schedule_result) return _MALI_OSK_ERR_TIMEOUT; /* timeout, ok, NULL will be returned */
		if (signal_pending(current)) return _MALI_OSK_ERR_RESTARTSYSCALL; /* handle the signal, then retry */

		/* we were woken because of a new entry */
		/* lock the queue and check (with normal signal handling logic) */
		if (down_interruptible(&queue->mutex)) return _MALI_OSK_ERR_RESTARTSYSCALL; /* handle the signal, then retry */
	}

	/*
		The while loop terminates when the list is non-empty and we hold the lock
		Pop the head and release the lock
	*/
	wrapper_object = list_entry(queue->head.next, _mali_osk_notification_wrapper_t, list);
	*result = &(wrapper_object->data);
	list_del_init(&wrapper_object->list);

	up(&queue->mutex);

	return _MALI_OSK_ERR_OK; /* all ok */
}

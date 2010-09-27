/*
 *  ioctl.c
 *
 *  Copyright (C) 1995, 1996 by Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 *  Copyright (C) 2008-2009 ARM Limited
 *
 *  Please add a note about your changes to vmfs_ in the ChangeLog file.
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/highuid.h>
//#include <linux/net.h>

#include "vmfs_fs.h"
#include "vmfs_mount.h"

#include <asm/uaccess.h>

#include "proto.h"

// GPB - not sure we actually need this
int
vmfs_ioctl(struct inode *inode, struct file *filp,
      unsigned int cmd, unsigned long arg)
{
    struct vmfs_sb_info *server = server_from_inode(inode);
    int result = -EINVAL;

    switch (cmd) {
        uid16_t uid16;
        uid_t uid32;
    case VMFS_IOC_GETMOUNTUID:
        SET_UID(uid16, server->mnt->mounted_uid);
        result = put_user(uid16, (uid16_t __user *) arg);
        break;
    case VMFS_IOC_GETMOUNTUID32:
        SET_UID(uid32, server->mnt->mounted_uid);
        result = put_user(uid32, (uid_t __user *) arg);
        break;
    default:
        break;
    }

    return result;
}

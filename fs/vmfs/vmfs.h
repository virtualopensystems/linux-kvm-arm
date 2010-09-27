/*
 *  vmfs.h
 *
 *  Copyright (C) 1995, 1996 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 */

#ifndef _LINUX_VMFS_H
#define _LINUX_VMFS_H

#include <linux/types.h>
#include <linux/magic.h>

#ifdef __KERNEL__

#define VMFS_MAXNAMELEN 255
#define VMFS_MAXPATHLEN 1024

/*
 * Contains all relevant data on a VMFS networked file.
 */
struct vmfs_fattr {
    __u16 attr;

    unsigned long   f_ino;
    umode_t     f_mode;
    nlink_t     f_nlink;
    uid_t       f_uid;
    gid_t       f_gid;
    dev_t       f_rdev;
    loff_t      f_size;
    struct timespec f_atime;
    struct timespec f_mtime;
    struct timespec f_ctime;
    unsigned long   f_blocks;
    int     f_unix;

    // vfs bits
    uint32_t f_type;
};

#endif
#endif

/*
 *  vmfs_mount.h
 *
 *  Copyright (C) 1995, 1996 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 */

#ifndef _LINUX_VMFS_MOUNT_H
#define _LINUX_VMFS_MOUNT_H

#include <linux/types.h>

#define VMFS_MOUNT_VERSION  6

struct vmfs_mount_data {
    int version;
    __kernel_uid_t mounted_uid; /* Who may umount() this filesystem? */
    __kernel_uid_t uid;
    __kernel_gid_t gid;
    __kernel_mode_t file_mode;
    __kernel_mode_t dir_mode;
};


#ifdef __KERNEL__

/* "vers" in big-endian */
#define VMFS_MOUNT_ASCII 0x76657273

#define VMFS_MOUNT_OLDVERSION   6
#undef VMFS_MOUNT_VERSION
#define VMFS_MOUNT_VERSION  7

/* flags */
#define VMFS_MOUNT_WIN95        0x0001  /* Win 95 server */
#define VMFS_MOUNT_OLDATTR  0x0002  /* Use core getattr (Win 95 speedup) */
#define VMFS_MOUNT_DIRATTR  0x0004  /* Use find_first for getattr */
#define VMFS_MOUNT_CASE     0x0008  /* Be case sensitive */
#define VMFS_MOUNT_UNICODE  0x0010  /* Server talks unicode */
#define VMFS_MOUNT_UID      0x0020  /* Use user specified uid */
#define VMFS_MOUNT_GID      0x0040  /* Use user specified gid */
#define VMFS_MOUNT_FMODE        0x0080  /* Use user specified file mode */
#define VMFS_MOUNT_DMODE        0x0100  /* Use user specified dir mode */

struct vmfs_mount_data_kernel {
    int version;

    uid_t mounted_uid;  /* Who may umount() this filesystem? */
    uid_t uid;
    gid_t gid;
    mode_t file_mode;
    mode_t dir_mode;

    u32 flags;

        /* maximum age in jiffies (inode, dentry and dircache) */
    int ttl;
};

#endif

#endif

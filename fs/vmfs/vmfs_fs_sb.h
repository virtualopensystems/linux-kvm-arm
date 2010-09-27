/*
 *  vmfs_fs_sb.h
 *
 *  Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 *  Copyright (C) 2008-2009 ARM Limited
 *
 */

#ifndef _VMFS_FS_SB
#define _VMFS_FS_SB

#ifdef __KERNEL__

#include <linux/types.h>
#include "vmfs.h"
#include "vfs.h"

/* structure access macros */
#define server_from_inode(inode) VMFS_SB((inode)->i_sb)
#define server_from_dentry(dentry) VMFS_SB((dentry)->d_sb)
#define SB_of(server) ((server)->super_block)

struct vmfs_sb_info {
    /* List of all vmfsfs superblocks */
    struct list_head entry;

    // GPBTODO - most of the 'server' code here should move to the
    //           messagebox

    struct vmfs_mount_data_kernel *mnt;

    /* Connections are counted. Each time a new socket arrives,
     * generation is incremented.
     */
    struct semaphore sem;

    struct vmfs_ops *ops;

    struct super_block *super_block;

    VFS* vfs;
};

static inline int
vmfs_lock_server_interruptible(struct vmfs_sb_info *server)
{
    return down_interruptible(&(server->sem));
}

static inline void
vmfs_lock_server(struct vmfs_sb_info *server)
{
    down(&(server->sem));
}

static inline void
vmfs_unlock_server(struct vmfs_sb_info *server)
{
    up(&(server->sem));
}

#endif /* __KERNEL__ */

#endif

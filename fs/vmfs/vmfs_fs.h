/*
 *  vmfs_fs.h
 *
 *  Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 *  Copyright (C) 2008-2009 ARM Limited
 */

#ifndef _LINUX_VMFS_FS_H
#define _LINUX_VMFS_FS_H

#include "vmfs.h"

/*
 * ioctl commands
 */
#define VMFS_IOC_GETMOUNTUID        _IOR('u', 1, __kernel_old_uid_t)

/* __kernel_uid_t can never change, so we have to use __kernel_uid32_t */
#define VMFS_IOC_GETMOUNTUID32      _IOR('u', 3, __kernel_uid32_t)


#ifdef __KERNEL__
#include "vmfs_fs_i.h"
#include "vmfs_fs_sb.h"

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include "vmfs_mount.h"
#include <linux/jiffies.h>
#include <asm/unaligned.h>

static inline struct vmfs_sb_info *VMFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

static inline struct vmfs_inode_info *VMFS_I(struct inode *inode)
{
    return container_of(inode, struct vmfs_inode_info, vfs_inode);
}

/*
 * This is the time we allow an inode, dentry or dir cache to live. It is bad
 * for performance to have shorter ttl on an inode than on the cache. It can
 * cause refresh on each inode for a dir listing ... one-by-one
 */
#define VMFS_MAX_AGE(server) (((server)->mnt->ttl * HZ) / 1000)

static inline void
vmfs_age_dentry(struct vmfs_sb_info *server, struct dentry *dentry)
{
    dentry->d_time = jiffies - VMFS_MAX_AGE(server);
}

struct vmfs_cache_head {
    time_t      mtime;  /* unused */
    unsigned long   time;   /* cache age */
    unsigned long   end;    /* last valid fpos in cache */
    int     eof;
};

#define VMFS_DIRCACHE_SIZE  ((int)(PAGE_CACHE_SIZE/sizeof(struct dentry *)))
union vmfs_dir_cache {
    struct vmfs_cache_head   head;
    struct dentry           *dentry[VMFS_DIRCACHE_SIZE];
};

#define VMFS_FIRSTCACHE_SIZE    ((int)((VMFS_DIRCACHE_SIZE * \
    sizeof(struct dentry *) - sizeof(struct vmfs_cache_head)) / \
    sizeof(struct dentry *)))

#define VMFS_DIRCACHE_START      (VMFS_DIRCACHE_SIZE - VMFS_FIRSTCACHE_SIZE)

struct vmfs_cache_control {
    struct  vmfs_cache_head     head;
    struct  page            *page;
    union   vmfs_dir_cache      *cache;
    unsigned long           fpos, ofs;
    int             filled, valid, idx;
};

#define VMFS_OPS_NUM_STATIC 5
struct vmfs_ops {
    int (*read)(struct inode *inode, loff_t offset, int count,
            char *data);
    int (*write)(struct inode *inode, loff_t offset, int count, const
             char *data);
    int (*readdir)(struct file *filp, void *dirent, filldir_t filldir,
               struct vmfs_cache_control *ctl);

    int (*getattr)(struct vmfs_sb_info *server, struct dentry *dir,
               struct vmfs_fattr *fattr);
    /* int (*setattr)(...); */      /* setattr is really icky! */

    int (*truncate)(struct inode *inode, loff_t length);
};

static inline int
vmfs_is_open(struct inode *i)
{
    return (VMFS_I(i)->vopen == 1);
}

extern void vmfs_install_ops(struct vmfs_ops *);
#endif /* __KERNEL__ */

#endif /* _LINUX_VMFS_FS_H */

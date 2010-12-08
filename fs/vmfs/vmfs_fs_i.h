/*
 *  vmfs_fs_i.h
 *
 *  Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 */

#ifndef _LINUX_VMFS_FS_I
#define _LINUX_VMFS_FS_I

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/fs.h>

/*
 * vmfs fs inode data (in memory only)
 */
struct vmfs_inode_info {

    unsigned int open;  /* open generation */

    unsigned long oldmtime; /* last time refreshed */
    unsigned long closed;   /* timestamp when closed */
    unsigned openers;   /* number of fileid users */

    // GPB - vfs data - we also use access

    uint32_t vhandle;    /* host side handle */
    uint32_t vaccess;    /* access (VMFS_OPEN_ ) */
    uint32_t vopen;      /* set to 1 when the file is open (why not use openers?) */

    struct inode vfs_inode; /* must be at the end */

};

#endif
#endif

/*
 *  symlink.c
 *
 *  Copyright (C) 2002 by John Newbigin
 *
 *  Please add a note about your changes to vmfs_ in the ChangeLog file.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/net.h>
#include <linux/namei.h>

#include <asm/uaccess.h>
#include <asm/system.h>

#include "vmfsno.h"
#include "vmfs_fs.h"

#include "vmfs_debug.h"
#include "proto.h"

int vmfs_symlink(struct inode *inode, struct dentry *dentry, const char *oldname)
{
    DEBUG1("create symlink %s -> %s/%s\n", oldname, DENTRY_PATH(dentry));

    return vmfs_proc_symlink(server_from_dentry(dentry), dentry, oldname);
}

static void *vmfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
    char *link = __getname();
    DEBUG1("followlink of %s/%s\n", DENTRY_PATH(dentry));

    if (!link) {
        link = ERR_PTR(-ENOMEM);
    } else {
        int len = vmfs_proc_read_link(server_from_dentry(dentry),
                        dentry, link, PATH_MAX - 1);
        if (len < 0) {
            __putname(link);
            link = ERR_PTR(len);
        } else {
            link[len] = 0;
        }
    }
    nd_set_link(nd, link);
    return NULL;
}

static void vmfs_put_link(struct dentry *dentry, struct nameidata *nd, void *p)
{
    char *s = nd_get_link(nd);
    if (!IS_ERR(s))
        __putname(s);
}

const struct inode_operations vmfs_link_inode_operations =
{
    .readlink   = generic_readlink,
    .follow_link    = vmfs_follow_link,
    .put_link   = vmfs_put_link,
};

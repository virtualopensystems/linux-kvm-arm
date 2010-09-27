/*
 *  dir.c
 *
 *  Copyright (C) 1995, 1996 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 *  Copyright (C) 2008-2009 ARM Limited
 *
 *  Please add a note about your changes to vmfs_ in the ChangeLog file.
 */

#include <linux/time.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/smp_lock.h>
#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/sched.h>

#include "vmfs_fs.h"
#include "vmfs_mount.h"
#include "vmfsno.h"

#include "vmfs_debug.h"
#include "proto.h"

static int vmfs_readdir(struct file *, void *, filldir_t);
static int vmfs_dir_open(struct inode *, struct file *);

static struct dentry *vmfs_lookup(struct inode *, struct dentry *, struct nameidata *);
static int vmfs_create(struct inode *, struct dentry *, int, struct nameidata *);
static int vmfs_mkdir(struct inode *, struct dentry *, int);
static int vmfs_rmdir(struct inode *, struct dentry *);
static int vmfs_unlink(struct inode *, struct dentry *);
static int vmfs_rename(struct inode *, struct dentry *,
              struct inode *, struct dentry *);
static int vmfs_make_node(struct inode *,struct dentry *,int,dev_t);
static int vmfs_link(struct dentry *, struct inode *, struct dentry *);

const struct file_operations vmfs_dir_operations =
{
    .read       = generic_read_dir,
    .readdir    = vmfs_readdir,
    .ioctl      = vmfs_ioctl,
    .open       = vmfs_dir_open,
};

const struct inode_operations vmfs_dir_inode_operations =
{
    .create     = vmfs_create,
    .lookup     = vmfs_lookup,
    .unlink     = vmfs_unlink,
    .mkdir      = vmfs_mkdir,
    .rmdir      = vmfs_rmdir,
    .rename     = vmfs_rename,
    .getattr    = vmfs_getattr,
    .setattr    = vmfs_notify_change,
};

const struct inode_operations vmfs_dir_inode_operations_unix =
{
    .create     = vmfs_create,
    .lookup     = vmfs_lookup,
    .unlink     = vmfs_unlink,
    .mkdir      = vmfs_mkdir,
    .rmdir      = vmfs_rmdir,
    .rename     = vmfs_rename,
    .getattr    = vmfs_getattr,
    .setattr    = vmfs_notify_change,
    .symlink    = vmfs_symlink,
    .mknod      = vmfs_make_node,
    .link       = vmfs_link,
};

/*
 * Read a directory, using filldir to fill the dirent memory.
 * vmfs_proc_readdir does the actual reading from the vmfs server.
 *
 * The cache code is almost directly taken from ncpfs
 */
static int 
vmfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
    struct dentry *dentry = filp->f_path.dentry;
    struct inode *dir = dentry->d_inode;
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    union  vmfs_dir_cache *cache = NULL;
    struct vmfs_cache_control ctl;
    struct page *page = NULL;
    int result;

    ctl.page  = NULL;
    ctl.cache = NULL;

    VERBOSE("reading %s/%s, f_pos=%d\n",
        DENTRY_PATH(dentry),  (int) filp->f_pos);

    result = 0;

    lock_kernel();

    switch ((unsigned int) filp->f_pos) {
    case 0:
        if (filldir(dirent, ".", 1, 0, dir->i_ino, DT_DIR) < 0)
            goto out;
        filp->f_pos = 1;
        /* fallthrough */
    case 1:
        if (filldir(dirent, "..", 2, 1, parent_ino(dentry), DT_DIR) < 0)
            goto out;
        filp->f_pos = 2;
    }

    /*
     * Make sure our inode is up-to-date.
     */
    result = vmfs_revalidate_inode(dentry);
    if (result)
        goto out;


    page = grab_cache_page(&dir->i_data, 0);
    if (!page)
        goto read_really;

    ctl.cache = cache = kmap(page);
    ctl.head  = cache->head;

    if (!PageUptodate(page) || !ctl.head.eof) {
        VERBOSE("%s/%s, page uptodate=%d, eof=%d\n",
             DENTRY_PATH(dentry), PageUptodate(page),ctl.head.eof);
        goto init_cache;
    }

    if (filp->f_pos == 2) {
        if (jiffies - ctl.head.time >= VMFS_MAX_AGE(server))
            goto init_cache;

        /*
         * N.B. ncpfs checks mtime of dentry too here, we don't.
         *   1. common vmfs servers do not update mtime on dir changes
         *   2. it requires an extra vmfs request
         *      (revalidate has the same timeout as ctl.head.time)
         *
         * Instead vmfs_ invalidates its own cache on local changes
         * and remote changes are not seen until timeout.
         */
    }

    if (filp->f_pos > ctl.head.end)
        goto finished;

    ctl.fpos = filp->f_pos + (VMFS_DIRCACHE_START - 2);
    ctl.ofs  = ctl.fpos / VMFS_DIRCACHE_SIZE;
    ctl.idx  = ctl.fpos % VMFS_DIRCACHE_SIZE;

    for (;;) {
        if (ctl.ofs != 0) {
            ctl.page = find_lock_page(&dir->i_data, ctl.ofs);
            if (!ctl.page)
                goto invalid_cache;
            ctl.cache = kmap(ctl.page);
            if (!PageUptodate(ctl.page))
                goto invalid_cache;
        }
        while (ctl.idx < VMFS_DIRCACHE_SIZE) {
            struct dentry *dent;
            int res;

            dent = vmfs_dget_fpos(ctl.cache->dentry[ctl.idx],
                         dentry, filp->f_pos);
            if (!dent)
                goto invalid_cache;

            res = filldir(dirent, dent->d_name.name,
                      dent->d_name.len, filp->f_pos,
                      dent->d_inode->i_ino, DT_UNKNOWN);
            dput(dent);
            if (res)
                goto finished;
            filp->f_pos += 1;
            ctl.idx += 1;
            if (filp->f_pos > ctl.head.end)
                goto finished;
        }
        if (ctl.page) {
            kunmap(ctl.page);
            SetPageUptodate(ctl.page);
            unlock_page(ctl.page);
            page_cache_release(ctl.page);
            ctl.page = NULL;
        }
        ctl.idx  = 0;
        ctl.ofs += 1;
    }
invalid_cache:
    if (ctl.page) {
        kunmap(ctl.page);
        unlock_page(ctl.page);
        page_cache_release(ctl.page);
        ctl.page = NULL;
    }
    ctl.cache = cache;
init_cache:
    vmfs_invalidate_dircache_entries(dentry);
    ctl.head.time = jiffies;
    ctl.head.eof = 0;
    ctl.fpos = 2;
    ctl.ofs = 0;
    ctl.idx = VMFS_DIRCACHE_START;
    ctl.filled = 0;
    ctl.valid  = 1;
read_really:
    result = server->ops->readdir(filp, dirent, filldir, &ctl);
    if (result == -ERESTARTSYS && page)
        ClearPageUptodate(page);
    if (ctl.idx == -1)
        goto invalid_cache; /* retry */
    ctl.head.end = ctl.fpos - 1;
    ctl.head.eof = ctl.valid;
finished:
    if (page) {
        cache->head = ctl.head;
        kunmap(page);
        if (result != -ERESTARTSYS)
            SetPageUptodate(page);
        unlock_page(page);
        page_cache_release(page);
    }
    if (ctl.page) {
        kunmap(ctl.page);
        SetPageUptodate(ctl.page);
        unlock_page(ctl.page);
        page_cache_release(ctl.page);
    }
out:
    unlock_kernel();
    return result;
}

static int
vmfs_dir_open(struct inode *dir, struct file *file)
{
    struct dentry *dentry = file->f_path.dentry;
//  struct vmfs_sb_info *server;
    int error = 0;

    VERBOSE("(%s/%s)\n", dentry->d_parent->d_name.name,
        file->f_path.dentry->d_name.name);

    lock_kernel();

#if 0
    /*
     * Directory timestamps in the core protocol aren't updated
     * when a file is added, so we give them a very short TTL.
     */

    // GPBTODO - not sure if this is necessary - check behaviour on
    //           linux/windows hosts

    server = server_from_dentry(dentry);

    if (server->opt.protocol < VMFS_PROTOCOL_LANMAN2) {
        unsigned long age = jiffies - VMFS_I(dir)->oldmtime;
        if (age > 2*HZ)
            vmfs_invalid_dir_cache(dir);
    }
#endif

    if (!IS_ROOT(dentry))
        error = vmfs_revalidate_inode(dentry);
    
    unlock_kernel();
    return error;
}

/*
 * Dentry operations routines
 */
static int vmfs_lookup_validate(struct dentry *, struct nameidata *);
//static int vmfs_hash_dentry(struct dentry *, struct qstr *);
//static int vmfs_compare_dentry(struct dentry *, struct qstr *, struct qstr *);
static int vmfs_delete_dentry(struct dentry *);

#if 0 // GPBTODO for case insensitivity

static struct dentry_operations vmfs__dentry_operations =
{
    .d_revalidate   = vmfs_lookup_validate,
    .d_hash         = vmfs_hash_dentry,
    .d_compare      = vmfs_compare_dentry,
    .d_delete       = vmfs_delete_dentry,
};

#endif

static struct dentry_operations vmfs__dentry_operations_case =
{
    .d_revalidate   = vmfs_lookup_validate,
    .d_delete       = vmfs_delete_dentry,
};


/*
 * This is the callback when the dcache has a lookup hit.
 */
static int
vmfs_lookup_validate(struct dentry * dentry, struct nameidata *nd)
{
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    struct inode * inode = dentry->d_inode;
    unsigned long age = jiffies - dentry->d_time;
    int valid;

    /*
     * The default validation is based on dentry age:
     * we believe in dentries for a few seconds.  (But each
     * successful server lookup renews the timestamp.)
     */
    valid = (age <= VMFS_MAX_AGE(server));
#ifdef VMFSFS_DEBUG_VERBOSE
    if (!valid)
        VERBOSE("%s/%s not valid, age=%lu\n", 
            DENTRY_PATH(dentry), age);
#endif

    if (inode) {
        lock_kernel();
        if (is_bad_inode(inode)) {
            PARANOIA("%s/%s has dud inode\n", DENTRY_PATH(dentry));
            valid = 0;
        } else if (!valid)
            valid = (vmfs_revalidate_inode(dentry) == 0);
        unlock_kernel();
    } else {
        /*
         * What should we do for negative dentries?
         */
    }
    return valid;
}

#if 0 // GPBTODO for case insensitivity

static int 
vmfs_hash_dentry(struct dentry *dir, struct qstr *this)
{
    unsigned long hash;
    int i;

    hash = init_name_hash();
    for (i=0; i < this->len ; i++)
        hash = partial_name_hash(tolower(this->name[i]), hash);
    this->hash = end_name_hash(hash);
  
    return 0;
}

static int
vmfs_compare_dentry(struct dentry *dir, struct qstr *a, struct qstr *b)
{
    int i, result = 1;

    if (a->len != b->len)
        goto out;
    for (i=0; i < a->len; i++) {
        if (tolower(a->name[i]) != tolower(b->name[i]))
            goto out;
    }
    result = 0;
out:
    return result;
}

#endif // GPB

/*
 * This is the callback from dput() when d_count is going to 0.
 * We use this to unhash dentries with bad inodes.
 */
static int
vmfs_delete_dentry(struct dentry * dentry)
{
    if (dentry->d_inode) {
        if (is_bad_inode(dentry->d_inode)) {
            PARANOIA("bad inode, unhashing %s/%s\n",
                 DENTRY_PATH(dentry));
            return 1;
        }
    } else {
        /* N.B. Unhash negative dentries? */
    }
    return 0;
}

/*
 * Initialize a new dentry
 */
void
vmfs_new_dentry(struct dentry *dentry)
{
    dentry->d_op = &vmfs__dentry_operations_case;

#if 0  // GPB
    struct vmfs_sb_info *server = server_from_dentry(dentry);


    if (server->mnt->flags & VMFS_MOUNT_CASE)
        dentry->d_op = &vmfs__dentry_operations_case;
    else
        dentry->d_op = &vmfs__dentry_operations;
    dentry->d_time = jiffies;
#endif // GPB
}


/*
 * Whenever a lookup succeeds, we know the parent directories
 * are all valid, so we want to update the dentry timestamps.
 * N.B. Move this to dcache?
 */
void
vmfs_renew_times(struct dentry * dentry)
{
    dget(dentry);
    spin_lock(&dentry->d_lock);
    for (;;) {
        struct dentry *parent;

        dentry->d_time = jiffies;
        if (IS_ROOT(dentry))
            break;
        parent = dentry->d_parent;
        dget(parent);
        spin_unlock(&dentry->d_lock);
        dput(dentry);
        dentry = parent;
        spin_lock(&dentry->d_lock);
    }
    spin_unlock(&dentry->d_lock);
    dput(dentry);
}

static struct dentry *
vmfs_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
    struct vmfs_fattr finfo;
    struct inode *inode;
    int error;
    struct vmfs_sb_info *server;

    VERBOSE("%s\n", dentry->d_name.name);

    error = -ENAMETOOLONG;
    if (dentry->d_name.len > VMFS_MAXNAMELEN)
        goto out;

    /* Do not allow lookup of names with backslashes in */
    error = -EINVAL;
#if 0
    if (memchr(dentry->d_name.name, '\\', dentry->d_name.len))
        goto out;
#endif

    lock_kernel();
    error = vmfs_proc_getattr(dentry, &finfo);
#ifdef VMFSFS_PARANOIA
    if (error && error != -ENOENT)
        PARANOIA("find %s/%s failed, error=%d\n",
             DENTRY_PATH(dentry), error);
#endif

    inode = NULL;
    if (error == -ENOENT)
        goto add_entry;
    if (!error) {
        error = -EACCES;
        finfo.f_ino = iunique(dentry->d_sb, 2);
        inode = vmfs_iget(dir->i_sb, &finfo);
        if (inode) {
    add_entry:
            server = server_from_dentry(dentry);
            dentry->d_op = &vmfs__dentry_operations_case;
#if 0 // GPB
            if (server->mnt->flags & VMFS_MOUNT_CASE)
                dentry->d_op = &vmfs__dentry_operations_case;
            else
                dentry->d_op = &vmfs__dentry_operations;
#endif // GPB
            d_add(dentry, inode);
            vmfs_renew_times(dentry);
            error = 0;
        }
    }
    unlock_kernel();
out:
    return ERR_PTR(error);
}

/*
 * This code is common to all routines creating a new inode.
 */
static int
vmfs_instantiate(struct dentry *dentry, int32_t vhandle, int have_id)
{
    struct inode *inode;
    int error;
    struct vmfs_fattr fattr;

    VERBOSE("file %s/%s, fileid=%u\n", DENTRY_PATH(dentry), vhandle);

    error = vmfs_proc_getattr(dentry, &fattr);
    if (error)
        goto out_close;

    vmfs_renew_times(dentry);
    fattr.f_ino = iunique(dentry->d_sb, 2);
    inode = vmfs_iget(dentry->d_sb, &fattr);
    if (!inode)
        goto out_no_inode;

    if (have_id) {
        // this is really only for create, where there is a catch-22 between creating the file
        // and inode
        struct vmfs_inode_info *ei = VMFS_I(inode);
        ei->vhandle = vhandle;
        ei->vopen = 1;
        ei->vaccess = VFS_OPEN_RDWR; // GPB is this right?
    }
    d_instantiate(dentry, inode);
out:
    return error;

out_no_inode:
    error = -EACCES;
out_close:
    if (have_id) {
        PARANOIA("%s/%s failed, error=%d, closing %u\n",
             DENTRY_PATH(dentry), error, vhandle);
        vmfs_close_fileid(dentry, vhandle);
    }
    goto out;
}

/* N.B. How should the mode argument be used? */
static int
vmfs_create(struct inode *dir, struct dentry *dentry, int mode,
        struct nameidata *nd)
{
//  struct vmfs_sb_info *server = server_from_dentry(dentry);
    int32_t fileid;
    int error;
//  struct iattr attr;

    VERBOSE("creating %s/%s, mode=%d\n", DENTRY_PATH(dentry), mode);

    lock_kernel();

    vmfs_invalid_dir_cache(dir);
    error = vmfs_proc_create(dentry, mode, &fileid);
    if (!error) {
#if 0 // GPB todo - we will need a second call for this
        if (server->opt.capabilities & VMFS_CAP_UNIX) {
            /* Set attributes for new file */
            attr.ia_valid = ATTR_MODE;
            attr.ia_mode = mode;
            error = vmfs_proc_setattr_unix(dentry, &attr, 0, 0);
        }
#endif
        error = vmfs_instantiate(dentry, fileid, 1);
    } else {
        PARANOIA("%s/%s failed, error=%d\n",
             DENTRY_PATH(dentry), error);
    }
    unlock_kernel();
    return error;
}

/* N.B. How should the mode argument be used? */
static int
vmfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
    int error;

    VERBOSE("\n");

    lock_kernel();
    vmfs_invalid_dir_cache(dir);
    error = vmfs_proc_mkdir(dentry);
    if (!error) {
#if 0 // GPBTODO
        struct vmfs_sb_info *server = server_from_dentry(dentry);
        if (server->opt.capabilities & VMFS_CAP_UNIX) {
            struct iattr attr;
            /* Set attributes for new directory */
            attr.ia_valid = ATTR_MODE;
            attr.ia_mode = mode;
            error = vmfs_proc_setattr_unix(dentry, &attr, 0, 0);
        }
#endif
        error = vmfs_instantiate(dentry, 0, 0);
    }
    unlock_kernel();
    return error;
}

static int
vmfs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct inode *inode = dentry->d_inode;
    int error;

    VERBOSE("\n");
    /*
     * Close the directory if it's open.
     */
    lock_kernel();
    vmfs_close(inode);

    /*
     * Check that nobody else is using the directory..
     */
    error = -EBUSY;
    if (!d_unhashed(dentry))
        goto out;

    vmfs_invalid_dir_cache(dir);
    error = vmfs_proc_rmdir(dentry);

out:
    unlock_kernel();
    return error;
}

static int
vmfs_unlink(struct inode *dir, struct dentry *dentry)
{
    int error;

    /*
     * Close the file if it's open.
     */
    lock_kernel();
    vmfs_close(dentry->d_inode);

    vmfs_invalid_dir_cache(dir);
    error = vmfs_proc_unlink(dentry);
    if (!error)
        vmfs_renew_times(dentry);
    unlock_kernel();
    return error;
}

static int
vmfs_rename(struct inode *old_dir, struct dentry *old_dentry,
       struct inode *new_dir, struct dentry *new_dentry)
{
    int error;

    VERBOSE("\n");

    /*
     * Close any open files, and check whether to delete the
     * target before attempting the rename.
     */
    lock_kernel();
    if (old_dentry->d_inode)
        vmfs_close(old_dentry->d_inode);
    if (new_dentry->d_inode) {
        vmfs_close(new_dentry->d_inode);
        error = vmfs_proc_unlink(new_dentry);
        if (error) {
            VERBOSE("unlink %s/%s, error=%d\n",
                DENTRY_PATH(new_dentry), error);
            goto out;
        }
        /* FIXME */
        d_delete(new_dentry);
    }

    vmfs_invalid_dir_cache(old_dir);
    vmfs_invalid_dir_cache(new_dir);
    error = vmfs_proc_mv(old_dentry, new_dentry);
    if (!error) {
        vmfs_renew_times(old_dentry);
        vmfs_renew_times(new_dentry);
    }
out:
    unlock_kernel();
    return error;
}

/*
 * FIXME: samba servers won't let you create device nodes unless uid/gid
 * matches the connection credentials (and we don't know which those are ...)
 */
static int
vmfs_make_node(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
    return -EINVAL;

#if 0 // GPBTODO
    int error;
    struct iattr attr;

    attr.ia_valid = ATTR_MODE | ATTR_UID | ATTR_GID;
    attr.ia_mode = mode;
    attr.ia_uid = current->euid;
    attr.ia_gid = current->egid;

    if (!new_valid_dev(dev))
        return -EINVAL;

    vmfs_invalid_dir_cache(dir);
    error = vmfs_proc_setattr_unix(dentry, &attr, MAJOR(dev), MINOR(dev));
    if (!error) {
        error = vmfs_instantiate(dentry, 0, 0);
    }
    return error;
#endif
}

/*
 * dentry = existing file
 * new_dentry = new file
 */
static int
vmfs_link(struct dentry *dentry, struct inode *dir, struct dentry *new_dentry)
{
    int error;

    DEBUG1("vmfs_link old=%s/%s new=%s/%s\n",
           DENTRY_PATH(dentry), DENTRY_PATH(new_dentry));
    vmfs_invalid_dir_cache(dir);
    error = vmfs_proc_link(server_from_dentry(dentry), dentry, new_dentry);
    if (!error) {
        vmfs_renew_times(dentry);
        error = vmfs_instantiate(new_dentry, 0, 0);
    }
    return error;
}

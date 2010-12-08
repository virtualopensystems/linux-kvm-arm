/*
 *  file.c
 *
 *  Copyright (C) 1995, 1996, 1997 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 *  Please add a note about your changes to vmfs_ in the ChangeLog file.
 */

#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
#include <linux/net.h>
#include <linux/aio.h>

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/version.h>

#include "vmfsno.h"
#include "vmfs_fs.h"

#include "vmfs_debug.h"
#include "proto.h"

static int
vmfs_fsync(struct file *file, struct dentry * dentry, int datasync)
{
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    int result;

    VERBOSE("sync file %s/%s\n", DENTRY_PATH(dentry));

    /*
     * The VFS will writepage() all dirty pages for us, but we
     * should send a VMFSflush to the server, letting it know that
     * we want things synchronized with actual storage.
     *
     * Note: this function requires all pages to have been written already
     *       (should be ok with writepage_sync)
     */
    lock_kernel();
    result = vmfs_proc_flush(server, VMFS_I(dentry->d_inode)->vhandle);
    unlock_kernel();

    return result;
}

/*
 * Read a page synchronously.
 */
static int
vmfs_readpage_sync(struct dentry *dentry, struct page *page)
{
    char *buffer = kmap(page);
    loff_t offset = (loff_t)page->index << PAGE_CACHE_SHIFT;
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    int count = PAGE_SIZE;
    unsigned int rsize = count;
    int result;

    VERBOSE("file %s/%s, count=%d@%Ld, rsize=%d\n",
        DENTRY_PATH(dentry), count, offset, rsize);

    result = vmfs_open(dentry, 0, VMFS_O_RDONLY);
    if (result < 0)
        goto io_error;

    do {
        if (count < rsize)
            rsize = count;

        result = server->ops->read(dentry->d_inode,offset,rsize,buffer);
        if (result < 0)
            goto io_error;

        count -= result;
        offset += result;
        buffer += result;
        dentry->d_inode->i_atime =
            current_fs_time(dentry->d_inode->i_sb);
        if (result < rsize)
            break;
    } while (count);

    memset(buffer, 0, count);
    flush_dcache_page(page);
    SetPageUptodate(page);
    result = 0;

io_error:
    kunmap(page);
    unlock_page(page);
    return result;
}

/*
 * We are called with the page locked and we unlock it when done.
 */
static int
vmfs_readpage(struct file *file, struct page *page)
{
    int     error;
    struct dentry  *dentry = file->f_path.dentry;

    page_cache_get(page);
    error = vmfs_readpage_sync(dentry, page);
    page_cache_release(page);
    return error;
}

/*
 * Write a page synchronously.
 * Offset is the data offset within the page.
 */
static int
vmfs_writepage_sync(struct inode *inode, struct page *page,
           unsigned long pageoffset, unsigned int count)
{
    loff_t offset;
    char *buffer = kmap(page) + pageoffset;
    struct vmfs_sb_info *server = server_from_inode(inode);
    unsigned int wsize = count;
    int ret = 0;

    offset = ((loff_t)page->index << PAGE_CACHE_SHIFT) + pageoffset;
    VERBOSE("file ino=%ld, handle=%d, count=%d@%Ld, wsize=%d\n",
        inode->i_ino, VMFS_I(inode)->vhandle, count, offset, wsize);

    do {
        int write_ret;

        if (count < wsize)
            wsize = count;

        write_ret = server->ops->write(inode, offset, wsize, buffer);
        if (write_ret < 0) {
            PARANOIA("failed write, wsize=%d, write_ret=%d\n",
                 wsize, write_ret);
            ret = write_ret;
            break;
        }

        /* N.B. what if result < wsize?? */
#ifdef VMFSFS_PARANOIA
        if (write_ret < wsize)
            PARANOIA("short write, wsize=%d, write_ret=%d\n",
                 wsize, write_ret);
#endif
        buffer += wsize;
        offset += wsize;
        count -= wsize;
        /*
         * Update the inode now rather than waiting for a refresh.
         */

        inode->i_mtime = inode->i_atime = current_fs_time(inode->i_sb);
//      VMFS_I(inode)->flags |= VMFS_F_LOCALWRITE;
        if (offset > inode->i_size)
            inode->i_size = offset;
    } while (count);

    kunmap(page);
    return ret;
}

/*
 * Write a page to the server. This will be used for NFS swapping only
 * (for now), and we currently do this synchronously only.
 *
 * We are called with the page locked and we unlock it when done.
 */
static int
vmfs_writepage(struct page *page, struct writeback_control *wbc)
{
    struct address_space *mapping = page->mapping;
    struct inode *inode;
    unsigned long end_index;
    unsigned offset = PAGE_CACHE_SIZE;
    int err;

    DEBUG1("\n");

    BUG_ON(!mapping);
    inode = mapping->host;
    BUG_ON(!inode);

    end_index = inode->i_size >> PAGE_CACHE_SHIFT;

    /* easy case */
    if (page->index < end_index)
        goto do_it;
    /* things got complicated... */
    offset = inode->i_size & (PAGE_CACHE_SIZE-1);
    /* OK, are we completely out? */
    if (page->index >= end_index+1 || !offset)
        return 0; /* truncated - don't care */
do_it:
    page_cache_get(page);
    err = vmfs_writepage_sync(inode, page, 0, offset);
    SetPageUptodate(page);
    unlock_page(page);
    page_cache_release(page);
    return err;
}

static int
vmfs_updatepage(struct file *file, struct page *page, unsigned long offset,
           unsigned int count)
{
    struct dentry *dentry = file->f_path.dentry;

    DEBUG1("(%s/%s %d@%lld)\n", DENTRY_PATH(dentry), count,
        ((unsigned long long)page->index << PAGE_CACHE_SHIFT) + offset);

    return vmfs_writepage_sync(dentry->d_inode, page, offset, count);
}

static ssize_t
vmfs_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
            unsigned long nr_segs, loff_t pos)
{
    struct file * file = iocb->ki_filp;
    struct dentry * dentry = file->f_path.dentry;
    ssize_t status;

    VERBOSE("file %s/%s, count=%lu@%lu\n", DENTRY_PATH(dentry),
        (unsigned long) iocb->ki_left, (unsigned long) pos);

    status = vmfs_revalidate_inode(dentry);
    if (status) {
        PARANOIA("%s/%s validation failed, error=%Zd\n",
             DENTRY_PATH(dentry), status);
        goto out;
    }

    VERBOSE("before read, size=%ld, flags=%x, atime=%ld\n",
        (long)dentry->d_inode->i_size,
        dentry->d_inode->i_flags, dentry->d_inode->i_atime.tv_sec);

    status = generic_file_aio_read(iocb, iov, nr_segs, pos);
out:
    return status;
}

static int
vmfs_file_mmap(struct file * file, struct vm_area_struct * vma)
{
    struct dentry * dentry = file->f_path.dentry;
    int status;

    VERBOSE("file %s/%s, address %lu - %lu\n",
        DENTRY_PATH(dentry), vma->vm_start, vma->vm_end);

    status = vmfs_revalidate_inode(dentry);
    if (status) {
        PARANOIA("%s/%s validation failed, error=%d\n",
             DENTRY_PATH(dentry), status);
        goto out;
    }
    status = generic_file_mmap(file, vma);
out:
    return status;
}

static ssize_t
vmfs_file_splice_read(struct file *file, loff_t *ppos,
             struct pipe_inode_info *pipe, size_t count,
             unsigned int flags)
{
    struct dentry *dentry = file->f_path.dentry;
    ssize_t status;

    VERBOSE("file %s/%s, pos=%Ld, count=%u\n",
        DENTRY_PATH(dentry), *ppos, count);

    status = vmfs_revalidate_inode(dentry);
    if (status) {
        PARANOIA("%s/%s validation failed, error=%Zd\n",
             DENTRY_PATH(dentry), status);
        goto out;
    }
    status = generic_file_splice_read(file, ppos, pipe, count, flags);
out:
    return status;
}

/*
 * This does the "real" work of the write. The generic routine has
 * allocated the page, locked it, done all the page alignment stuff
 * calculations etc. Now we should just copy the data from user
 * space and write it back to the real medium..
 *
 * If the writer ends up delaying the write, the writer needs to
 * increment the page use counts until he is done with the page.
 */
static int vmfs_write_begin(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned flags,
            struct page **pagep, void **fsdata)
{
    pgoff_t index = pos >> PAGE_CACHE_SHIFT;
    *pagep = grab_cache_page(mapping, index);
    if (!*pagep)
        return -ENOMEM;
    return 0;
}

static int vmfs_write_end(struct file *file, struct address_space *mapping,
            loff_t pos, unsigned len, unsigned copied,
            struct page *page, void *fsdata)
{
    int status;
    unsigned offset = pos & (PAGE_CACHE_SIZE - 1);

    lock_kernel();
    status = vmfs_updatepage(file, page, offset, copied);
    unlock_kernel();

    if (!status) {
        if (!PageUptodate(page) && copied == PAGE_CACHE_SIZE)
            SetPageUptodate(page);
        status = copied;
    }

    unlock_page(page);
    page_cache_release(page);

    return status;
}

const struct address_space_operations vmfs_file_aops = {
    .readpage = vmfs_readpage,
    .writepage = vmfs_writepage,
    .write_begin = vmfs_write_begin,
    .write_end = vmfs_write_end,
};

/* 
 * Write to a file (through the page cache).
 */
static ssize_t
vmfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
                   unsigned long nr_segs, loff_t pos)
{
    struct file * file = iocb->ki_filp;
    struct dentry * dentry = file->f_path.dentry;
    ssize_t result;

    VERBOSE("file %s/%s, count=%lu@%lu\n",
        DENTRY_PATH(dentry),
        (unsigned long) iocb->ki_left, (unsigned long) pos);

    result = vmfs_revalidate_inode(dentry);
    if (result) {
        PARANOIA("%s/%s validation failed, error=%Zd\n",
             DENTRY_PATH(dentry), result);
        goto out;
    }

    lock_kernel();
    result = vmfs_open(dentry, 0, VMFS_O_WRONLY);
    unlock_kernel();

    DEBUG1("1\n");

    if (result)
        goto out;

    if (iocb->ki_left > 0) {
        DEBUG1("1\n");

        result = generic_file_aio_write(iocb, iov, nr_segs, pos);
        VERBOSE("pos=%ld, size=%ld, mtime=%ld, atime=%ld\n",
            (long) file->f_pos, (long) dentry->d_inode->i_size,
            dentry->d_inode->i_mtime.tv_sec,
            dentry->d_inode->i_atime.tv_sec);

        DEBUG1("2\n");
    }
out:
    DEBUG1("return\n");
    return result;
}

static int
vmfs_file_open(struct inode *inode, struct file * file)
{
    int result;
    struct dentry *dentry = file->f_path.dentry;
    int vmfs_mode = (file->f_mode & O_ACCMODE) - 1;
    int vmfs_flags = file->f_flags;

    VERBOSE("\n");

    lock_kernel();
    result = vmfs_open(dentry, vmfs_flags, vmfs_mode);
    if (result)
        goto out;

    DEBUG1("inode=%p, ei=%p\n", inode, VMFS_I(inode));

    VMFS_I(inode)->openers++;
out:
    unlock_kernel();
    DEBUG1("return\n");

    return result;
}

static int
vmfs_file_release(struct inode *inode, struct file * file)
{
    lock_kernel();
    if (!--VMFS_I(inode)->openers) {
        /* We must flush any dirty pages now as we won't be able to
           write anything after close. mmap can trigger this.
           "openers" should perhaps include mmap'ers ... */
        filemap_write_and_wait(inode->i_mapping);
        vmfs_close(inode);
    }
    unlock_kernel();
    return 0;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
static loff_t 
vmfs_remote_llseek(struct file *file, loff_t offset, int origin)
{
    loff_t ret;
    lock_kernel();
    ret = generic_file_llseek_unlocked(file, offset, origin);
    unlock_kernel();
    return ret;
}
#endif
/*
 * Check whether the required access is compatible with
 * an inode's permission. VMFS doesn't recognize superuser
 * privileges, so we need our own check for this.
 */
static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
vmfs_file_permission(struct inode *inode, int mask)
#else
vmfs_file_permission(struct inode *inode, int mask, struct nameidata *nd)
#endif
{
    int mode = inode->i_mode;
    int error = 0;

    VERBOSE("mode=%x, mask=%x\n", mode, mask);

    /* Look at user permissions */
    mode >>= 6;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
    if ((mask & ~mode) & (MAY_READ | MAY_WRITE | MAY_EXEC))
#else
    if ((mode & 7 & mask) != mask)
#endif
        error = -EACCES;
    return error;
}

const struct file_operations vmfs_file_operations =
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
    .llseek     = vmfs_remote_llseek,
#else
    .llseek     = remote_llseek,
#endif
    .read       = do_sync_read,
    .aio_read   = vmfs_file_aio_read,
    .write      = do_sync_write,
    .aio_write  = vmfs_file_aio_write,
    .ioctl      = vmfs_ioctl,
    .mmap       = vmfs_file_mmap,
    .open       = vmfs_file_open,
    .release    = vmfs_file_release,
    .fsync      = vmfs_fsync,
    .splice_read    = vmfs_file_splice_read,
};

const struct inode_operations vmfs_file_inode_operations =
{
    .permission = vmfs_file_permission,
    .getattr    = vmfs_getattr,
    .setattr    = vmfs_notify_change,
};

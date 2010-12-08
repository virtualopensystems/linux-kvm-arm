/*
 *  proc.c
 *
 *  Copyright (C) 1995, 1996 by Paal-Kr. Engstad and Volker Lendecke
 *  Copyright (C) 1997 by Volker Lendecke
 *
 *  Please add a note about your changes to vmfs_ in the ChangeLog file.
 *
 *  Copyright (C) 2008-2009 by ARM Limited
 */

#include <linux/types.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/dcache.h>
#include <linux/dirent.h>
#include <linux/smp_lock.h>
#include <linux/vfs.h>
#include "vmfs_fs.h"
#include "vmfsno.h"
#include "vmfs_mount.h"

#include <asm/string.h>
#include <asm/div64.h>

#include "vmfs_debug.h"
#include "proto.h"
#include "vfs.h"


/* Features. Undefine if they cause problems, this should perhaps be a
   config option. */
#define VMFSFS_POSIX_UNLINK 1

#define VMFS_ST_BLKSIZE     (PAGE_SIZE)
#define VMFS_ST_BLKSHIFT    (PAGE_SHIFT)

// dont seem to have ulldiv. This is good enough for  / 1000
static uint64_t divmod64(uint64_t dividend, uint32_t divisor, uint32_t* remainder)
{
    uint64_t quotient=0;
    uint32_t pquot, prem = 0;
    uint32_t i;

    // divide in 4 32x16->32 bit parts. As most ARMs don't have / anyway
    // we should probably do this bit by bit
    for (i=0; i<4; ++i)
    {
        uint32_t part = (prem<<16) | (dividend>>48);

        pquot = part / divisor;
        prem  = part % divisor;

        dividend = dividend<<16;
        quotient = (quotient<<16) | pquot;
    }

    if (remainder)
        *remainder = prem;

    return quotient;
}

#if 0
static void
str_upper(char *name, int len)
{
    while (len--)
    {
        if (*name >= 'a' && *name <= 'z')
            *name -= ('a' - 'A');
        name++;
    }
}

static void
str_lower(char *name, int len)
{
    while (len--)
    {
        if (*name >= 'A' && *name <= 'Z')
            *name += ('a' - 'A');
        name++;
    }
}
#endif

#define VMFS_ATTR_MAX (PATH_MAX+256)

// GPB not exactly fast but OK for now
struct vmfs_ws
{
    char path[PATH_MAX];
    char path2[PATH_MAX];
    uint8_t attr[VMFS_ATTR_MAX];
};

static struct vmfs_ws* vmfs_get_ws(struct vmfs_sb_info* server)
{
    return kmalloc(sizeof(struct vmfs_ws), GFP_NOFS);
}

static void vmfs_put_ws(struct vmfs_ws* ws)
{
    kfree(ws);
}

/*****************************************************************************/
/*                                                                           */
/*  Encoding/Decoding section                                                */
/*                                                                           */
/*****************************************************************************/

/*
 * vmfs_build_path: build the path to entry and name storing it in buf.
 * The path returned will have the trailing '\0'.
 */
static int vmfs_build_path(struct vmfs_sb_info *server, unsigned char *buf,
              int buflen,
              struct dentry *entry, struct qstr *name)
{
    unsigned char *path = buf;
    int maxlen = buflen;
    int len;

    VERBOSE("for dir %s\n", entry->d_name.name);

    if (maxlen > VMFS_MAXPATHLEN + 1)
        maxlen = VMFS_MAXPATHLEN + 1;

    if (maxlen < 1)
        return -ENAMETOOLONG;

    path = buf+buflen;
    *--path = '\0';
    --maxlen;

    if (name)
    {
        len = name->len+1;

        if (len > maxlen)
            return -ENAMETOOLONG;

        path -= len;
        maxlen -= len;
        memcpy(path, name->name, len);
        
        *--path = '/';
        --maxlen;
    }

    if (entry != NULL)
    {
        dget(entry);
        spin_lock(&entry->d_lock);
        do {
            struct dentry *parent;

            len = entry->d_name.len;

            if (len+1 > maxlen) // +1 for separator
            {
                spin_unlock(&entry->d_lock);
                dput(entry);
                return -ENAMETOOLONG;
            }

            path -= len;
            maxlen -= len;
            memcpy(path, entry->d_name.name, len);

            // TODO separator should be configurable

            *--path = '/';
            --maxlen;

            parent = entry->d_parent;
            dget(parent);
            spin_unlock(&entry->d_lock);
            dput(entry);
            entry = parent;
            spin_lock(&entry->d_lock);
        } while (!IS_ROOT(entry)); 
        spin_unlock(&entry->d_lock);
        dput(entry);
    }

    // at the root we need to put on the root prefix, which is held in the server
    // TODO - for now we assume it is called 'A'

    if (maxlen < 2)
        return -ENAMETOOLONG;

    maxlen -= 2;
    *--path = ':';
    *--path = 'A';

    len = buflen-maxlen;
    memmove(buf, path, len);

    return len;
}

static int vmfs_encode_path(struct vmfs_sb_info *server, char *buf, int maxlen,
               struct dentry *dir, struct qstr *name)
{
    int result;

    result = vmfs_build_path(server, buf, maxlen, dir, name);
    if (result < 0)
        goto out;
#if 0 // GPB
    if (server->opt.protocol <= VMFS_PROTOCOL_COREPLUS)
        str_upper(buf, result);
#endif

out:
    FNEXIT("%d", result);

    return result;
}

#if 0 // GPB

// GPB VMFS time will be some number of ms (in 64bit) since some epoch

/* The following are taken directly from msdos-fs */

/* Linear day numbers of the respective 1sts in non-leap years. */

static int day_n[] =
{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0, 0};
          /* JanFebMarApr May Jun Jul Aug Sep Oct Nov Dec */


static time_t
utc2local(struct vmfs_sb_info *server, time_t time)
{
//  return time - server->opt.serverzone*60;
    return 0;
}

static time_t
local2utc(struct vmfs_sb_info *server, time_t time)
{
//  return time + server->opt.serverzone*60;
    return 0;
}

/* Convert a MS-DOS time/date pair to a UNIX date (seconds since 1 1 70). */

static time_t
date_dos2unix(struct vmfs_sb_info *server, __u16 date, __u16 time)
{
    int month, year;
    time_t secs;

    /* first subtract and mask after that... Otherwise, if
       date == 0, bad things happen */
    month = ((date >> 5) - 1) & 15;
    year = date >> 9;
    secs = (time & 31) * 2 + 60 * ((time >> 5) & 63) + (time >> 11) * 3600 + 86400 *
        ((date & 31) - 1 + day_n[month] + (year / 4) + year * 365 - ((year & 3) == 0 &&
                           month < 2 ? 1 : 0) + 3653);
    /* days since 1.1.70 plus 80's leap day */
    return local2utc(server, secs);
}


/* Convert linear UNIX date to a MS-DOS time/date pair. */

static void
date_unix2dos(struct vmfs_sb_info *server,
          int unix_date, __u16 *date, __u16 *time)
{
    int day, year, nl_day, month;

    unix_date = utc2local(server, unix_date);
    if (unix_date < 315532800)
        unix_date = 315532800;

    *time = (unix_date % 60) / 2 +
        (((unix_date / 60) % 60) << 5) +
        (((unix_date / 3600) % 24) << 11);

    day = unix_date / 86400 - 3652;
    year = day / 365;
    if ((year + 3) / 4 + 365 * year > day)
        year--;
    day -= (year + 3) / 4 + 365 * year;
    if (day == 59 && !(year & 3)) {
        nl_day = day;
        month = 2;
    } else {
        nl_day = (year & 3) || day <= 59 ? day : day - 1;
        for (month = 0; month < 12; month++)
            if (day_n[month] > nl_day)
                break;
    }
    *date = nl_day - day_n[month - 1] + 1 + (month << 5) + (year << 9);
}

/* The following are taken from fs/ntfs/util.c */

#define NTFS_TIME_OFFSET ((u64)(369*365 + 89) * 24 * 3600 * 10000000)

/*
 * Convert the NT UTC (based 1601-01-01, in hundred nanosecond units)
 * into Unix UTC (based 1970-01-01, in seconds).
 */
static struct timespec
vmfs_ntutc2unixutc(u64 ntutc)
{
    struct timespec ts;
    /* FIXME: what about the timezone difference? */
    /* Subtract the NTFS time offset, then convert to 1s intervals. */
    u64 t = ntutc - NTFS_TIME_OFFSET;
    ts.tv_nsec = do_div(t, 10000000) * 100;
    ts.tv_sec = t; 
    return ts;
}

/* Convert the Unix UTC into NT time */
static u64
vmfs_unixutc2ntutc(struct timespec ts)
{
    /* Note: timezone conversion is probably wrong. */
    /* return ((u64)utc2local(server, t)) * 10000000 + NTFS_TIME_OFFSET; */
    return ((u64)ts.tv_sec) * 10000000 + ts.tv_nsec/100 + NTFS_TIME_OFFSET;
}

#define MAX_FILE_MODE   6
static mode_t file_mode[] = {
    S_IFREG, S_IFDIR, S_IFLNK, S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK
};

static int vmfs_filetype_to_mode(u32 filetype)
{
    if (filetype > MAX_FILE_MODE) {
        PARANOIA("Filetype out of range: %d\n", filetype);
        return S_IFREG;
    }
    return file_mode[filetype];
}

static u32 vmfs_filetype_from_mode(int mode)
{
    if (S_ISREG(mode))
        return UNIX_TYPE_FILE;
    if (S_ISDIR(mode))
        return UNIX_TYPE_DIR;
    if (S_ISLNK(mode))
        return UNIX_TYPE_SYMLINK;
    if (S_ISCHR(mode))
        return UNIX_TYPE_CHARDEV;
    if (S_ISBLK(mode))
        return UNIX_TYPE_BLKDEV;
    if (S_ISFIFO(mode))
        return UNIX_TYPE_FIFO;
    if (S_ISSOCK(mode))
        return UNIX_TYPE_SOCKET;
    return UNIX_TYPE_UNKNOWN;
}

#endif // GPB

/*****************************************************************************/
/*                                                                           */
/*  Support section.                                                         */
/*                                                                           */
/*****************************************************************************/

/*
 * Convert VMFS error codes to -E... errno values.
 */
int
vmfs_errno(int error)
{
    if (error < 0)
    {
        VERBOSE("%d\n", error);

        switch(error)
        {
        case VFS_ERR_BADHANDLE:  return -EBADF;
        case VFS_ERR_NOENTRY:    return -ENOENT;
        case VFS_ERR_NOROOM:     return -ENOMEM;
        case VFS_ERR_MAXHANDLE:  return -EMFILE;
        case VFS_ERR_NOMOUNT:    return -ENXIO;
        case VFS_ERR_NOTFOUND:   return -ENOENT;
        case VFS_ERR_PERM:       return -EACCES;         // EPERM?
        case VFS_ERR_NOTDIR:     return -ENOTDIR;
        case VFS_ERR_TOOLONG:    return -ENAMETOOLONG;
        case VFS_ERR_EXIST:      return -EEXIST;
        case VFS_ERR_NOTEMPTY:   return -ENOTEMPTY;
        case VFS_ERR_INVALID:    return -EINVAL;
        case VFS_ERR_ISDIR:      return -EISDIR;
        case VFS_ERR_TOOBIG:     return -ERANGE;
        case VFS_ERR_UNIMPL:     return -ENOSYS;
        
        default:
            // something generic
            return -EIO;
        }
    }
    else
        return error;
}


static int
vmfs_proc_open(struct vmfs_sb_info *server, struct dentry *dentry, int wish)
{
    struct inode *ino = dentry->d_inode;
    struct vmfs_inode_info *ei = VMFS_I(ino);
    VFSOpenFlags mode = wish;
    int res;
    struct vmfs_ws* ws = vmfs_get_ws(server);

    FNENTER();

    if (!(ino->i_mode & (S_IWUSR | S_IWGRP | S_IWOTH)))
        mode &= ~VFS_OPEN_WRONLY;

    res = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (res < 0)
        goto out;

    res = vfsop_openfile(server->vfs, ws->path, mode);
    if ((res < 0) && ((mode & VFS_OPEN_RDWR) == VFS_OPEN_RDWR))
    {
        mode &= ~VFS_OPEN_WRONLY;
        res = vfsop_openfile(server->vfs, ws->path, mode);
    }

    if (res < 0)
    {
        res = vmfs_errno(res);
        goto out;
    }

    // we appear to need attribute information also. Not sure why.
    // res = vfsop_getattr(server->vfs, p, VFS_ATTR_, attr, attrlen);

    ei->vhandle = res;
    ei->vaccess = mode & VFS_OPEN_RDWR;
    ei->vopen   = 1;

    // may want to set up attr (as in dos attr) here, and access

    res = 0;
out:
    vmfs_put_ws(ws);

    FNEXIT("%d\n", res);
    return res;
}

/*
 * Make sure the file is open, and check that the access
 * is compatible with the desired access.
 *
 * wish is one of VMFS_O_RDONLY = 0/VMFS_O_WRONLY = 1/VMFS_O_RDWR = 2
 */
int
vmfs_open(struct dentry *dentry, int flags, int wish)
{
    struct inode *inode = dentry->d_inode;
    int result;
    VFSOpenFlags vwish, vaccess;

    FNENTER();

    if (wish == VMFS_O_RDONLY)
        vwish = VFS_OPEN_RDONLY;
    else if (wish == VMFS_O_WRONLY)
        vwish = VFS_OPEN_WRONLY;
    else if (wish == VMFS_O_RDWR)
        vwish = VFS_OPEN_RDWR;
    else
    {
        DEBUG1("unexpected open flags!\n");
        vwish = VFS_OPEN_RDWR;
    }

    if (flags & O_CREAT)
        vwish |= VFS_OPEN_CREATE;
    if (flags & O_TRUNC)
        vwish |= VFS_OPEN_TRUNCATE;
    if (flags & O_EXCL)
        vwish |= VFS_OPEN_NEW;

    result = -ENOENT;
    if (!inode) {
        printk(KERN_ERR "vmfs_open: no inode for dentry %s/%s\n",
               DENTRY_PATH(dentry));
        goto out;
    }

    if (!vmfs_is_open(inode)) {
        struct vmfs_sb_info *server = server_from_inode(inode);
        result = 0;
        if (!vmfs_is_open(inode))
            result = vmfs_proc_open(server, dentry, vwish);
        if (result)
            goto out;
        /*
         * A successful open means the path is still valid ...
         */
        vmfs_renew_times(dentry);
    }

    /*
     * Check whether the access is compatible with the desired mode.
     */

    result = 0;
    vaccess = VMFS_I(inode)->vaccess;

    if (vaccess != (vwish & VFS_OPEN_RDWR) && vaccess != VFS_OPEN_RDWR) {
        PARANOIA("%s/%s access denied, access=%x, wish=%x\n",
             DENTRY_PATH(dentry), vaccess, vwish);
        result = -EACCES;
    }
out:
    FNEXIT("%d", result);
    return result;
}

static int 
vmfs_proc_close(struct vmfs_sb_info *server, int32_t handle)
{
    int result = -ENOMEM;

    FNENTER();

    result = vmfs_errno(vfsop_closefile(server->vfs, handle));

    // GPBTODO - may need to set mtime using utc2local(server, mtime)

    FNEXIT("%d", result);

    return result;
}

/*
 * Win NT 4.0 has an apparent bug in that it fails to update the
 * modify time when writing to a file. As a workaround, we update
 * both modify and access time locally, and post the times to the
 * server when closing the file.
 */
static int 
vmfs_proc_close_inode(struct vmfs_sb_info *server, struct inode * ino)
{
    struct vmfs_inode_info *ei = VMFS_I(ino);
    int result = 0;
    if (vmfs_is_open(ino))
    {
        /*
         * We clear the open flag in advance, in case another
         * process observes the value while we block below.
         */
        ei->vopen = 0;

        result = vmfs_proc_close(server, ei->vhandle);

        ei->closed = jiffies;
    }

    FNEXIT("%d", result);

    return result;
}

int
vmfs_close(struct inode *ino)
{
    int result = 0;

    if (vmfs_is_open(ino)) {
        struct vmfs_sb_info *server = server_from_inode(ino);
        result = vmfs_proc_close_inode(server, ino);
    }

    FNEXIT("%d", result);

    return result;
}

/*
 * This is used to close a file following a failed instantiate.
 * Since we don't have an inode, we can't use any of the above.
 */
int
vmfs_close_fileid(struct dentry *dentry, int32_t fileid)
{

    struct vmfs_sb_info *server = server_from_dentry(dentry);
    int result;

    result = vmfs_proc_close(server, fileid /*, get_seconds() */);

    FNEXIT("%d", result);

    return result;
}

static int
vmfs_proc_read(struct inode *inode, loff_t offset, int count, char *data)
{
    struct vmfs_sb_info *server = server_from_inode(inode);
    int result;

    result = vfsop_readfile(server->vfs, VMFS_I(inode)->vhandle, offset, data, count);
    if (result < 0)
        result = vmfs_errno(result);

    VERBOSE("ino=%ld, handle=%d, count=%d, result=%d\n",
        inode->i_ino, VMFS_I(inode)->vhandle, count, result);


    return result;
}

static int
vmfs_proc_write(struct inode *inode, loff_t offset, int count, const char *data)
{
    struct vmfs_sb_info *server = server_from_inode(inode);
    int result;

    result = vfsop_writefile(server->vfs, VMFS_I(inode)->vhandle, offset, data, count);
    if (result < 0)
        result = vmfs_errno(result);

    VERBOSE("ino=%ld, handle=%d, count=%d, result=%d\n",
        inode->i_ino, VMFS_I(inode)->vhandle, count, result);
    return result;
}


// GPB - this appears to be open(O_CREAT) which we do support
int
vmfs_proc_create(struct dentry *dentry, uint32_t mode, int32_t *fileid)
{
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    int result;

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    result = vfsop_openfile(server->vfs, ws->path, VFS_OPEN_CREATE|VFS_OPEN_RDWR);
    if (result < 0)
    {
        result = vmfs_errno(result);
        goto out;
    }

    // GPBTODO - may need to set mtime when file is created
    // GPBTODO - what should create do if the file already exists?

    *fileid = result;
    result = 0;

out:
    vmfs_put_ws(ws);
    FNEXIT("%d", result);
    return result;
}

int
vmfs_proc_mv(struct dentry *old_dentry, struct dentry *new_dentry)
{
    struct vmfs_sb_info *server = server_from_dentry(old_dentry);
    struct vmfs_ws* ws = vmfs_get_ws(server);

    int result;

    result = vmfs_encode_path(server, ws->path, PATH_MAX, old_dentry, NULL);
    if (result < 0)
        goto out;
    result = vmfs_encode_path(server, ws->path2, PATH_MAX, new_dentry, NULL);
    if (result < 0)
        goto out;

    result = vmfs_errno(vfsop_rename(server->vfs, ws->path, ws->path2));
    if (result < 0)
        goto out;

    result = 0;

out:
    vmfs_put_ws(ws);
    FNEXIT("%d", result);
    return result;
}

int
vmfs_proc_mkdir(struct dentry *dentry)
{
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    int result;

    FNENTER();

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    result = vmfs_errno(vfsop_mkdir(server->vfs, ws->path));
    if (result < 0)
        goto out;

    result = 0;

out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

int
vmfs_proc_rmdir(struct dentry *dentry)
{
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    int result;

    FNENTER();

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    result = vmfs_errno(vfsop_rmdir(server->vfs, ws->path));
    if (result < 0)
        goto out;

    result = 0;

out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

#if VMFSFS_POSIX_UNLINK
/*
 * Removes readonly attribute from a file. Used by unlink to give posix
 * semantics.
 */
#if 0 // GPB - not yet used
static int
vmfs_set_rw(struct dentry *dentry,struct vmfs_sb_info *server)
{
    int result;
    struct vmfs_ws* ws = vmfs_get_ws(server);
    uint32_t perm;

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    // GPBTODO
//    perm = VFS_PERM_RW;
//    result = vmfs_errno(vfsop_setattr(server->vfs, p, VFS_ATTR_PERM, (void*)&perm, sizeof(perm)));
    result = 0;

out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}
#endif // GPB

#endif

int
vmfs_proc_unlink(struct dentry *dentry)
{
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    int result;

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    // GPBTODO - this needs to work even if the file is read only
    //           should this be done on the host side?

    result = vmfs_errno(vfsop_remove(server->vfs, ws->path));
out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

int
vmfs_proc_flush(struct vmfs_sb_info *server, int32_t handle)
{
    int result;

    result = vmfs_errno(vfsop_filesync(server->vfs, handle));

    FNEXIT("%d", result);

    return result;
}

static int
vmfs_proc_trunc32(struct inode *inode, loff_t length)
{
    struct vmfs_sb_info *server = server_from_inode(inode);
    int result;

    result = vmfs_errno(vfsop_setfilesize(server->vfs, VMFS_I(inode)->vhandle, length));    
    if (result < 0)
        goto out;

    result = 0;

    FNEXIT("%d", result);

out:
    return result;
}

static void
vmfs_init_dirent(struct vmfs_sb_info *server, struct vmfs_fattr *fattr)
{
    memset(fattr, 0, sizeof(*fattr));

    fattr->f_nlink = 1;
    fattr->f_uid = server->mnt->uid;
    fattr->f_gid = server->mnt->gid;
    fattr->f_unix = 0;
}

static void
vmfs_finish_dirent(struct vmfs_sb_info *server, struct vmfs_fattr *fattr)
{
    if (fattr->f_unix)
        return;

    fattr->f_mode = server->mnt->file_mode;
    if (fattr->attr & aDIR) {
        fattr->f_mode = server->mnt->dir_mode;
        fattr->f_size = VMFS_ST_BLKSIZE;
    }
    /* Check the read-only flag */
    if (fattr->attr & aRONLY)
        fattr->f_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);

    /* How many 512 byte blocks do we need for this file? */
    fattr->f_blocks = 0;
    if (fattr->f_size != 0)
        fattr->f_blocks = 1 + ((fattr->f_size-1) >> 9);
    return;
}

void
vmfs_init_root_dirent(struct vmfs_sb_info *server, struct vmfs_fattr *fattr,
             struct super_block *sb)
{
    vmfs_init_dirent(server, fattr);
    fattr->attr = aDIR;
    fattr->f_ino = 2; /* traditional root inode number */
    fattr->f_mtime = current_fs_time(sb);
    vmfs_finish_dirent(server, fattr);
}

/*
 * read in directory entries into the dentry cache
 */
static int
vmfs_proc_readdir_long(struct file *filp, void *dirent, filldir_t filldir,
              struct vmfs_cache_control *ctl)
{
    struct dentry *dir = filp->f_path.dentry;
    struct vmfs_sb_info *server = server_from_dentry(dir);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    int vhandle;
    struct vmfs_fattr fattr;
    struct qstr qname;
    int result;

    lock_kernel();

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dir, NULL);
    if (result < 0)
        goto out;

    result = vfsop_opendir(server->vfs, ws->path);
    if (result < 0)
    {
        result = vmfs_errno(result);
        goto out;
    }

    vhandle = result;

    while (result >= 0)
    {
        uint32_t attrlen = VMFS_ATTR_MAX;
        uint8_t* attrdata = ws->attr; 
        uint32_t attr = VFS_ATTR_MTIME|VFS_ATTR_TYPE|VFS_ATTR_SIZE|VFS_ATTR_CTIME|VFS_ATTR_ATIME|VFS_ATTR_NAME; 
        uint64_t mtime,ctime,atime;
        VFSAttr ftype;
        uint64_t fsize;
        char* fname;
        
        // todo - get other attributes
        result = vmfs_errno(vfsop_readdir(server->vfs, vhandle, attr, (void*)attrdata, attrlen));
        if (result < 0)
        {
            if (result == -ENOENT)
                result = 0;

            break;
        }

        mtime = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
        ftype = *(uint32_t*)attrdata; attrdata += sizeof(uint32_t);      
        fsize = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
        ctime = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
        atime = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
        fname = (char*)attrdata;

        if (fname[0] == '.' && ((fname[1] == 0) || (fname[1] == '.' && fname[2] == 0)))
            continue;

        // todo - decode attr
        vmfs_init_dirent(server, &fattr);
        fattr.f_ino = 0;

        // mtime/ctime/atime are ms since linux epoch
        {
            uint32_t div, mod;

            div = (uint32_t)divmod64(mtime, 1000, &mod);

            fattr.f_mtime.tv_sec = div;
            fattr.f_mtime.tv_nsec = mod * 1000000;
        }

        {
            uint32_t div, mod;

            div = (uint32_t)divmod64(ctime, 1000, &mod);

            fattr.f_ctime.tv_sec = div;
            fattr.f_ctime.tv_nsec = mod * 1000000;
        }

        {
            uint32_t div, mod;

            div = (uint32_t)divmod64(atime, 1000, &mod);

            fattr.f_atime.tv_sec = div;
            fattr.f_atime.tv_nsec = mod * 1000000;
        }

        fattr.f_size = fsize;
        fattr.attr = 0;
        if (ftype == VFS_TYPE_DIR)
            fattr.attr |= aDIR;

        qname.name = fname;
        qname.len = strlen(fname);

        vmfs_finish_dirent(server, &fattr);
    
        if (!vmfs_fill_cache(filp, dirent, filldir, ctl, &qname, &fattr))
        {
            // smbfs carries on here...
        }
    }

    vfsop_closedir(server->vfs, vhandle);

out:
    unlock_kernel();
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}


static int
vmfs_proc_getattr_unix(struct vmfs_sb_info *server, struct dentry *dir,
              struct vmfs_fattr *fattr)
{
    struct vmfs_ws* ws = vmfs_get_ws(server);
    int attr;
    uint8_t* attrdata = ws->attr;
    int attrlen = VMFS_ATTR_MAX;
    uint64_t mtime,ctime,atime;
    enum VFSType ftype;
    uint64_t fsize;
    char* fname;
    int result;

    lock_kernel();

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dir, NULL);
    if (result < 0)
        goto out;

    attr = VFS_ATTR_MTIME|VFS_ATTR_TYPE|VFS_ATTR_SIZE|VFS_ATTR_CTIME|VFS_ATTR_ATIME|VFS_ATTR_NAME;
    result = vmfs_errno(vfsop_getattr(server->vfs, ws->path, attr, (void*)attrdata, attrlen));
    if (result < 0)
        goto out;

    mtime = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
    ftype = *(uint32_t*)attrdata; attrdata += sizeof(uint32_t);

    // GPBTODO - return this as an error code, why two codes?
    if (ftype == VFS_TYPE_NONE || ftype == VFS_TYPE_UNKNOWN)
    {
        result = -ENOENT;
        goto out;
    }

    fsize = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
    ctime = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
    atime = *(uint64_t*)attrdata; attrdata += sizeof(uint64_t);
    fname = (char*)(attrdata+20);

    // todo - decode attr
    vmfs_init_dirent(server, fattr);
//    fattr->f_ino = 0;
    {
        uint32_t div, mod;

        div = (uint32_t)divmod64(mtime, 1000, &mod);

        fattr->f_mtime.tv_sec = div;
        fattr->f_mtime.tv_nsec = mod * 1000000;
    }

    {
        uint32_t div, mod;

        div = (uint32_t)divmod64(ctime, 1000, &mod);

        fattr->f_ctime.tv_sec = div;
        fattr->f_ctime.tv_nsec = mod * 1000000;
    }

    {
        uint32_t div, mod;

        div = (uint32_t)divmod64(atime, 1000, &mod);

        fattr->f_atime.tv_sec = div;
        fattr->f_atime.tv_nsec = mod * 1000000;
    }

    fattr->f_size = fsize;

    fattr->attr = 0;
    if (ftype == VFS_TYPE_DIR)
        fattr->attr |= aDIR;

    vmfs_finish_dirent(server, fattr);

out:
    unlock_kernel();
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

int
vmfs_proc_getattr(struct dentry *dir, struct vmfs_fattr *fattr)
{
    struct vmfs_sb_info *server = server_from_dentry(dir);
    int result;

    vmfs_init_dirent(server, fattr);
    result = server->ops->getattr(server, dir, fattr);
    vmfs_finish_dirent(server, fattr);

    FNEXIT("%d", result);

    return result;
}


/*
 * Because of bugs in the trans2 setattr messages, we must set
 * attributes and timestamps separately. The core VMFSsetatr
 * message seems to be the only reliable way to set attributes.
 */
int
vmfs_proc_setattr(struct dentry *dir, struct vmfs_fattr *fattr)
{
    struct vmfs_sb_info *server = server_from_dentry(dir);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    int result;

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dir, NULL);
    if (result < 0)
        goto out;

    VERBOSE("setting %s/%s, open=%d\n", 
        DENTRY_PATH(dir), vmfs_is_open(dir->d_inode));

#if 0 // GPBTODO - actually set attributes
#endif
    result = 0;

out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}


/*
 * Set the modify and access timestamps for a file.
 */
int
vmfs_proc_settime(struct dentry *dentry, struct vmfs_fattr *fattr)
{
    struct vmfs_sb_info *server = server_from_dentry(dentry);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    uint32_t attr = VFS_ATTR_MTIME;
    uint8_t* attrdata = ws->attr;
    uint32_t attrlen = 8;
    int result;

    // GPBTODO atime

#if 0 //  GPBTODO - if the file is open for writing, we can use write
        struct inode *inode = dentry->d_inode;
        if (vmfs_is_open(inode) && VMFS_I(inode)->vaccess != VFS_OPEN_RDONLY)
        {
            result = vfsop_writedata(server->vfs, VMFS_I(inode)->vhandle, 0, NULL, 0);
        }
#endif // GPBTODO

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

#if 0 // GPBTODO - actually set the time...
    *(uint64_t*)attrdata = 0;
    result = vmfs_errno(vfsop_setattr(server->vfs, ws->path, attr, (void*)attrdata, attrlen));
#endif // GPBTODO
    result = 0;

out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

int
vmfs_proc_dskattr(struct dentry *dentry, struct kstatfs *kattr)
{
    int result;
    struct vmfs_sb_info *server = VMFS_SB(dentry->d_sb);
    struct vmfs_ws* ws = vmfs_get_ws(server);
    uint32_t attr = VFS_ATTR_DISKSIZE|VFS_ATTR_DISKFREE;
    uint8_t* attrdata = ws->attr;
    uint32_t attrlen = 16;
    uint64_t disksize, diskfree;

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    result = vmfs_errno(vfsop_getattr(server->vfs, ws->path, attr, (void*)attrdata, attrlen));
    if (result < 0)
        goto out;

    disksize = *(uint64_t*)attrdata;
    diskfree = *(uint64_t*)(attrdata+8);

    kattr->f_bsize  = VMFS_ST_BLKSIZE;
    kattr->f_blocks = disksize >> VMFS_ST_BLKSHIFT;
    kattr->f_bavail = diskfree >> VMFS_ST_BLKSHIFT;

    result = 0;
out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

/* vfs may not support this operation
 */

int
vmfs_proc_read_link(struct vmfs_sb_info *server, struct dentry *dentry,
           char *buffer, int len)
{
    int result;
    struct vmfs_ws* ws = vmfs_get_ws(server);

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    result = vmfs_errno(vfsop_readlink(server->vfs, ws->path, buffer, len));
    if (result < 0)
        goto out;

    // GPB can't remember if we return the length or not
    // we should
    buffer[len-1] = 0;
    result = strlen(buffer);

out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

/*
 * Create a symlink object called dentry which points to oldpath.
 * vfs may not support this operation
 */
int
vmfs_proc_symlink(struct vmfs_sb_info *server, struct dentry *dentry,
         const char *oldpath)
{
    int result;
    struct vmfs_ws* ws = vmfs_get_ws(server);

    result = vmfs_encode_path(server, ws->path, PATH_MAX, dentry, NULL);
    if (result < 0)
        goto out;

    result = vmfs_errno(vfsop_symlink(server->vfs, ws->path, oldpath));

out:
    vmfs_put_ws(ws);

    FNEXIT("%d", result);

    return result;
}

/*
 * Create a hard link object called new_dentry which points to dentry.
 */
int
vmfs_proc_link(struct vmfs_sb_info *server, struct dentry *dentry,
          struct dentry *new_dentry)
{
    // we don't support hard links
    return -EPERM;
}

static void
install_ops(struct vmfs_ops *dst, struct vmfs_ops *src)
{
    memcpy(dst, src, sizeof(void *) * VMFS_OPS_NUM_STATIC);
}

static struct vmfs_ops vmfs_server_ops =
{
    .read       = vmfs_proc_read,
    .write      = vmfs_proc_write,
    .readdir    = vmfs_proc_readdir_long,
    .getattr    = vmfs_proc_getattr_unix,
    /* .setattr = vmfs_proc_setattr_unix, */
    .truncate   = vmfs_proc_trunc32,
};

void vmfs_install_ops(struct vmfs_ops *ops)
{
    install_ops(ops, &vmfs_server_ops);
}

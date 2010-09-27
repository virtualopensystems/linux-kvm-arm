/*
 * Copyright 2008-2009 ARM Limited. All rights reserved.
 */

/*!
 * \file    vfs.cpp
 * \brief   target side vfs implementation in C
 *
 * The vfs functions have been renamed to vfsop to avoid
 * symbol clashes in linux. We should standardise on one or the other.
 */

// linux kernel requires different includes

#include <linux/mm.h>
#include <linux/string.h>
#include <linux/types.h>

#include "messagebox.h"
#include "msg.h"
#include "vfs.h"

////////////////////////////////////////////////////////////////////////////////
// vfs layer implementation

// VFS operations - these must match those defined in VFS.h
typedef enum VFSOp
{
    VFS_OPENMOUNTS,
    VFS_READMOUNTS,
    VFS_CLOSEMOUNTS,
    
    VFS_OPENDIR,
    VFS_READDIR,
    VFS_CLOSEDIR,
    VFS_MKDIR,
    VFS_RMDIR,
    VFS_REMOVE,
    VFS_RENAME,
    VFS_GETATTR,
    VFS_SETATTR,
    
    VFS_OPENFILE,
    VFS_CLOSEFILE,
    VFS_WRITEFILE,
    VFS_READFILE,
    VFS_GETFILESIZE,
    VFS_SETFILESIZE,
    VFS_FILESYNC,
    
    VFS_SYMLINK,
    VFS_READLINK
} VFSOp;


// maximum _data_ transfer in a message, this must allow for other message parameters
// \todo it should be derived from the maximum messsage size
#define VFS_MAX_DATA 4096
#define VFS_MAX_MSG  8192

struct VFS
{
    MessageBox* mb;
    MessageComposer* mc;
    MessageDecomposer* md;

    int last_err;
};

void vfsop_init(VFS* vfs, MessageBox* mb)
{
    vfs->mb = mb;
    vfs->mc = msgc_new(NULL, 0);
    vfs->md = msgd_new(NULL, 0);

    vfs->last_err = 0;
}

void vfsop_cleanup(VFS* vfs)
{
    vfs->mb = NULL;
    msgc_delete(vfs->mc);
    vfs->mc = NULL;
    msgd_delete(vfs->md);
    vfs->md = NULL;
}

VFS* vfsop_new(MessageBox* mb)
{
    VFS* vfs = (VFS*)kmalloc(sizeof(struct VFS), GFP_KERNEL);

    // vfs should check that MB is actually a VFS mb

    vfsop_init(vfs, mb);

    return vfs;
}

void vfsop_delete(VFS* vfs)
{
    vfsop_cleanup(vfs);

//    free(vfs);
    kfree(vfs);
}

int vfsop_startcall(VFS* vfs, uint32_t op)
{
    void* buffer;
    
    if (mb_lock(vfs->mb) < 0)
        return -1;
    
    buffer = mb_start(vfs->mb, VFS_MAX_MSG);

    msgc_init(vfs->mc, buffer, VFS_MAX_MSG);

    msgc_put_uint32(vfs->mc, 0);        // message id
    msgc_put_uint32(vfs->mc, op);       // vfs operation

    return 0;
}

void vfsop_call(VFS* vfs)
{
    void* buffer;
    uint32_t blen;
    uint32_t id;

    /* int ret = */ mb_end(vfs->mb, msgc_get_size(vfs->mc));

    msgc_cleanup(vfs->mc);

    // todo - this can currently return -1 if the thread was interrupted.
    //        we probably don't want to support interruption during the call
    mb_wait(vfs->mb);

    buffer = mb_receive(vfs->mb, &blen);

    msgd_init(vfs->md, buffer, blen);

    msgd_get_uint32(vfs->md, &id);       // message id inserted above
   
    // todo - check the id's match
}

void vfsop_endcall(VFS* vfs)
{
    msgd_cleanup(vfs->md);

    mb_unlock(vfs->mb);
}

int32_t vfsop_openmounts(VFS* vfs)
{
    int32_t handle;

    vfsop_startcall(vfs, VFS_OPENMOUNTS);

        vfsop_call(vfs);
        msgd_get_int32(vfs->md, &handle);

    vfsop_endcall(vfs);

    return handle;
}

int32_t vfsop_readmounts(VFS* vfs, int32_t handle, uint32_t attr, uint8_t* attrdata, uint32_t attrdatalen)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_READMOUNTS);

        msgc_put_int32(vfs->mc, handle);
        msgc_put_uint32(vfs->mc, attr);
        msgc_put_uint32(vfs->mc, attrdatalen);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);
        msgd_get_data(vfs->md, attrdata, &attrdatalen);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_closemounts(VFS* vfs, int32_t handle)
{
    int32_t ret;

    ret = vfsop_startcall(vfs, VFS_READMOUNTS);
    if (ret < 0)
        return ret;

        msgc_put_int32(vfs->mc, handle);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_opendir(VFS* vfs, const char* dirname)
{
    int32_t ret;

    // todo - return code
    vfsop_startcall(vfs, VFS_OPENDIR);

        msgc_put_cstr(vfs->mc, dirname);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_readdir(VFS* vfs,int32_t handle, uint32_t attr, uint8_t* attrdata, uint32_t attrdatalen)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_READDIR);

        msgc_put_int32(vfs->mc, handle);
        msgc_put_uint32(vfs->mc, attr);
        msgc_put_uint32(vfs->mc, attrdatalen);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);
        msgd_get_data(vfs->md, attrdata, &attrdatalen);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_closedir(VFS* vfs, int32_t handle)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_CLOSEDIR);

        msgc_put_int32(vfs->mc, handle);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_mkdir(VFS* vfs, const char* name)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_MKDIR);

        msgc_put_cstr(vfs->mc, name);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_rmdir(VFS* vfs, const char* name)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_RMDIR);

        msgc_put_cstr(vfs->mc, name);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_remove(VFS* vfs, const char* name)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_REMOVE);

        msgc_put_cstr(vfs->mc, name);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_rename(VFS* vfs, const char* oldname, const char* newname)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_RENAME);

        msgc_put_cstr(vfs->mc, oldname);
        msgc_put_cstr(vfs->mc, newname);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_getattr(VFS* vfs, const char* name, uint32_t attr, uint8_t* attrdata, uint32_t attrdatalen)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_GETATTR);

        msgc_put_cstr(vfs->mc, name);
        msgc_put_uint32(vfs->mc, attr);
        msgc_put_uint32(vfs->mc, attrdatalen);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);
        msgd_get_data(vfs->md, attrdata, &attrdatalen);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_setattr(VFS* vfs, const char* name, uint32_t attr, const uint8_t* attrdata, uint32_t attrdatalen)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_SETATTR);

        msgc_put_cstr(vfs->mc, name);
        msgc_put_uint32(vfs->mc, attr);
        msgc_put_data(vfs->mc, attrdata, attrdatalen);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_openfile(VFS* vfs, const char* name, uint32_t flags)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_OPENFILE);

        msgc_put_cstr(vfs->mc, name);
        msgc_put_uint32(vfs->mc, flags);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_closefile(VFS* vfs, int32_t handle)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_CLOSEFILE);

        msgc_put_int32(vfs->mc, handle);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_writefile(VFS* vfs, int32_t handle, uint64_t offset, const void* data, int32_t len)
{
    int32_t ret;
    int32_t residual = len;

    // Transfer has to be broken into manageable chunks

    while (residual > 0)
    {
        int32_t t_len = (residual > VFS_MAX_DATA) ? VFS_MAX_DATA : residual;

        vfsop_startcall(vfs, VFS_WRITEFILE);

            msgc_put_int32(vfs->mc, handle);
            msgc_put_uint64(vfs->mc, offset);
            msgc_put_data(vfs->mc, data, t_len);
            msgc_put_uint32(vfs->mc, t_len);       // why?

            vfsop_call(vfs);

            msgd_get_int32(vfs->md, &ret);

        vfsop_endcall(vfs);

        if (ret < 0)
            return ret;

        offset += ret;
        residual -= ret;
        data = (uint8_t*)data + ret;

        if (ret < t_len)
            break;
    }

    return len-residual;
}

int32_t vfsop_readfile(VFS* vfs, int32_t handle, uint64_t offset, void* data, int32_t len)
{
    int32_t ret;
    int32_t residual = len;
    uint32_t rlen = len;

    // data must be sent in manageable chunks

    while (residual > 0)
    {
        int32_t t_len = (residual > VFS_MAX_DATA) ? VFS_MAX_DATA : residual;

        vfsop_startcall(vfs, VFS_READFILE);

            msgc_put_int32(vfs->mc, handle);
            msgc_put_uint64(vfs->mc, offset);
            msgc_put_uint32(vfs->mc, t_len); 

            vfsop_call(vfs);

            msgd_get_int32(vfs->md, &ret);
            msgd_get_data(vfs->md, data, &rlen);

        vfsop_endcall(vfs);

        if (ret < 0)
            return ret;

        offset += ret;
        residual -= ret;
        data = (uint8_t*)data + ret;

        if (ret < t_len)
            break;
    }

    return len-residual;
}

int32_t vfsop_getfilesize(VFS* vfs, int32_t handle, uint64_t* size)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_GETFILESIZE);

        msgc_put_int32(vfs->mc, handle);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);
        msgd_get_uint64(vfs->md, size);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_setfilesize(VFS* vfs, int32_t handle, uint64_t size)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_SETFILESIZE);

        msgc_put_int32(vfs->mc, handle);
        msgc_put_uint64(vfs->mc, size);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_filesync(VFS* vfs, int32_t handle)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_FILESYNC);

        msgc_put_int32(vfs->mc, handle);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_symlink(VFS* vfs, const char* filename, const char* symlink)
{
    int32_t ret;

    vfsop_startcall(vfs, VFS_SYMLINK);

        msgc_put_cstr(vfs->mc, filename);
        msgc_put_cstr(vfs->mc, symlink);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);

    vfsop_endcall(vfs);

    return ret;
}

int32_t vfsop_readlink(VFS* vfs, const char* filename, char* buf, int32_t bufsiz)
{
    int32_t ret;
    uint32_t rlen;

    vfsop_startcall(vfs, VFS_READLINK);

        msgc_put_cstr(vfs->mc, filename);
        msgc_put_int32(vfs->mc, bufsiz);

        vfsop_call(vfs);

        msgd_get_int32(vfs->md, &ret);
        msgd_get_data(vfs->md, buf, &rlen);

    vfsop_endcall(vfs);

    return ret;
}


/*
 * Copyright 2008-2009 ARM Limited. All rights reserved.
 */

/*!
 * \file    vfs.h
 * \brief   target side vfs interface in C
 *
 * This interface has been renamed to VFS (and the operations to vfsop) to avoid
 * symbol clashes in linux. We should standardise on one or the other.
 */

#ifndef VFS_H
#define VFS_H

#include "messagebox.h"

// \todo - get these definitions from a shared header used on both host/target side

// Objects types that can exist on a filesystem
enum VFSType
{
    VFS_TYPE_NONE,      // file not found
    VFS_TYPE_FILE,      // regular file
    VFS_TYPE_DIR,       // directory
    VFS_TYPE_LINK,      // symbolic link
    VFS_TYPE_UNKNOWN,   // unknown object type
    VFS_TYPE_MOUNT      // mount point
};

// \todo these should probably be +ve and return as -VFS_ERR_ etc.
enum VFSError
{
    VFS_ERR_OK        =  0,     // all ok (actually 0 or +ve means ok)
    VFS_ERR_BADHANDLE = -1,     // invalid or wrong type of handle
    VFS_ERR_NOENTRY   = -2,     // no more entries in a directory
    VFS_ERR_NOROOM    = -3,     // ran out of memory/buffer/disk space
    VFS_ERR_MAXHANDLE = -4,     // ran out of handles
    VFS_ERR_NOMOUNT   = -5,     // no such mount exists
    VFS_ERR_NOTFOUND  = -6,     // object not found
    VFS_ERR_PERM      = -7,     // permission error
    VFS_ERR_NOTDIR    = -8,     // path element wasn't a directory
    VFS_ERR_TOOLONG   = -9,     // path or path element too long
    VFS_ERR_EXIST     = -10,    // an object with the name already exists
    VFS_ERR_NOTEMPTY  = -11,    // tried to remove a directory that wasn't empty
    VFS_ERR_INVALID   = -12,    // invalid operation or operand, e.g. bad pathname
    VFS_ERR_ISDIR     = -13,    // object is a directory
    VFS_ERR_TOOBIG    = -14,    // parameter or return value was too large to represent
    VFS_ERR_UNIMPL    = -15,    // unimplemented feature
    VFS_ERR_UNKNOWN   = -100    // unexpected host error
};

typedef enum VFSAttr
{
    VFS_ATTR_MTIME    = 0x0001,  // uint64_t modification time
    VFS_ATTR_ACCESS   = 0x0002,  // uint32_t access permissions (read/write/execute etc)    
    VFS_ATTR_TYPE     = 0x0004,  // uint32_t object type (as above)
    VFS_ATTR_SIZE     = 0x0008,  // uint64_t object size in bytes
    VFS_ATTR_CTIME    = 0x0010,  // uint64_t object creation time (if supported)
    VFS_ATTR_ATIME    = 0x0020,  // uint64_t object access time
    VFS_ATTR_RTIME    = 0x0040,  // uint64_t current real time
    VFS_ATTR_DISKSIZE = 0x0100,  // uint64_t size of disk in bytes
    VFS_ATTR_DISKFREE = 0x0200,  // uint64_t free space on disk in bytes
    VFS_ATTR_NAME     = 0x8000,  // char* always last to make the variable length easy
} VFSAttr;

// flags passed to Mount::openFile
typedef enum VFSOpenFlags
{
    VFS_OPEN_RDONLY = 1,
    VFS_OPEN_WRONLY = 2,
    VFS_OPEN_RDWR   = VFS_OPEN_RDONLY|VFS_OPEN_WRONLY,
    VFS_OPEN_CREATE = 4,
    VFS_OPEN_NEW    = 8,
    VFS_OPEN_TRUNCATE = 16
} VFSOpenFlags;

/*! Opaque instance handle for use in vfs calls */
typedef struct VFS VFS;

   /*! instantiate a new vfs object
    *
    * \param mb         message box instance to use as a transport layer
    *
    * \return           vfs instance handle to use in vfs calls
    */
VFS* vfsop_new(MessageBox* mb);

   /*! delete a vfs instance
    *
    * \param vfs       instance to delete
    */
void vfsop_delete(VFS* vfs);

    /*! Open an iterator on the list of mounts added with add Mount
     *
     * \param vfs      vfs instance
     * 
     * \return a handle to be used with readmounts/closemounts or a VFSError code
     */
int32_t vfsop_openmounts(VFS* vfs);

    /* Read the next entry in a list of mounts
     *
     * \param vfs      vfs instance
     * \param id        mount iterator handle
     * \param attr      a bit mask of attributes to return (one or more VFSAttr)
     * \param attrdata  data block to receive attributes
     * \param attrlen   size of attribute block
     *
     * \return VFSError code
     *
     * The attribute block is packed with data in VFSAttr order (lowest to highest). Be careful
     * to unpack the attribute block using the correct data sizes. Not all attributes are
     * relavent to mount data
     *
     */
int32_t vfsop_readmounts(VFS* vfs, int32_t handle, uint32_t attr, uint8_t* attrdata, uint32_t attrdatalen);

    /* Close a mount iterator handle
     *
     * \param vfs      vfs instance
     * \param id        mount iterator handle
     *
     * \return VFSError code
     */
int32_t vfsop_closemounts(VFS* vfs, int32_t handle);

    /* Open a directory iterator handle
     *
     * \param vfs      vfs instance
     * \param name      full (vfs) path name to directory
     *
     * \return directory iterator handle for use with readdir/closedir or a VFSError code
     */
int32_t vfsop_opendir(VFS* vfs, const char* dirname);

    /* Read an entry form a directory iterator
     *
     * \param vfs      vfs instance
     * \param id        directory iterator handle
     * \param attr      a bit mask of attributes to return (one or more VFSAttr)
     * \param attrdata  data block to receive attributes
     * \param attrlen   size of attribute block
     *
     * \return VFSError code
     *
     * The attribute block is packed with data in VFSAttr order (lowest to highest). Be careful
     * to unpack the attribute block using the correct data sizes
     *
     * \todo pass attrlen by reference so it can be updated with the size used
     * \todo pass attr by reference so that the actual returned attributes can be indicated
     */
int32_t vfsop_readdir(VFS* vfs,int32_t handle, uint32_t attr, uint8_t* attrdata, uint32_t attrdatalen);

    /* Close a directory iterator
     *
     * \param vfs      vfs instance
     * \param id        directory iterator handle
     *
     * \return VFSError code
     */
int32_t vfsop_closedir(VFS* vfs, int32_t handle);

    /* Create a directory
     *
     * \param vfs      vfs instance
     * \param name      (vfs) directory name to create
     *
     * \return VFSError code
     */
int32_t vfsop_mkdir(VFS* vfs, const char* name);

    /* Remove a directory
     *
     * \param vfs      vfs instance
     * \param name      (vfs) directory name to create
     *
     * \return VFSError code
     */
int32_t vfsop_rmdir(VFS* vfs, const char* name);

    /* Remove a file
     *
     * \param vfs      vfs instance
     * \param name      (vfs) file to remove (may also work on other object types)
     *
     * \return VFSError code
     */
int32_t vfsop_remove(VFS* vfs, const char* name);

    /* Rename an object
     *
     * \param vfs      vfs instance
     * \param oldname   (vfs) object to rename
     * \param newname   (vfs) new name of object
     *
     * \return VFSError code
     */
int32_t vfsop_rename(VFS* vfs, const char* oldname, const char* newname);

    /* Retrieve attributes of an object on the filesystem
     *
     * \param vfs      vfs instance
     * \param name      (vfs) object name
     * \param attr      a bit mask of attributes to return (one or more VFSAttr)
     * \param attrdata  data block to receive attributes
     * \param attrlen   size of attribute block
     *
     * \return VFSError code
     *
     * The attribute block is packed with data in VFSAttr order (lowest to highest). Be careful
     * to unpack the attribute block using the correct data sizes
     *
     * \todo pass attrlen by reference so it can be updated with the size used
     * \todo pass attr by reference so that the actual returned attributes can be indicated
     */
int32_t vfsop_getattr(VFS* vfs, const char* name, uint32_t attr, uint8_t* attrdata, uint32_t attrdatalen);

    /* Retrieve attributes of an object on the filesystem
     *
     * \param vfs      vfs instance
     * \param name      (vfs) object name
     * \param attr      a bit mask of attributes to modify (one or more VFSAttr)
     * \param attrdata  data block containing packed attributes
     * \param attrlen   size of attribute block
     *
     * \return VFSError code
     *
     * The attribute block should be packed with data in VFSAttr order (lowest to highest). Be careful
     * to pack the attribute block using the correct data sizes
     *
     * Not all attributes can be modified using this (e.g. file size/disk free/file name)
     *
     * \todo pass attr by reference so that the actual modified attributes can be indicated
     */
int32_t vfsop_setattr(VFS* vfs, const char* name, uint32_t attr, const uint8_t* attrdata, uint32_t attrdatalen);

    /* Open a file object on the filesystem for reading/writing
     *
     * \param vfs      vfs instance
     * \param filename  (vfs) file name
     * \param flags     VFSOpenFlags value indicating how to open the file
     *
     * \return file handle to use with readfile/writefile/closefile etc or a VFSError code
     */
int32_t vfsop_openfile(VFS* vfs, const char* name, uint32_t flags);

    /* Close a file object by a handle returned from openfile
     *
     * \param vfs      vfs instance
     * \param id        file handle
     *
     * \return VFSError code
     */
int32_t vfsop_closefile(VFS* vfs, int32_t handle);

    /* Write data to a file 
     *
     * \param vfs      vfs instance
     * \param id        file handle returned from openfile
     * \param offset    offset into file from where to start writing
     * \param data      pointer to data block containing data to be written
     * \param len       length of data to be written
     * 
     * \return length of data actually written to the file or a VFSError code
     */
int32_t vfsop_writefile(VFS* vfs, int32_t handle, uint64_t offset, const void* data, int32_t len);

    /* Read data from a file 
     *
     * \param vfs      vfs instance
     * \param id        file handle returned from openfile
     * \param offset    offset into file from where to start reading
     * \param data      pointer to data block to receive data read from file
     * \param len       size of data block to receive data
     * 
     * \return length of data actually read from the file or a VFSError code
     */
int32_t vfsop_readfile(VFS* vfs, int32_t handle, uint64_t offset, void* data, int32_t len);

    /* Get the size of an open file
     *
     * \param vfs      vfs instance
     * \param id        file handle returned from openfile
     * \param size      pointer to instance data to receive file size
     *
     * \return VFSError code
     */
int32_t vfsop_getfilesize(VFS* vfs, int32_t handle, uint64_t* size);

    /* Set the size of an open file
     *
     * \param vfs      vfs instance
     * \param id        file handle returned from openfile
     * \param size      new size of file
     *
     * \return VFSError code
     *
     * this will truncate or extend the file depending on whether the new size is
     * smaller or larger than the current file size
     */
int32_t vfsop_setfilesize(VFS* vfs, int32_t handle, uint64_t size);

    /* Force modified parts of a file back to persistent storage
     *
     * \param vfs      vfs instance
     * \param id        file handle returned from openfile
     *
     * \return VFSError code
     */
int32_t vfsop_filesync(VFS* vfs, int32_t handle);

/* Linux target support functions */

   /* Create a symbolic link object
    *
    * \param vfs      vfs instance
    * \param filename  (vfs) name of link object to be created
    * \param data      content of link object (typically a path to another object)
    *
    * \return VFSError code
    *
    * \todo this is not yet implemented
    */

int32_t vfsop_symlink(VFS* vfs, const char* filename, const char* symlink);

    /* Read the contents of a symbolic link object
     *
     * \param vfs      vfs instance
     * \param filename  (vfs) name of link object to be read
     * \param data      data block to receive link object contents
     * \param bufsiz    size of data block to receive link object contents
     *
     * \return VFSError code
     *
     * \todo this is not yet implemented
     */
int32_t vfsop_readlink(VFS* vfs, const char* filename, char* buf, int32_t bufsiz);

#endif // VFS_H

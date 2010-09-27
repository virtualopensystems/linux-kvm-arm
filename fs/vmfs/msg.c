/*
 * Copyright 2008-2009 ARM Limited. All rights reserved.
 */

/* 
    Utility types/functions for constructing/deconstructing blocks of data to be sent over
    a message box between the target and host (and vice versa)

    this implementation is coverted to be used in the linux kernel

    These must match the behaviour in the equivalent C++ classes used on the host side
*/

//#include <stdio.h>
//#include <stdint.h>
//#include <stdlib.h>
//#include <string.h>
//#include <assert.h>

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/string.h>

#include "msg.h"

typedef enum MsgDataType
{
    MSG_END,            // (potential) marker for end of message data
    MSG_UINT32,         // 32 bit data
    MSG_UINT64,         // 64 bit data
    MSG_INT32,          // 32 bit data
    MSG_CSTR,           // zero terminated c string
    MSG_DATA,           // raw data
    MSG_CHAR,           // single character
    MSG_BOOL            // packed int?
} MsgDataType;

typedef enum MsgTraits
{
    TYPE_SHIFT  = 0,
    TYPE_BITS   = 8,
    TYPE_MASK   = (1<<TYPE_BITS)-1,

    LEN_SHIFT   = TYPE_BITS,
    LEN_BITS    = 20,
    MAX_LEN     = 1<<LEN_BITS,
    LEN_MASK    = MAX_LEN-1
} MsgTraits;

struct MessageComposer
{
    uint8_t* b_data;  // message data
    uint32_t b_size;  // buffer size
    uint32_t b_index; // offset to next byte to fill
};

void msgc_init(MessageComposer* mc, void* data, uint32_t len)
{
    mc->b_data = data;
    mc->b_size = len;
    mc->b_index = 0;
}

void msgc_cleanup(MessageComposer* mc)
{
}

MessageComposer* msgc_new(void* data, uint32_t len)
{
//    MessageComposer* mc = (MessageComposer*)malloc(sizeof(struct MessageComposer));
    MessageComposer* mc = (MessageComposer*)kmalloc(sizeof(struct MessageComposer), GFP_KERNEL);

    msgc_init(mc, data, len);

    return mc;
}

void msgc_delete(MessageComposer* mc)
{
    msgc_cleanup(mc);

//    free(mc);
    kfree(mc);
}


static int msgc_put(MessageComposer* mc, MsgDataType type, const void* data, uint32_t len)
{
    uint32_t tag;

    if (len >= mc->b_size)
        return 0;

    if (!mc->b_data)
        return 0;

    tag = (len << LEN_SHIFT)|((uint32_t)type);

    *(uint32_t*)(mc->b_data + mc->b_index) = tag;
    mc->b_index += 4;

    memcpy(mc->b_data+mc->b_index, data, len);
    mc->b_index += len;

    mc->b_index = (mc->b_index + 3) &~ 3; // word align

    return 1;
}


int msgc_put_int32(MessageComposer* mc, int32_t data)
{
    return msgc_put(mc, MSG_INT32, (void*)&data, sizeof(int32_t));
}

int msgc_put_uint32(MessageComposer* mc, uint32_t data)
{
    return msgc_put(mc, MSG_UINT32, (void*)&data, sizeof(uint32_t));
}

int msgc_put_uint64(MessageComposer* mc, uint64_t data)
{
    return msgc_put(mc, MSG_UINT64, (void*)&data, sizeof(uint64_t));
}

int msgc_put_cstr(MessageComposer* mc, const char* data)
{
    return msgc_put(mc, MSG_CSTR, (void*)data, strlen(data)+1);
}

int msgc_put_data(MessageComposer* mc, const void* data, uint32_t len)
{
    return msgc_put(mc, MSG_DATA, data, len);
}

// todo - other types

uint32_t msgc_get_size(MessageComposer* mc)
{ 
    return mc->b_index; 
}

struct MessageDecomposer
{
    const uint8_t* b_data;        // message data
    uint32_t       b_size;        // size of buffer
    uint32_t       b_index;       // current index into buffer
};


static int msgd_get(MessageDecomposer* md, MsgDataType type, void* data, uint32_t* len)
{
    uint32_t tag;
    uint32_t d_len;
    MsgDataType d_type;

    if (md->b_index + 4 > md->b_size)
        return 0;

    tag = *(uint32_t*)(md->b_data + md->b_index);

    d_type = (MsgDataType)((tag>>TYPE_SHIFT) & TYPE_MASK);
    d_len = ((tag>>LEN_SHIFT) & LEN_MASK);

    if (d_type != type)
        return 0;

    md->b_index += 4;

    if (md->b_index + d_len > md->b_size)
        return 0;

    if (*len > d_len)
        *len = d_len;

    memcpy(data, md->b_data+md->b_index, *len);

    md->b_index += d_len;

    md->b_index = (md->b_index + 3) &~ 3; // word align

    return 1;
}

void msgd_init(MessageDecomposer* md, const void* data, uint32_t len)
{
    md->b_data  = (const unsigned char*)data;
    md->b_size  = len;
    md->b_index = 0;
}

void msgd_cleanup(MessageDecomposer* md)
{
}

MessageDecomposer* msgd_new(const void* data, uint32_t len)
{
//    MessageDecomposer* md = (MessageDecomposer*)malloc(sizeof(struct MessageDecomposer));
    MessageDecomposer* md = (MessageDecomposer*)kmalloc(sizeof(struct MessageDecomposer), GFP_KERNEL);

    msgd_init(md, data, len);

    return md;
}

void msgd_delete(MessageDecomposer* md)
{
    msgd_cleanup(md);
//    free(md);
    kfree(md);
}

// for decomposing

int msgd_get_int32(MessageDecomposer* md, int32_t* data)
{
    uint32_t len = sizeof(int32_t);

    return msgd_get(md, MSG_INT32, (void*)data, &len);
}

int msgd_get_uint32(MessageDecomposer* md, uint32_t* data)
{
    uint32_t len = sizeof(uint32_t);

    return msgd_get(md, MSG_UINT32, (void*)data, &len);
}

int msgd_get_uint64(MessageDecomposer* md, uint64_t* data)
{
    uint32_t len = sizeof(uint64_t);

    return msgd_get(md, MSG_UINT64, (void*)data, &len);
}

int msgd_get_cstr(MessageDecomposer* md, char* data, unsigned int* len)
{
    return msgd_get(md, MSG_CSTR, (void*)data, len);
}

int msgd_get_data(MessageDecomposer* md, void* data, uint32_t* len)
{
    return msgd_get(md, MSG_DATA, data, len);
}

/*
 * Copyright 2008-2009 ARM Limited. All rights reserved.
 */

/*!
 * \file    msg.h
 * \brief   objects and functions to covert function calls into messages and back
 *
 * \todo change return codes, and define some errors
 */

#ifndef MSG_H
#define MSG_H

/*! opaque type for an object that can compose messages */
typedef struct MessageComposer MessageComposer;

/*! instantiate a new message composer object that can compose a message into the
 *  supplied buffer
 *
 * \param data  buffer into which messages can be composed (may be NULL)
 * \param len   size of buffer (may be 0)
 *
 * \return message composer object
 */
MessageComposer* msgc_new(void* data, uint32_t len);

/*! destroy a message composer object 
 * 
 * \param mc    message composer object
 */
void msgc_delete(MessageComposer* mc);

/*! (re)initialise a message composer object to use a new buffer
 *
 * \param mc    message composer object
 * \param data  buffer into which messages can be composed (may be NULL)
 * \param len   size of buffer (may be 0)
 */
void msgc_init(MessageComposer* mc, void* data, uint32_t len);

/*! disassociate a message composer object from a buffer
 *
 * \param mc    message composer object
 */
void msgc_cleanup(MessageComposer* mc);

/*! add a signed integer to the message 
 *
 * \param mc    message composer object
 * \param data  data to add to message
 *
 * \return 1 for success, 0 for fail
 */
int msgc_put_int32(MessageComposer* mc, int32_t data);

/*! add an unsigned signed integer to the message 
 *
 * \param mc    message composer object
 * \param data  data to add to message
 *
 * \return 1 for success, 0 for fail
 */
int msgc_put_uint32(MessageComposer* mc, uint32_t data);

/*! add an unsigned 64bit integer to the message 
 *
 * \param mc    message composer object
 * \param data  data to add to message
 *
 * \return 1 for success, 0 for fail
 */
int msgc_put_uint64(MessageComposer* mc, uint64_t data);

/*! add a zero terminated string to the message 
 *
 * \param mc    message composer object
 * \param data  data to add to message
 *
 * \return 1 for success, 0 for fail
 */
int msgc_put_cstr(MessageComposer* mc, const char* data);

/*! add a data block the message 
 *
 * \param mc    message composer object
 * \param data  data to add to message
 * \param len   length of data to add to the message
 *
 * \return 1 for success, 0 for fail
 */
int msgc_put_data(MessageComposer* mc, const void* data, uint32_t len);

/*! return the current size of the message in bytes
 *
 * \param mc    message composer object
 *
 * \return size of the message in bytes
 */
uint32_t msgc_get_size(MessageComposer* mc);

/*! opaque type for an object that can decompose messages */
typedef struct MessageDecomposer MessageDecomposer;

/*! instantiate a new message decomposer object that can decompose a message from the
 *  supplied buffer
 *
 * \param data  buffer from which messages can be decomposed (may be NULL)
 * \param len   size of buffer (may be 0)
 *
 * \return message decomposer object
 */
MessageDecomposer* msgd_new(const void* data, uint32_t len);

/*! destroy a message decomposer object 
 * 
 * \param md    message decomposer object
 */
void msgd_delete(MessageDecomposer* md);

/*! (re)initialise a message decomposer object to use a new buffer
 *
 * \param md    message decomposer object
 * \param data  buffer from which messages can be decomposed (may be NULL)
 * \param len   size of buffer (may be 0)
 */
void msgd_init(MessageDecomposer* md, const void* data, uint32_t len);

/*! disassociate a message decomposer object from a buffer
 *
 * \param md    message decomposer object
 */
void msgd_cleanup(MessageDecomposer* md);

/*! extract a signed integer from the message 
 *
 * \param md    message decomposer object
 * \param data  data to extract from message
 *
 * \return 1 for success, 0 for fail
 */
int msgd_get_int32(MessageDecomposer* md, int32_t* data);

/*! extract an unsigned integer from the message 
 *
 * \param md    message decomposer object
 * \param data  data to extract from message
 *
 * \return 1 for success, 0 for fail
 */
int msgd_get_uint32(MessageDecomposer* md, uint32_t* data);

/*! extract an unsigned 64 bit integer from the message 
 *
 * \param md    message decomposer object
 * \param data  data to extract from message
 *
 * \return 1 for success, 0 for fail
 */
int msgd_get_uint64(MessageDecomposer* md, uint64_t* data);

/*! extract a zero terminated C string from the message 
 *
 * \param md    message decomposer object
 * \param data  data to extract from message
 * \param len   in: max length to extract, out: length of string extracted
 *
 * \return 1 for success, 0 for fail
 */
int msgd_get_cstr(MessageDecomposer* md, char* data, unsigned int* len);

/*! extract a data block from the message 
 *
 * \param md    message decomposer object
 * \param data  data to extract from message
 * \param len   in: max length to extract, out: length of data extracted
 *
 * \return 1 for success, 0 for fail
 */
int msgd_get_data(MessageDecomposer* md, void* data, uint32_t* len);

#endif // MSG_H

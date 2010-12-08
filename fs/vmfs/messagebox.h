/*
 * Copyright 2008-2009 ARM Limited. All rights reserved.
 */

/*!
 * \file    messagebox.h
 * \brief   driver for simple messagebox device
 *
 */

/*! Defines the interface to a simple messagebox device driver
 *
 * The intention with the messagebox device is to provide a very simple
 * interface for sending and receiving packets of information to the host
 * side device. It should be possible to encapsulate all target OS locking
 * and barriers within the messagebox.
 *
 * The current implementation is very basic, supporting enough functionality
 * for the VFS blocking model to work correctly.
 *
 * \todo split the interface so that the buffer is allocated/freed separate to send/receive?
 * \todo the implementation is currently _very_basic
 *
 *  
 */

#ifndef MESSAGEBOX_H
#define MESSAGEBOX_H

/*! Opaque handle for message box operations */
typedef struct MessageBox MessageBox;

/*! Instantiate a new messagebox driver
 *
 * \param dev_base physical base address of device registers+buffer
 * \param dev_irq  irq number of device
 *
 * \return opaque message box structure for use in other calls
 */
MessageBox* mb_new(uint32_t dev_base, uint32_t dev_irq);

/*! free resources assocuated with the messagebox handle
 *
 * \param mb    messagebox handle
 */
void mb_delete(MessageBox* mb);

/*! Reserve resources for sending a message
 *
 * \param mb    messagebox handle
 * \param len   maximum length of message that will be sent
 *
 * \returns     pointer to buffer to fill with message
 */
void* mb_start(MessageBox* mb, uint32_t len);

/*! Send and release the buffer obtained with mb_start
 *
 * \param mb    messagebox handle
 * \param len   actual length of message in buffer
 *
 * \return      non-zero if a reply message is ready to be received
 */
int mb_end(MessageBox* mb, uint32_t len);

/*! Check whether receive data is available
 *
 * \param mb    messagebox handle
 *
 * \return      1 for data available. 0 for none available
 *
 * Allows drivers to poll for receive data (rather than using interrupts)
 */
int mb_ready(MessageBox* mb);

/*! Wait for receive data to become available
 *
 * \param mb    messagebox handle
 *
 * \return      0 for data available. -ve for error (e.g. -EINTR)
 *
 * This function will block until there is receive data available
 */
int mb_wait(MessageBox* mb);

/*! lock the messagebox for exclusive access by a thread
 *
 * \param mb    messagebox handle
 *
 * \return      0 for lockable, -ve for error (e.g. -EINTR)
 *
 * This function will block until the message box is free and locked,
 * or until the thread is interrupted
 */
int mb_lock(MessageBox* mb);

/*! unlock the messagebox and allow it to be used by another thread
 *
 * \param mb    messagebox handle
  */
void mb_unlock(MessageBox* mb);

/*! Receive an incoming (reply) message
 *
 * \param mb    messagebox handle
 * \param len   pointer to instance to receive length of message
 * 
 * \return      pointer to buffer containing received message
 *
 * Message data should be copied from the buffer before the call returns
 */
void* mb_receive(MessageBox* mb, uint32_t* len);

/*! Get the device configured id
 * 
 * \param mb    messagebox handle
 *
 * \return      value configured in the 'id' parameter in the lisa model
 */
uint32_t mb_id(MessageBox* mb);

#endif // MESSAGEBOX_H

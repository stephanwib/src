/*      $NetBSD: port.h,v 1.00 2022/11/08 16:57:28 stephanwib Exp $        */

/*-
 * Copyright (c) 2015 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Stephan Wiebusch.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef _SYS_PORT_H
#define _SYS_PORT_H

#include <sys/types.h>

#define PORT_MAX_NAME_LENGTH 32

enum flags {
    PORT_TIMEOUT               = 0x8,
    PORT_RELATIVE_TIMEOUT      = 0x8,
    PORT_ABSOLUTE_TIMEOUT      = 0x10
};

#ifndef _OS_H
typedef int32_t port_id;


typedef struct port_info {
	port_id     port;
	pid_t       pid;
	char	    	name[PORT_MAX_NAME_LENGTH];
	int32_t		capacity;		
	int32_t		queue_count;	/* messages in queue */
	int32_t		total_count;	/* total messages read */
} port_info;
#endif /* _OS_H */


port_id		_create_port(int32_t, const char *);
port_id		_find_port(const char *);
ssize_t		_read_port(port_id, int32_t *, void *,size_t);
ssize_t		_read_port_etc(port_id, int32_t *, void *,	size_t, uint32_t, int64_t);
int     	_write_port(port_id, int32_t, const void *, size_t);
int     	_write_port_etc(port_id, int32_t, const void *, size_t, uint32_t, int64_t);
int     	_close_port(port_id);
int     	_delete_port(port_id);
ssize_t		_port_buffer_size(port_id);
ssize_t		_port_buffer_size_etc(port_id, uint32_t,	int64_t);
int   		_port_count(port_id);
int     	_set_port_owner(port_id, pid_t);
int       _get_port_info(port_id , port_info *);
int       _get_next_port_info(pid_t, uint32_t *, port_info *);

#ifdef _KERNEL

#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/condvar.h>


enum port_state {
    KP_ACTIVE,
    KP_CLOSED,
    KP_DELETED
};


struct kport {
  LIST_ENTRY(kport)       kp_entry;        /* global list entry */
  SIMPLEQ_HEAD(, kp_msg)  kp_msgq;        /* head of message queue */
  kmutex_t                kp_interlock;   /* lock on this kport */
  kcondvar_t              kp_rdcv;        /* reader CV, wait for write event */
  kcondvar_t              kp_wrcv;        /* writer CV, wait for read event */
  port_id                 kp_id;          /* id of this port */
  pid_t                   kp_owner;       /* owner PID assigned to this port */
  char                    *kp_name;       /* name of this port */
  size_t                  kp_namelen;     /* length of name */
  int                     kp_state;       /* state of this port */
  int                     kp_nmsg;        /* number of messages in this port */
  int                     kp_total_count; /* number of messages already read */  
  int                     kp_qlen;        /* queue length */
  int                     kp_waiters;     /* count of waiters */
  uid_t                   kp_uid;         /* creator uid */
  gid_t                   kp_gid;         /* creator gid */
};

struct kp_msg {
  SIMPLEQ_ENTRY(kp_msg)   kp_msg_next;          /* message queue entry */
  int32_t                 kp_msg_code;          /* message code */
  size_t                  kp_msg_size;          /* bytes in message */
  uid_t                   kp_msg_sender_uid;    /* uid of sender */
  gid_t                   kp_msg_sender_gid;    /* gid of sender */
  pid_t                   kp_msg_sender_pid;    /* pid of sender */
  char                    *kp_msg_buffer;       /* message data */
};


/* Prototypes */
void kport_init(void);

#endif	/* _KERNEL */

#endif	/* _SYS_PORT_H_ */

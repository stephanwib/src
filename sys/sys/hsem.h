/*      $NetBSD: hsem.h,v 1.00 2023/11/18 14:57:22 stephanwib Exp $        */

/*-
 * Copyright (c) 2023 The NetBSD Foundation, Inc.
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


#ifndef _SYS_HSEM_H
#define _SYS_HSEM_H

#include <sys/types.h>

#define SEM_MAX_NAME_LENGTH NAME_MAX

enum sem_flags {
    SEM_TIMEOUT               = 0x8,
    SEM_RELATIVE_TIMEOUT      = 0x8,
    SEM_ABSOLUTE_TIMEOUT      = 0x10
};

#ifndef _OS_H
typedef int32_t sem_id;
typedef int64_t thread_id;

typedef struct sem_info {
	sem_id  		sem;
	pid_t       pid;
	char		    name[SEM_MAX_NAME_LENGTH];
	int32_t		  count;
	thread_id	  latest_holder;
} sem_info;


#endif /* _OS_H */

sem_id      _create_sem(int32_t count, const char *name);
int         _delete_sem(sem_id sem);
int         _acquire_sem(sem_id sem);
int         _acquire_sem_etc(sem_id sem, int32_t count, uint32_t flags, int64_t timeout);
int         _release_sem(sem_id sem);
int         _release_sem_etc(sem_id sem, int32_t count, uint32_t flags);
int         _get_sem_count(sem_id id, int32_t *threadCount);
int         _set_sem_owner(sem_id id, pid_t pid);
int         _get_sem_info(sem_id sem, sem_info *info);
int         _get_next_sem_info(pid_t pid, int32_t *cookie, sem_info *info);

#ifdef _KERNEL

#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/condvar.h>


struct khsem {
  //sem_id                  khs_id;                           /* id of this semaphore */
  SIMPLEQ_ENTRY(khsem)    khs_freeq_entry;                  /* free queue entry */
  LIST_ENTRY(khsem)       khs_usedq_entry;                  /* in use queue entry */
  kcondvar_t              khs_cv;                           /* CV for wait events */
  kmutex_t                khs_interlock;                    /* lock on this semaphore */
  pid_t                   khs_owner;                        /* owning process */
  char                    khs_name[SEM_MAX_NAME_LENGTH];    /* name of this semaphore */
  int                     khs_state;                        /* state of this port */
  int                     khs_waiters;                      /* count of waiting threads */
  int32_t                 khs_count;                        /* current semaphore value  */  
  lwpid_t                 khs_latest_holder;                /* latest holder LWP id */
  uid_t                   khs_uid;                          /* creator uid */
  gid_t                   khs_gid;                          /* creator gid */
};

enum sem_state {
    KHS_FREE = 0,
    KHS_IN_USE,
    KHS_DELETED
};


/* Prototypes */
int khsem_init(void);

#endif	/* _KERNEL */

#endif	/* _SYS_HSEM_H */

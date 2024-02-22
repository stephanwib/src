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


#ifndef _SYS_AREA_H
#define _SYS_AREA_H

#include <sys/types.h>

#define AREA_MAX_NAME_LENGTH NAME_MAX


#ifndef _OS_H
typedef int32_t area_id;
#endif /* _OS_H */


/* locking options */
#define AREA_NO_LOCK			0
#define AREA_LAZY_LOCK			1
#define AREA_FULL_LOCK			2
#define AREA_CONTIGUOUS			3

/* mapping options */
#define AREA_ANY_ADDRESS		0
#define AREA_EXACT_ADDRESS		1
#define AREA_BASE_ADDRESS		2
#define AREA_CLONE_ADDRESS		3
#define	AREA_ANY_KERNEL_ADDRESS		4
#define AREA_RANDOMIZED_ANY_ADDRESS	6
#define AREA_RANDOMIZED_BASE_ADDRESS	7

/* page protection */
#define AREA_READ_AREA			(1 << 0)
#define AREA_WRITE_AREA			(1 << 1)
#define AREA_EXECUTE_AREA		(1 << 2)
#define AREA_STACK_AREA			(1 << 3)
#define AREA_CLONEABLE_AREA		(1 << 8)

typedef struct area_info {
	area_id		area;
	char		name[AREA_MAX_NAME_LENGTH];
	size_t		size;
	uint32_t	lock;
	uint32_t	protection;
	pid_t		pid;
	uint32_t	ram_size;
	uint32_t	copy_count;
	uint32_t	in_count;
	uint32_t	out_count;
	void		*address;
} area_info;


area_id		_create_area(const char *name, void **startAddress,
						uint32_t addressSpec, size_t size, uint32_t lock,
						uint32_t protection);
area_id		_clone_area(const char *name, void **destAddress,
						uint32_t addressSpec, uint32_t protection, area_id source);
area_id		_find_area(const char *name);
area_id		_area_for(void *address);
int 		_delete_area(area_id id);
int 		_resize_area(area_id id, size_t newSize);
int 		_set_area_protection(area_id id, uint32_t newProtection);
status_t	_get_area_info(area_id id, area_info *areaInfo, size_t size);
status_t	_get_next_area_info(pid_t pid, ssize_t *cookie,	area_info *areaInfo,
                                size_t size);


#ifdef _KERNEL

#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/condvar.h>


struct karea {
  area_id                 ka_id;                           /* area identifier */
  LIST_ENTRY(karea)       ka_entry;                        /* global list entry */
  vaddr_t                 ka_va;                           /* adress mapped */
  size_t                  ka_size;                         /* area space */
  uint32_t                ka_lock;                         /* flags for wiring, continuity, ... */
  uint32_t                ka_protection;                   /* page protection flags */
  pid_t                   ka_owner;                        /* owning process */
  char                    ka_name[AREA_MAX_NAME_LENGTH];   /* name of this area */
  uid_t                   ka_uid;                          /* creator uid */
  gid_t                   ka_gid;                          /* creator gid */
  struct uvm_object       *ka_uobj;                        /* backing UVM object */
};


/* Prototypes */
int area_init(void);

#endif	/* _KERNEL */

#endif	/* _SYS_AREA_H_ */

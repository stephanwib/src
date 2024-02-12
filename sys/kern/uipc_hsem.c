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



#include <sys/param.h>
// #include <sys/syscall.h>
#include <sys/syscallargs.h>
#include <uvm/uvm.h>
#include <sys/proc.h>
#include <sys/hsem.h>
#include <sys/kmem.h>
#include <sys/kauth.h>


// Helper function to implement semaphore syscalls


const int khsem_max = 8192;

static kmutex_t                 khsem_mutex               __cacheline_aligned;
static struct khsem             *hsems                    __read_mostly;
static SIMPLEQ_HEAD(, khsem)    khsem_freeq               __cacheline_aligned;
static LIST_HEAD(, khsem)       khsem_used_list           __cacheline_aligned;


#define PTR_TO_ID(x) (x - hsems)

int
khsem_init(void) 
{
    int i, sz;
    vaddr_t v;

    SIMPLEQ_INIT(&khsem_freeq);
    LIST_INIT(&khsem_used_list);
    mutex_init(&khsem_mutex, MUTEX_DEFAULT, IPL_NONE);

    sz = ALIGN(khsem_max * sizeof(struct khsem));
    sz = round_page(sz);

    v = uvm_km_alloc(kernel_map, sz, 0, UVM_KMF_WIRED|UVM_KMF_ZERO);
	if (v == 0) {
		printf("hsem: cannot allocate memory");
		return ENOMEM;
	}

    for (i = 0; i < khsem_max; i++) {
        cv_init(&hsems[i].khs_cv, "acquire_sem");
        mutex_init(&hsems[i].khs_interlock, MUTEX_DEFAULT, IPL_NONE);
	    hsems[i].khs_state = KHS_FREE;
        SIMPLEQ_INSERT_TAIL(&khsem_freeq, &hsems[i], khs_freeq_entry);
    }

}


static void
khsem_free(struct khsem *khs) {

    struct khsem *khs_this;
    struct khsem *khs_next;

    KASSERT(mutex_owned(&khs->khs_interlock));
    KASSERT(khs->khs_state == KHS_DELETED);

    mutex_enter(&khsem_mutex);
    LIST_FOREACH_SAFE(khs_this, &khsem_used_list, khs_usedq_entry, khs_next) {
        if (khs_this == khs) {
            LIST_REMOVE(khs_this, khs_usedq_entry);
        }
    }

    SIMPLEQ_INSERT_TAIL(&khsem_freeq, khs, khs_freeq_entry);
    mutex_exit(&khsem_mutex);

    khs->khs_state = KHS_FREE;
    mutex_exit(&khs->khs_interlock);
}

static struct khsem *
khsem_lookup_byid(sem_id id) {

    if (id < 0 || id >= khsem_max)
        return NULL;

    mutex_enter(&hsems[id].khs_interlock);

    return &hsems[id];
}

static void
fill_hsem_info(const struct khsem *khs, struct sem_info *info)
{
    *info = (struct sem_info) {
        .sem = PTR_TO_ID(khs),
        .pid = khs->khs_owner,
        .count = khs->khs_count,
        .latest_holder = khs->khs_latest_holder
    };

    (void)strlcpy(info->name, khs->khs_name, SEM_MAX_NAME_LENGTH);
}

static int 
khsem_acquire(struct lwp *l, sem_id id, int32_t count, uint32_t flags, int64_t timeout) {

    int error, t;
    struct khsem *khs;
    
    
    if ((flags & (SEM_RELATIVE_TIMEOUT | SEM_ABSOLUTE_TIMEOUT)) == (SEM_RELATIVE_TIMEOUT | SEM_ABSOLUTE_TIMEOUT))
        return EINVAL;

    if ((flags & SEM_ABSOLUTE_TIMEOUT) && timeout < 0)
        return ETIMEDOUT;
    
    khs = khsem_lookup_byid(id);
    if (khs == NULL)
        return ENOENT;
    
    if (khs->khs_state != KHS_IN_USE)
    {
        mutex_exit(&khs->khs_interlock);
        return ENOENT;
    }

    if (khs->khs_count - count <= 0)
    {
        if (flags & SEM_RELATIVE_TIMEOUT && timeout == 0)
        {
            mutex_exit(&khs->khs_interlock);
            return EAGAIN;
        }

        t = (flags & SEM_TIMEOUT) ? timeout : 0;

        do
        {
            khs->khs_waiters++;
            error = cv_timedwait_sig(&khs->khs_cv, &khs->khs_interlock, mstohz(t));
            khs->khs_waiters--;

            if (khs->khs_state == KHS_DELETED)
            {
                if (khs->khs_waiters == 0)
                    khsem_free(khs);
                else
                    mutex_exit(&khs->khs_interlock);

                return ENOENT;
            }

            if (error)
            {
                if (error == EWOULDBLOCK)
                    error = ETIMEDOUT;

                mutex_exit(&khs->khs_interlock);
                return error;
            }

        } while (khs->khs_count - count <= 0);

        khs->khs_latest_holder = l->l_lid;
        khs->khs_count -= count;
        
        mutex_exit(&khs->khs_interlock);
        return 0;
    }

}

static int 
khsem_release(sem_id id, int32_t count, uint32_t flags) {

    struct khsem *khs;
    
    /* The original implementation has a "do not rescedule" flag, which we do not support */
    (void)flags;

    khs = khsem_lookup_byid(id);
    if (khs == NULL)
        return ENOENT;
    
    if (khs->khs_state != KHS_IN_USE)
    {
        mutex_exit(&khs->khs_interlock);
        return ENOENT;
    }

    khs->khs_count += count;

    if (khs->khs_waiters)
        cv_signal(&khs->khs_cv);

}

// _create_sem syscall
int sys__create_sem(struct lwp *l, const struct sys__create_sem_args *uap, register_t *retval)
{
    /* {
        syscallarg(int32_t) count;
        syscallarg(const char *) name;
    } */

    int error;
    size_t namelen;
    int32_t count = SCARG(uap, count);
    const char *name = SCARG(uap, name);
    char namebuf[SEM_MAX_NAME_LENGTH];
    kauth_cred_t uc;
    struct khsem *khs;

    error = copyinstr(name, namebuf, sizeof(namebuf), &namelen);
    if (error)
        return error;

    mutex_enter(&khsem_mutex);

    if (__predict_false(SIMPLEQ_EMPTY(&khsem_freeq))) {
        mutex_exit(&khsem_mutex);
        return ENOSPC;
    }

    khs = SIMPLEQ_FIRST(&khsem_freeq);
    SIMPLEQ_REMOVE_HEAD(&khsem_freeq, khs_freeq_entry);
    LIST_INSERT_HEAD(&khsem_used_list, khs, khs_usedq_entry);
    mutex_enter(&khs->khs_interlock);
    mutex_exit(&khsem_mutex);

    uc = l->l_cred;

    *khs = (struct khsem) {
        .khs_state = KHS_IN_USE,
        .khs_count = count,
        .khs_owner = l->l_proc->p_pid,
        .khs_uid = kauth_cred_geteuid(uc);
        .khs_gid = kauth_cred_getegid(uc);
    };
    
    mutex_exit(&khs->khs_interlock);

    *retval = PTR_TO_ID(khs);

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _delete_sem syscall
int sys__delete_sem(struct lwp *l, const struct sys__delete_sem_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) sem;
    } */

    struct khsem *khs;
    sem_id id = SCARG(uap, sem);

    khs = khsem_lookup_byid(id);
    if (khs == NULL)
        return ENOENT;
    
    if (khs->khs_state != KHS_IN_USE) {
        mutex_exit(&khs->khs_interlock);
        return ENOENT;
    }

    /* Only the owning process may delete a semaphore */
    if (khs->khs_owner != l->l_proc->p_pid)
    {
        mutex_exit(&khs->khs_interlock);
        return EPERM;
    }

    khs->khs_state = KHS_DELETED;
    if (khs->khs_waiters)
        cv_broadcast(&khs->khs_cv);
    else
        khsem_free(khs);

    *retval = 0;

    return 0;
}

// _acquire_sem syscall
int sys__acquire_sem(struct lwp *l, const struct sys__acquire_sem_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) sem;
    } */

    int error;
    sem_id sem = SCARG(uap, sem);

    error = khsem_acquire(l, sem, 1, 0, 0);


    // Implement semaphore acquisition logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _acquire_sem_etc syscall
int sys__acquire_sem_etc(struct lwp *l, const struct sys__acquire_sem_etc_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) sem;
        syscallarg(int32_t) count;
        syscallarg(uint32_t) flags;
        syscallarg(int64_t) timeout;
    } */

    int error;
    sem_id sem = SCARG(uap, sem);
    int32_t count = SCARG(uap, count);
    uint32_t flags = SCARG(uap, flags);
    int64_t timeout = SCARG(uap, timeout);

    error = khsem_acquire(l, sem, count, flags, timeout);

    // Implement extended semaphore acquisition logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _release_sem syscall
int sys__release_sem(struct lwp *l, const struct sys__release_sem_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) sem;
    } */

    int error;
    sem_id sem = SCARG(uap, sem);

    error = khsem_release(sem, 1, 0);

    // Implement semaphore release logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _release_sem_etc syscall
int sys__release_sem_etc(struct lwp *l, const struct sys__release_sem_etc_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) sem;
        syscallarg(int32_t) count;
        syscallarg(uint32_t) flags;
    } */

    int error;
    sem_id sem = SCARG(uap, sem);
    int32_t count = SCARG(uap, count);
    uint32_t flags = SCARG(uap, flags);

    error = khsem_release(sem, count, flags);

    // Implement extended semaphore release logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _get_sem_count syscall
int sys__get_sem_count(struct lwp *l, const struct sys__get_sem_count_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) id;
        syscallarg(int32_t *) threadCount;
    } */

    sem_id id = SCARG(uap, id);
    int32_t *threadCount = SCARG(uap, threadCount);

    // Implement getting semaphore count logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _set_sem_owner syscall
int sys__set_sem_owner(struct lwp *l, const struct sys__set_sem_owner_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) id;
        syscallarg(pid_t) pid;
    } */

    sem_id id = SCARG(uap, id);
    pid_t pid = SCARG(uap, pid);

    // Implement setting semaphore owner logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _get_sem_info syscall
int sys__get_sem_info(struct lwp *l, const struct sys__get_sem_info_args *uap, register_t *retval)
{
    /* {
        syscallarg(sem_id) sem;
        syscallarg(struct sem_info *) info;
    } */

    sem_id sem = SCARG(uap, sem);
    struct sem_info *info = SCARG(uap, info);

    // Implement getting semaphore information logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

// _get_next_sem_info syscall
int sys__get_next_sem_info(struct lwp *l, const struct sys__get_next_sem_info_args *uap, register_t *retval)
{
    /* {
        syscallarg(pid_t) pid;
        syscallarg(int32_t *) cookie;
        syscallarg(struct sem_info *) info;
    } */

    pid_t pid = SCARG(uap, pid);
    int32_t *cookie = SCARG(uap, cookie);
    struct sem_info *info = SCARG(uap, info);

    // Implement getting next semaphore information logic here

    // Set the return value if necessary
    // *retval = <your_return_value>;

    return 0;  // Return 0 on success, or an appropriate error code on failure
}

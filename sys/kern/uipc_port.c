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


#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/port.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/syscallargs.h>

/* For reference, not implemented (yet) 

static const size_t PORT_INITIAL_BUF_SIZE = 4 * 1024 * 1024;
static const size_t PORT_TOTAL_SPACE_LIMIT = 64 * 1024 * 1024;
static const size_t PORT_PROC_SPACE_LIMIT = 8 * 1024 * 1024;
static const size_t PORT_BUFFER_GROW_RATE = 4 * 1024 * 1024;

*/

#define PORT_MAX 4096
#define PORT_MAX_QUEUE_LENGTH 4096
#define PORT_MAX_MESSAGE_SIZE (256 * 1024)

static int port_max = PORT_MAX;
static int nports = 0;
static port_id port_next_id = 1;
static kmutex_t kport_mutex; /* XXX: better use reader/writer lock? */

LIST_HEAD(kport_list, kport);
static struct kport_list kport_head = LIST_HEAD_INITIALIZER(&kport_head);

/* for exithook_establish() */
void *eh_cookie;
static void eh_handler(struct proc *p, void *v);


void kport_init(void)
{
    mutex_init(&kport_mutex, MUTEX_DEFAULT, IPL_NONE);

    eh_cookie = exithook_establish(eh_handler, NULL);
}

    /*  helper functions  */

static struct kport *
kport_lookup_byid(port_id id)
{
    struct kport *kp;

    KASSERT(mutex_owned(&kport_mutex));
    LIST_FOREACH(kp, &kport_head, kp_entry)
    {
        if (kp->kp_id == id)
        {
            mutex_enter(&kp->kp_interlock);
            return kp;
        }
    }
    return NULL;
}

static struct kport *
kport_lookup_byname(const char *name)
{
    struct kport *kp;

    KASSERT(mutex_owned(&kport_mutex));
    LIST_FOREACH(kp, &kport_head, kp_entry)
    {
        if (strcmp(kp->kp_name, name) == 0)
        {
            mutex_enter(&kp->kp_interlock);
            return kp;
        }
    }
    return NULL;
}

static void
fill_port_info(const struct kport *kp, struct port_info *info)
{
    *info = (struct port_info){
        .port = kp->kp_id,
        .pid = kp->kp_owner,
        .capacity = kp->kp_qlen,
        .queue_count = kp->kp_nmsg,
        .total_count = kp->kp_total_count,
    };
    (void)strlcpy(info->name, kp->kp_name, PORT_MAX_NAME_LENGTH);
}


    /* syscall implementation functions */

static int
kport_create(struct lwp *l, const int32_t queue_length, const char *name, port_id *val)
{
    struct kport *ret;
    struct kport *search;
    kauth_cred_t uc;
    int error;
    size_t namelen = 0;
    char namebuf[PORT_MAX_NAME_LENGTH];

    if (queue_length < 1 || queue_length > PORT_MAX_QUEUE_LENGTH)
        return EINVAL;

    if (name != NULL) {
        error = copyinstr(name, namebuf, sizeof(namebuf), &namelen);
        if (error)
            return error;
    }
    
    uc = l->l_cred;

    ret = kmem_alloc(sizeof(*ret), KM_SLEEP);
    
    *ret = (struct kport) {
        .kp_uid = kauth_cred_geteuid(uc),
        .kp_gid = kauth_cred_getegid(uc),
        .kp_owner = l->l_proc->p_pid,
        .kp_state = KP_ACTIVE,
        .kp_nmsg = 0,
        .kp_qlen = queue_length,
        .kp_waiters = 0,
    };
    
    strlcpy(ret->kp_name,
            (namelen == 0) ? "unnamed port" : namebuf,
            sizeof(ret->kp_name));
    
    SIMPLEQ_INIT(&ret->kp_msgq);
    mutex_init(&ret->kp_interlock, MUTEX_DEFAULT, IPL_NONE);
    cv_init(&ret->kp_rdcv, "port_read");
    cv_init(&ret->kp_wrcv, "port_write");

    mutex_enter(&kport_mutex);

    if (__predict_false(nports >= port_max))
    {
        mutex_exit(&kport_mutex);
        kmem_free(ret, sizeof(*ret));

        return ENFILE;
    }

 
    while (__predict_false((search = kport_lookup_byid(port_next_id)) != NULL))
    {
        KASSERT(mutex_owned(&search->kp_interlock));
        mutex_exit(&search->kp_interlock);
        port_next_id++;
    }

    ret->kp_id = port_next_id;
    
    nports++;

    port_next_id++;
    /* Do not issue a negative port id */
    if (port_next_id < 0)
        port_next_id = 1;

    LIST_INSERT_HEAD(&kport_head, ret, kp_entry);

    mutex_exit(&kport_mutex);

    *val = ret->kp_id;

    return 0;

}

static int
kport_close(port_id id)
{
    struct kport *port;

    mutex_enter(&kport_mutex);
    port = kport_lookup_byid(id);
    mutex_exit(&kport_mutex);

    if (port == NULL)
        return ENOENT;
    
    port->kp_state = KP_CLOSED;

    if (port->kp_waiters > 0)
    {
        cv_broadcast(&port->kp_rdcv);
        cv_broadcast(&port->kp_wrcv);
    }

    mutex_exit(&port->kp_interlock);

    return 0;
}


/* Must be called with port mutex held. */
static int
kport_delete_physical(struct kport *port)
{
    struct kp_msg *msg;

    KASSERT(mutex_owned(&port->kp_interlock));

    KASSERT(!cv_has_waiters(&port->kp_rdcv));
    KASSERT(!cv_has_waiters(&port->kp_wrcv));
    cv_destroy(&port->kp_rdcv);
    cv_destroy(&port->kp_wrcv);

    while (port->kp_nmsg)   /* get rid of eventually outstanding messages */
    {
        KASSERT(!SIMPLEQ_EMPTY(&port->kp_msgq));
        
        msg = SIMPLEQ_FIRST(&port->kp_msgq);
        SIMPLEQ_REMOVE_HEAD(&port->kp_msgq, kp_msg_next);

        if (msg->kp_msg_size)
            kmem_free(msg->kp_msg_buffer, msg->kp_msg_size);

        kmem_free(msg, sizeof(*msg));
        
        port->kp_nmsg--;
    }
 
    mutex_exit(&port->kp_interlock);
    mutex_destroy(&port->kp_interlock);
    
    kmem_free(port, sizeof(*port));

    return 0;
}



static int
kport_delete_logical(struct kport *port)
{
 
    KASSERT(mutex_owned(&port->kp_interlock));

    if (port->kp_waiters > 0)
    {
        port->kp_state = KP_DELETED;
        cv_broadcast(&port->kp_rdcv);
        cv_broadcast(&port->kp_wrcv);
        mutex_exit(&port->kp_interlock);
    }
    else
    {
        kport_delete_physical(port);
    }
    
    return 0;
}

static int
kport_find(const char *name, port_id *id)
{
    struct kport *port;
    char namebuf[PORT_MAX_NAME_LENGTH];
    size_t namelen;
    int error;

    error = copyinstr(name, namebuf, sizeof(namebuf), &namelen);
    if (error)
        return error;

    mutex_enter(&kport_mutex);
    port = kport_lookup_byname(namebuf);
    mutex_exit(&kport_mutex);

    if (port == NULL)
        return ENOENT;

    *id = port->kp_id;
    mutex_exit(&port->kp_interlock);

    return 0;
}

static int
kport_get_info(port_id id, struct port_info *p_info_user)
{
    struct kport *port;
    struct port_info p_info_kernel;
    int error;

    mutex_enter(&kport_mutex);
    port = kport_lookup_byid(id);
    mutex_exit(&kport_mutex);

    if (port == NULL)
        return ENOENT;
    
    fill_port_info(port, &p_info_kernel);
    mutex_exit(&port->kp_interlock);

    error = copyout(&p_info_kernel, p_info_user, sizeof(struct port_info));

    return error;
}

static int
kport_get_next_info(pid_t pid, uint32_t *_cookie, struct port_info *p_info_user)
{
    struct kport *kp;
    struct port_info p_info_kernel;
    int error;
    uint32_t skip, cookie;
   
    error = copyin(_cookie, &skip, sizeof(uint32_t));
    if (error)
        return error;

    cookie = skip;  /* Keep the initial cookie state, will be incremented for the next run */

    mutex_enter(&kport_mutex);
   
    LIST_FOREACH(kp, &kport_head, kp_entry)
    {
        if (kp->kp_owner == pid)
        {
            if (skip == 0)
            {
                mutex_enter(&kp->kp_interlock);
                mutex_exit(&kport_mutex);
                fill_port_info(kp, &p_info_kernel);
                mutex_exit(&kp->kp_interlock);
                
                error = copyout(&p_info_kernel, p_info_user, sizeof(struct port_info));
                if (error)
                    return error;

                cookie++;
                error = copyout(&cookie, _cookie, sizeof(uint32_t));
                if (error)
                    return error;

                return 0;
            }
            else
            {
                skip--;
            }
        }
    }

    /* Nothing found */

    mutex_exit(&kport_mutex);

    return ENOENT;
    
}

static int
kport_count(port_id id, int *count)
{
    struct kport *port;

    mutex_enter(&kport_mutex);
    port = kport_lookup_byid(id);
    mutex_exit(&kport_mutex);

    if (port == NULL)
        return ENOENT;
 
    *count = port->kp_nmsg;
    mutex_exit(&port->kp_interlock);

    return 0;
}

static int
kport_read_etc(struct lwp *l, port_id id, int32_t *code, void *data, size_t size, uint32_t flags, int64_t timeout, ssize_t *bytes_read, bool peek_only)
{
    struct kport *port;
    struct kp_msg *msg;
    // kauth_cred_t uc;
    int error, copyout_size, t;

    // uc = l->l_cred;

    mutex_enter(&kport_mutex);
    port = kport_lookup_byid(id);
    mutex_exit(&kport_mutex);
    
    if (port == NULL)
        return ENOENT;
    
    if ((port->kp_state == KP_DELETED) ||
        (port->kp_state == KP_CLOSED && port->kp_nmsg == 0)) /* A closed port will never get new messages */
    {
        mutex_exit(&port->kp_interlock);
        return ENOENT;
    }

    if (port->kp_nmsg == 0)
    {
        if ((flags & PORT_TIMEOUT) && (timeout == 0))
        {
            mutex_exit(&port->kp_interlock);
            return EAGAIN;
        }
        else
        {
            t = (flags & PORT_TIMEOUT) ? timeout : 0;
            
            while (port->kp_nmsg == 0) {
                port->kp_waiters++;
                error = cv_timedwait_sig(&port->kp_rdcv, &port->kp_interlock, mstohz(t));
                port->kp_waiters--;
                
                if ((port->kp_state == KP_DELETED)) /* port has been logically destroyed */
                {
                    if (port->kp_waiters == 0) /* we are the last waiter */
                        kport_delete_physical(port);
                    else
                        mutex_exit(&port->kp_interlock);
                    
                    return ENOENT;
                }

                if (port->kp_state == KP_CLOSED && port->kp_nmsg == 0)
                {
                    mutex_exit(&port->kp_interlock);

                    return ENOENT;
                }

                if (error)
                {
                    if (error == EWOULDBLOCK)
                        error = ETIMEDOUT;

                    mutex_exit(&port->kp_interlock);
                    return error;
                }
            }
        }
    }

    msg = SIMPLEQ_FIRST(&port->kp_msgq);

    if (peek_only)
    {
        *bytes_read = msg->kp_msg_size;
        mutex_exit(&port->kp_interlock);
        return 0;
    }

    error = copyout(&msg->kp_msg_code, code, sizeof(*code));
    if (error)
    {
        mutex_exit(&port->kp_interlock);
        return error;
    }

    copyout_size = MIN(msg->kp_msg_size, size);
    if (copyout_size) /* message can have zero size or caller provided a zero-size buffer */
    {
        error = copyout(msg->kp_msg_buffer, data, copyout_size);
        if (error)
        {
            mutex_exit(&port->kp_interlock);
            return error;
        }
    }

    SIMPLEQ_REMOVE_HEAD(&port->kp_msgq, kp_msg_next);

    if (msg->kp_msg_size)
        kmem_free(msg->kp_msg_buffer, msg->kp_msg_size);

    kmem_free(msg, sizeof(*msg));
    
    port->kp_nmsg--;
    port->kp_total_count++;
    cv_signal(&port->kp_wrcv);
    mutex_exit(&port->kp_interlock);

    *bytes_read = copyout_size;

    return 0;
}

static int
kport_set_owner(port_id id, pid_t new_pid)
{
    struct kport *port;
    struct proc *new_proc;

    mutex_enter(&kport_mutex);
    port = kport_lookup_byid(id);
    mutex_exit(&kport_mutex);
    
    if (port == NULL)
        return ENOENT;
    
    if (port->kp_owner == new_pid)
    {
        mutex_exit(&port->kp_interlock);
        return 0;
    }

    mutex_enter(&proc_lock);
    new_proc = proc_find(new_pid);

    if (!new_proc)
    {
        mutex_exit(&proc_lock);
        mutex_exit(&port->kp_interlock);

        return ESRCH;
    }

    /* Everything is valid, change ownership */

    port->kp_owner = new_pid;

    mutex_exit(&proc_lock);
    mutex_exit(&port->kp_interlock);

    return 0;
}


static int
kport_write_etc(struct lwp *l, port_id id, int32_t code, void *data, size_t size, uint32_t flags, int64_t timeout)
{
    struct kport *port;
    struct kp_msg *msg;
    kauth_cred_t uc;
    int error, t;

    uc = l->l_cred;

    mutex_enter(&kport_mutex);
    port = kport_lookup_byid(id);
    mutex_exit(&kport_mutex);

    if (port == NULL)
        return ENOENT;
    
    if (port->kp_state != KP_ACTIVE)
    {
        mutex_exit(&port->kp_interlock);
        return ENOENT;
    }

    if (size > PORT_MAX_MESSAGE_SIZE)
    {
        mutex_exit(&port->kp_interlock);
        return EMSGSIZE;
    }
    
    if (port->kp_nmsg >= port->kp_qlen)
    {
        if ((flags & PORT_TIMEOUT) && (timeout == 0))
        {
            mutex_exit(&port->kp_interlock);
            return EAGAIN;
        }
        else
        {
            t = (flags & PORT_TIMEOUT) ? timeout : 0;

            while (port->kp_nmsg >= port->kp_qlen) {
                port->kp_waiters++;
                error = cv_timedwait_sig(&port->kp_wrcv, &port->kp_interlock, mstohz(t));
                port->kp_waiters--;

                if ((port->kp_state == KP_DELETED)) /* port has been logically destroyed */
                {
                    if (port->kp_waiters == 0) /* we are the last waiter */
                        kport_delete_physical(port);
                    else
                        mutex_exit(&port->kp_interlock);
                    
                    return ENOENT;
                }

                if (port->kp_state != KP_ACTIVE)
                    error = ENOENT;

                if (error)
                {
                    mutex_exit(&port->kp_interlock);
                    return error;
                }
            }
        }
    }

    msg = kmem_alloc(sizeof(*msg), KM_SLEEP);
    *msg = (struct kp_msg){
        .kp_msg_code = code,
        .kp_msg_size = size,
        .kp_msg_sender_uid = kauth_cred_geteuid(uc),
        .kp_msg_sender_gid = kauth_cred_getegid(uc),
        .kp_msg_sender_pid = l->l_proc->p_pid,
    };
    
    if (size)
    {
        msg->kp_msg_buffer = kmem_alloc(size, KM_SLEEP);

        error = copyin(data, msg->kp_msg_buffer, size);
        if (error)
        {
            mutex_exit(&port->kp_interlock);
            kmem_free(msg->kp_msg_buffer, size);
            kmem_free(msg, sizeof(*msg));

            return error;
        }
    }

    SIMPLEQ_INSERT_TAIL(&port->kp_msgq, msg, kp_msg_next);
    port->kp_nmsg++;
    cv_signal(&port->kp_rdcv);
    mutex_exit(&port->kp_interlock);

    return 0;
}


static void
eh_handler(struct proc *p, void *v)
{
    // printf("Exithook: %s, %d\n", p->p_path, p->p_pid);
    struct kport *kp, *kp_next;

    mutex_enter(&kport_mutex);
    
    LIST_FOREACH_SAFE(kp, &kport_head, kp_entry, kp_next)
    {
        if (kp->kp_owner == p->p_pid)
        {
            mutex_enter(&kp->kp_interlock);
            kport_delete_logical(kp);

            LIST_REMOVE(kp, kp_entry);
            nports--;
        }
    }

    mutex_exit(&kport_mutex);
}


/* syscall functions */

int sys__create_port(struct lwp *l, const struct sys__create_port_args *uap, register_t *retval)
{
    /* {
            syscallarg(int32_t) queue_length;
            syscallarg(const char *) name;
       } */

    port_id port;
    int error;

    error = kport_create(l, SCARG(uap, queue_length), SCARG(uap, name), &port);
    if (error == 0)
        *retval = port;

    return error;
}

int sys__close_port(struct lwp *l, const struct sys__close_port_args *uap, register_t *retval)
{
    /* {
             syscallarg(port_id) port;
    } */

    int error;

    error = kport_close(SCARG(uap, port));
    if (error == 0)
        *retval = error;

    return error;
}

int sys__delete_port(struct lwp *l, const struct sys__delete_port_args *uap, register_t *retval)
{
    /* {
             syscallarg(port_id) port;
    } */

    int error;
    port_id id;
    struct kport *port, *kp;

    id = SCARG(uap, port);

    mutex_enter(&kport_mutex);
    port = kport_lookup_byid(id);
    if (port == NULL)
    {
        mutex_exit(&kport_mutex);
        return ENOENT;
    }

    LIST_FOREACH(kp, &kport_head, kp_entry)
    {
        if (kp->kp_id == id)
        {
            LIST_REMOVE(kp, kp_entry);
            break;
        }
    }

    nports--;

    mutex_exit(&kport_mutex);

    error = kport_delete_logical(port);
    if (error == 0)
        *retval = 0;

    return error;
}

int sys__find_port(struct lwp *l, const struct sys__find_port_args *uap, register_t *retval)
{
    /* {
            syscallarg(const char *) port_name;
    } */

    int error, id;

    error = kport_find(SCARG(uap, port_name), &id);
    if (error == 0)
        *retval = id;

    return error;
}

int sys__get_port_info(struct lwp *l, const struct sys__get_port_info_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id)             port;
            syscallarg(struct *port_info)   info;
    } */

    int error;

    error = kport_get_info(SCARG(uap, port), SCARG(uap, info));
    if (error == 0)
        *retval = 0;
    return error;
}

int sys__get_next_port_info(struct lwp *l, const struct sys__get_next_port_info_args *uap, register_t *retval)
{
    /* {
            syscallarg(pid_t)               pid;
            syscallarg(uint32_t)            *cookie;
            syscallarg(struct *port_info)   info;
    } */

    int error;

    error = kport_get_next_info(SCARG(uap, pid), SCARG(uap, cookie), SCARG(uap, info));
    if (error == 0)
        *retval = 0;
    return error;
}


int sys__port_buffer_size(struct lwp *l, const struct sys__port_buffer_size_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id) port;
    } */

    int error;
    ssize_t size;

    //error = kport_buffer_size_etc(l, SCARG(uap, port), 0, 0, &size);
    error = kport_read_etc(l, SCARG(uap, port), NULL, NULL, 0, 0, 0, &size, 1);
    if (error == 0)
        *retval = size;

    return error;
}

int sys__port_buffer_size_etc(struct lwp *l, const struct sys__port_buffer_size_etc_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id) port;
            syscallarg(uint32_t) flags;
            syscallarg(int) timeout;
    } */

    int error;
    ssize_t size;

    //error = kport_buffer_size_etc(l, SCARG(uap, port), SCARG(uap, flags), SCARG(uap, timeout), &size);
    error = kport_read_etc(l, SCARG(uap, port), NULL, NULL, 0, SCARG(uap, flags), SCARG(uap, timeout), &size, 1);
    if (error == 0)
        *retval = size;

    return error;
}



int sys__port_count(struct lwp *l, const struct sys__port_count_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id) port;
    } */

    int error, count;

    error = kport_count(SCARG(uap, port), &count);
    if (error == 0)
        *retval = count;
    return error;
}

int sys__read_port(struct lwp *l, const struct sys__read_port_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id)     port;
            syscallarg(int32_t*)    msg_code;
            syscallarg(void*)       msg_buffer;
            syscallarg(int)         buffer_size;
    } */

    int error;
    ssize_t nread;

    error = kport_read_etc(l, SCARG(uap, port), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), 0, 0, &nread, 0);
    if (error == 0)
        *retval = nread;

    return error;
}

int sys__read_port_etc(struct lwp *l, const struct sys__read_port_etc_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id)     port;
            syscallarg(int32_t*)    msg_code;
            syscallarg(void*)       msg_buffer;
            syscallarg(size_t)      buffer_size;
            syscallarg(uint32_t)    flags;
            syscallarg(int64_t)     timeout;
    } */
    int error;
    ssize_t nread;

    error = kport_read_etc(l, SCARG(uap, port), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), SCARG(uap, flags), SCARG(uap, timeout), &nread, 0);
    if (error == 0)
        *retval = nread;

    return error;
}

int sys__set_port_owner(struct lwp *l, const struct sys__set_port_owner_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id) port;
            syscallarg(pid_t)   pid;
    } */

    int error;

    error = kport_set_owner(SCARG(uap, port), SCARG(uap, pid));
    if (error == 0)
        *retval = 0;
        
    return error;
}

int sys__write_port(struct lwp *l, const struct sys__write_port_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id) port;
            syscallarg(int32_t) msg_code;
            syscallarg(void*)   msg_buffer;
            syscallarg(size_t)  buffer_size;
    } */

    int error;

    error = kport_write_etc(l, SCARG(uap, port), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), 0, 0);
    if (error == 0)
        *retval = error;

    return error;
}

int sys__write_port_etc(struct lwp *l, const struct sys__write_port_etc_args *uap, register_t *retval)
{
    /* {
            syscallarg(port_id)     port;
            syscallarg(int32_t)     msg_code;
            syscallarg(void*)       msg_buffer;
            syscallarg(size_t)      buffer_size;
            syscallarg(uint32_t)    flags;
            syscallarg(int64_t)     timeout;
       } */
    int error;

    error = kport_write_etc(l, SCARG(uap, port), SCARG(uap, msg_code), SCARG(uap, msg_buffer), SCARG(uap, buffer_size), SCARG(uap, flags), SCARG(uap, timeout));
    if (error == 0)
        *retval = error;

    return error;
}

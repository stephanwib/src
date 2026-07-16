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

#include "OS.h"
#include "Errors.h"
#include "thread.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <lwp.h>
#include <sys/param.h>


LIST_HEAD(thr_list, haiku_thread);
pthread_once_t                          init_control           = PTHREAD_ONCE_INIT;
static struct thr_list                  thread_list            = LIST_HEAD_INITIALIZER(&thread_list);
static pthread_mutex_t                  threadss_lock          = PTHREAD_MUTEX_INITIALIZER;
lwpid_t									main_thread_lwpid;

typedef void* (*pthread_entry) (void*);
void init_main_thread(void);

/* NOTES: 
 *        - send_data()/receive_data() work in-process only, but seems to be used cross-process also.
 *        - return types of Haiku (status_t) und POSIX (void*) threads differ with potentially different storage sizes (4 vs. 8 bytes)
 */


void __attribute__ ((constructor))
init_main_thread(void)
{
	printf("libroot: init_main_thread() called\n");
    struct haiku_thread *ht;

    ht = malloc(sizeof(struct haiku_thread));
	if (ht == NULL) {
        fprintf(stderr, "FATAL: Cannot allocate memory for main thread.\n");
		return;
	}

    *ht = (struct haiku_thread) {
        .ht_pt = pthread_self(),

	    /*  Since NetBSD 10, PIDs and LWP IDs share the same name space.
         *  Hence, the PID of a process is the LWP ID of the main thread.
	     */
        .ht_lid = (lwpid_t)getpid(),

        .ht_message = THR_MSG_ABSENT,
		.ht_msg.tm_external_buffer = NULL,
        .ht_waiters = 0,
        .ht_state = THR_ACTIVE,
    };

	printf("init_main_thread: pthread_t of main lwp: %p\n", ht->ht_pt);

	main_thread_lwpid = ht->ht_lid;

    pthread_cond_init(&ht->ht_cv, NULL);

    pthread_mutex_lock(&threadss_lock);
    LIST_INSERT_HEAD(&thread_list, ht, ht_entry);
    pthread_mutex_unlock(&threadss_lock);
}

/* Returns a locked thread */
static struct haiku_thread *
find_haiku_thread_byid(thread_id id)
{
    haiku_thread *ht;

	if (id < 0)
		return NULL;

    pthread_mutex_lock(&threadss_lock);
    LIST_FOREACH(ht, &thread_list, ht_entry) {
        if (ht->ht_lid == id)
            return ht;
    }

    pthread_mutex_unlock(&threadss_lock);
    return NULL;
}

static void
free_haiku_thread(struct haiku_thread *ht)
{
    if (ht->ht_message == THR_MSG_EXTERN)
        free(ht->ht_msg.tm_external_buffer);

    pthread_cond_destroy(&ht->ht_cv);

    LIST_REMOVE(ht, ht_entry);
	
    free(ht);

    pthread_mutex_unlock(&threadss_lock);
}

thread_id
spawn_thread(thread_func func, const char *name, int32 priority, void *data)
{
    //int error;
    pthread_t thread;
    pthread_attr_t attr;
    haiku_thread *ht;
    char namebuf[NAME_MAX];
    void *func_ptr;

	/*
    error = pthread_once(&init_control, init_main_thread);
    if (error)
        return B_NO_MEMORY;
    */
	
    (void)priority;
	
    strlcpy(namebuf,
		    name == NULL ? "" : name,
		    sizeof(namebuf));

    func_ptr = (void*)func;

    pthread_attr_init(&attr);

    /* Set thread priority 
    struct sched_param schedParam;
    schedParam.sched_priority = priority;
    pthread_attr_setschedparam(&attr, &schedParam);
    */

    pthread_attr_setcreatesuspend_np(&attr);
    
	ht = malloc(sizeof(haiku_thread));
	if (ht == NULL)
		return B_NO_MEMORY;
	
    if (pthread_create(&thread, &attr, (pthread_entry)func_ptr, data) != 0) {
		free(ht);
	    return B_NO_MEMORY;
	}

    *ht = (struct haiku_thread) {
        .ht_pt = thread,
        .ht_message = THR_MSG_ABSENT,
		.ht_msg.tm_external_buffer = NULL,
        .ht_waiters = 0,
        .ht_state = THR_ACTIVE,
    };

	(void)pthread_getlwpid_np(thread, &ht->ht_lid);

    pthread_cond_init(&ht->ht_cv, NULL);

    pthread_mutex_lock(&threadss_lock);
    LIST_INSERT_HEAD(&thread_list, ht, ht_entry);
    pthread_mutex_unlock(&threadss_lock);

    pthread_attr_destroy(&attr);
 
    pthread_setname_np(thread, "%s", (void*)namebuf);

    return (thread_id)ht->ht_lid;
}

status_t
resume_thread(thread_id id)
{
    struct haiku_thread *ht;
    int error;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    if (pthread_resume_np(ht->ht_pt) == 0)
        error = B_OK;
    else
        error = B_BAD_THREAD_ID;

    pthread_mutex_unlock(&threadss_lock);
    return error;
}

status_t
suspend_thread(thread_id id)
{
    struct haiku_thread *ht;
    int error;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    if (pthread_suspend_np(ht->ht_pt) == 0)
        error = B_OK;
    else
        error = B_BAD_THREAD_ID;

    pthread_mutex_unlock(&threadss_lock);
    return error;
}

void
exit_thread(status_t status)
{

    lwpid_t self;
    struct haiku_thread *ht;

    self = _lwp_self();
    ht  = find_haiku_thread_byid((thread_id)self);
    if (ht == NULL)
        return; /* XXX should not happen */   

    if (ht->ht_waiters > 0) {
        ht->ht_state = THR_ENDING;
	pthread_cond_broadcast(&ht->ht_cv);
	pthread_mutex_unlock(&threadss_lock);
    }
    else
        free_haiku_thread(ht);

    pthread_exit((void *) &status);

}

status_t
wait_for_thread(thread_id id, status_t *ret)
{
    int error;
    struct haiku_thread *ht;
	void *pt_ret = NULL;

	if (id == (thread_id)main_thread_lwpid) {
        printf("BUG: wait_for_thread() called on main thread (%d)\n", id);
		return B_BAD_THREAD_ID;
	}

	if (id == find_thread(NULL)) {
        printf("BUG: wait_for_thread() called on its own thread (%d)\n", id);
		return B_BAD_THREAD_ID;
	}
	
    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    pthread_mutex_unlock(&threadss_lock);

	

    // XXX add resume thread for compliance
	
    /* XXX: Possible race with kill_thread() ? */
    // if (pthread_join(ht->ht_pt, (void**)ret) == 0)

	if (pthread_join(ht->ht_pt, &pt_ret) == 0) {
        error = B_OK;

		// XXX Unlinke BeBook says, allow the return value to be null. This seems to match what others are doing.
		// XXX DANGER: 8 to 4 byte size conversion, this is cleary not a good solution.
		if (ret)
			*ret = (status_t)(uintptr_t)pt_ret;
	}
    else
        error = B_BAD_THREAD_ID;

    pthread_mutex_lock(&threadss_lock);
    if (ht->ht_waiters > 0) {
        ht->ht_state = THR_ENDING;
	pthread_cond_broadcast(&ht->ht_cv);
	pthread_mutex_unlock(&threadss_lock);
    }
    else
        free_haiku_thread(ht);

    return error;
}  

status_t
kill_thread(thread_id id)
{
    int error;
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;   

    if (pthread_cancel(ht->ht_pt) == 0)
        error = B_OK;
    else
	error = B_BAD_THREAD_ID;

    if (ht->ht_waiters > 0) {
        ht->ht_state = THR_ENDING;
	pthread_cond_broadcast(&ht->ht_cv);
	pthread_mutex_unlock(&threadss_lock);
    }
    else
        free_haiku_thread(ht);

    return error;
}

status_t
on_exit_thread(void (*callback)(void *), void *data)
{
    printf("Callback: %p\n", callback);
    //pthread_cleanup_push(callback, data);

    return B_OK;
}

thread_id
find_thread(const char *name)
{
    struct haiku_thread *ht;

    if (name == NULL)
        return (thread_id) _lwp_self();

    pthread_mutex_lock(&threadss_lock);
    LIST_FOREACH(ht, &thread_list, ht_entry) {
        char thread_name[NAME_MAX];
		
        pthread_getname_np(ht->ht_pt, thread_name, NAME_MAX);
        if (strcmp(thread_name, name) == 0) {
            pthread_mutex_unlock(&threadss_lock);
            return ht->ht_lid;
        }
    }

    pthread_mutex_unlock(&threadss_lock);
    return B_NAME_NOT_FOUND;
}


status_t
set_thread_priority(thread_id id, int32 priority)
{
    int error;
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL) {
        return B_BAD_THREAD_ID;
	}

    struct sched_param param;
    param.sched_priority = priority;
    if (pthread_setschedparam(ht->ht_pt, SCHED_RR, &param) == 0)
        error = B_OK;
    else {
        error = B_BAD_THREAD_ID;
	}
	
    pthread_mutex_unlock(&threadss_lock);
    return error;
}


status_t
rename_thread(thread_id id, const char *newName)
{
	int error;
    struct haiku_thread *ht;
	char namebuf[NAME_MAX];

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    strlcpy(namebuf, newName, sizeof(namebuf));
    error = pthread_setname_np(ht->ht_pt, "%s", (void*)namebuf);

    pthread_mutex_unlock(&threadss_lock);
    return error ? B_ERROR : B_OK;
}

int
send_signal(thread_id id, unsigned int signal)
{
	int error;
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL) {
        return B_BAD_THREAD_ID;
	}
	
	error = pthread_kill(ht->ht_pt, signal);

	pthread_mutex_unlock(&threadss_lock);
    return error ? B_ERROR : B_OK;
}


status_t
send_data(thread_id thread, int32 code, const void *buffer, size_t bufferSize)
{
    struct haiku_thread *ht;
    void *dest;  /* pointer to data buffer - internal or external */

    ht = find_haiku_thread_byid(thread);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    while (ht->ht_message != THR_MSG_ABSENT) {

        /* wait for the existing message to disappear */
        ht->ht_waiters++;
        pthread_cond_wait(&ht->ht_cv, &threadss_lock);
        ht->ht_waiters--;
        
        /* check if this thread was cancelled */
        if (ht->ht_state != THR_ACTIVE) {

            if (ht->ht_waiters == 0)
                free_haiku_thread(ht);
            else
                pthread_mutex_unlock(&threadss_lock);

            return B_BAD_THREAD_ID;
        }
    }

        ht->ht_msg.tm_code = code;
        ht->ht_msg.tm_size = bufferSize;
        ht->ht_msg.tm_sender = _lwp_self();

        if (bufferSize > MSG_PRIVATE_BUFFER_SIZE) {
            dest = malloc(bufferSize);
			if (dest == NULL) {
                pthread_mutex_unlock(&threadss_lock);
				return B_NO_MEMORY;
			}
            ht->ht_message = THR_MSG_EXTERN;
			ht->ht_msg.tm_external_buffer = dest;
        }
        else {
            dest = &ht->ht_msg.tm_buffer;
            ht->ht_message = THR_MSG_INTERN;
        }
        memcpy(dest, buffer, bufferSize);

    pthread_cond_broadcast(&ht->ht_cv);
    pthread_mutex_unlock(&threadss_lock);
	
    return B_OK;
}


int32_t
receive_data(thread_id *sender, void *buffer, size_t bufferSize)
{
    int32_t code;
    void *source;
    struct haiku_thread *ht;

	/*
    error = pthread_once(&init_control, init_main_thread);
    if (error)
        return B_NO_MEMORY;
    */

    ht = find_haiku_thread_byid((thread_id)_lwp_self());
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    while (ht->ht_message == THR_MSG_ABSENT) {

        /* wait for a new message to appear */
	ht->ht_waiters++;
        pthread_cond_wait(&ht->ht_cv, &threadss_lock);
	ht->ht_waiters--;
        
        /* check if this thread was cancelled */
        if (ht->ht_state != THR_ACTIVE) {

	    if (ht->ht_waiters == 0)
                free_haiku_thread(ht);
	    else
                pthread_mutex_unlock(&threadss_lock);

            return B_BAD_THREAD_ID;
        }
    }

    code = ht->ht_msg.tm_code;
    *sender = ht->ht_msg.tm_sender;

    if (buffer != NULL && bufferSize > 0) {
        
        source = (ht->ht_message == THR_MSG_INTERN) ? &ht->ht_msg.tm_buffer : ht->ht_msg.tm_external_buffer;
        memcpy(buffer, source, MIN(ht->ht_msg.tm_size, bufferSize));
    }

    if (ht->ht_message == THR_MSG_EXTERN) {
        free(ht->ht_msg.tm_external_buffer);
	    ht->ht_msg.tm_external_buffer = NULL;
	}
    
    ht->ht_message = THR_MSG_ABSENT;

    pthread_cond_broadcast(&ht->ht_cv);
    pthread_mutex_unlock(&threadss_lock);

    return code;
}


bool 
has_data(thread_id thread) {
	
    struct haiku_thread *ht;
    bool has_data;
   
    ht = find_haiku_thread_byid(thread);
    if (ht == NULL)
        return false; /* XXX: This function does not seem to allow proper error reporting */

    has_data = (ht->ht_message != THR_MSG_ABSENT);

    pthread_mutex_unlock(&threadss_lock);
	
    return has_data;
}


status_t
snooze(bigtime_t timeout) {
    
    int error;
    struct timespec ts;
    
    if (timeout == 0) {
        return 0;
    }

    ts.tv_sec = timeout / 1000000;
    ts.tv_nsec = (timeout % 1000000) * 1000;

    if (ts.tv_nsec >= 1000000000) {
        errno = EINVAL;
        return -1;
    }
        
    error = nanosleep(&ts, &ts);
    if (error == -1 && errno == EINTR)
	    return B_INTERRUPTED;

    return B_OK;
}

status_t
snooze_until(bigtime_t timeout, int timeBase)
{
    bigtime_t now;

    (void)timeBase;

    now = system_time();
	
    if (timeout <= now)
        return B_OK;

    return snooze(timeout - now);
}

status_t
snooze_etc(bigtime_t amount, int timeBase, uint32 flags)
{

	return snooze(amount);
}



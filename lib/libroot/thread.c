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
#include <pthread.h>
#include <unistd.h> /* for usleep() */
#include <string.h>
#include <errno.h>


LIST_HEAD(thr_list, haiku_thread);
static struct thr_list                  thread_list            = LIST_HEAD_INITIALIZER(&thread_list);
static pthread_mutex_t                  threadss_lock          = PTHREAD_MUTEX_INITIALIZER;

typedef void* (*pthread_entry) (void*);

lwpid_t next_lid = 0; /* HACK: Issue fake LWP IDs */


static struct haiku_thread *
find_haiku_thread_byid(thread_id id)
{
    haiku_thread *ht;

    pthread_mutex_lock(&threadss_lock);
    LIST_FOREACH(ht, &threadss_lock, ht_entry) {
        if (ht->ht_lid == id) {
            pthread_mutex_unlock(&threadss_lock);
            return ht;
        }
    }
    pthread_mutex_unlock(&threadss_lock);
    return NULL;
}

thread_id
spawn_thread(thread_func func, const char *name, int32 priority, void *data)
{
	pthread_t thread;
	pthread_attr_t attr;
	haiku_thread *ht;
	char namebuf[NAME_MAX];
	void *func_ptr;

	(void)priority;
	strlcpy(namebuf, name, sizeof(namebuf));

	func_ptr = (void*)func;

    pthread_attr_init(&attr);

    /* Set thread priority 
    struct sched_param schedParam;
    schedParam.sched_priority = priority;
    pthread_attr_setschedparam(&attr, &schedParam);
    */

    pthread_attr_setcreatesuspend_np(&attr);

    if (pthread_create(&thread, &attr, (pthread_entry)func_ptr, data) != 0)
	    return B_NO_MEMORY;

	
    ht = malloc(sizeof(haiku_thread));
    *ht = (haiku_thread) {
        .ht_pt = thread,
	    .ht_lid = next_lid++,
	    .ht_message = THR_MSG_ABSENT,
        .ht_state = THR_ACTIVE;
    };

    pthread_mutex_lock(&threadss_lock);
    LIST_INSERT_HEAD(&thread_list, ht, ht_entry);
    pthread_mutex_unlock(&threadss_lock);

    pthread_attr_destroy(&attr);
 
    pthread_setname_np(thread, "%s", (void*)namebuf);

    return (thread_id)thread;
}

status_t
resume_thread(thread_id id)
{
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

	if (pthread_resume_np(ht->ht_pt) == 0)
	    return B_OK;

    return B_BAD_THREAD_ID;
}

status_t
suspend_thread(thread_id id)
{
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

	if (pthread_suspend_np(ht->ht_pt) == 0)
	    return B_OK;

	return B_BAD_THREAD_ID;
}

void
exit_thread(status_t status)
{
	pthread_exit((void *) &status);
}

status_t
wait_for_thread(thread_id id, status_t *ret)
{
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;   
	
    if (pthread_join(ht->ht_pt, (void**)ret) == 0)
		return B_OK;
	
	return B_BAD_THREAD_ID;
}  

status_t
kill_thread(thread_id id)
{
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;   

	if (pthread_cancel(ht->ht_pt) == 0)
		return B_OK;
			
	return B_BAD_THREAD_ID;
}

status_t
on_exit_thread(void (*callback)(void *), void *data)
{
    return B_NO_MEMORY;
}

thread_id
find_thread(const char *name)
{
    struct haiku_thread *ht;

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
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    struct sched_param param;
    param.sched_priority = priority;
    if (pthread_setschedparam(ht->ht_pt, SCHED_RR, &param) == 0)
        return B_OK;

    return B_ERROR;
}


status_t
rename_thread(thread_id id, const char *newName)
{
    struct haiku_thread *ht;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;
    
	char namebuf[NAME_MAX];
	strlcpy(namebuf, newName, sizeof(namebuf));
	pthread_setname_np(ht->ht_pt, "%s", (void*)namebuf);

	return B_OK;
}

status_t
send_data(thread_id thread, int32 code, const void *buffer, size_t bufferSize)
{
    struct haiku_thread *ht;
    void *dest;

    ht = find_haiku_thread_byid(id);
    if (ht == NULL)
        return B_BAD_THREAD_ID;

    while (ht->message != THR_MSG_ABSENT) {

        /* wait for the existing message to disappear */
        pthread_cond_wait(&ht->ht_cv, &threadss_lock);
        
        /* check if this thread was cancelled */
        if (ht->ht_state != THR_ACTIVE) {
            pthread_mutex_unlock(&threadss_lock);
            return B_BAD_THREAD_ID;
        }
    }

        ht->ht_msg->tm_code = code;
        ht->ht_msg->tm_size = bufferSize;

        if (bufferSize > MSG_PRIVATE_BUFFER_SIZE) {
            dest = malloc(bufferSize);
            ht->message = THR_MSG_EXTERN;
        }
        else {
            dest = &ht->ht_msg->tm_buffer;
            ht->message = THR_MSG_INTERN;
        }
        memcpy(dest, buffer, bufferSize);

    pthread_mutex_unlock(&threadss_lock);

	return B_OK;
}


status_t
receive_data(thread_id *sender, void *buffer, size_t bufferSize)
{
	return B_BAD_THREAD_ID;
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
snooze_etc(bigtime_t amount, int timeBase, uint32 flags)
{

	return snooze(amount);
}



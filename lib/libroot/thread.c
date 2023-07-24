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

#include <OS.h>
#include <pthread.h>
#include <unistd.h> /* for usleep() */
#include <errno.h>


thread_id
spawn_thread(thread_func func, const char *name, int32 priority, void *data)
{

	return B_ERROR;
}

status_t
kill_thread(thread_id thread)
{


			if (pthread_kill(thread_table[i].pth, SIGKILL) == 0)
				return B_OK;
			
	return B_BAD_THREAD_ID;
}

status_t
rename_thread(thread_id thread, const char *newName)
{

	return B_BAD_THREAD_ID;
}


void
exit_thread(status_t status)
{
	pthread_t this_thread = pthread_self();
	
	pthread_exit((void *) &status);
}


status_t
on_exit_thread(void (*callback)(void *), void *data)
{
    return B_NO_MEMORY;
}

thread_id
find_thread(const char *name)
{

	pthread_t pt = 0;

	if (name == NULL)
		pt = pthread_self();



	return B_NAME_NOT_FOUND;
}

status_t
set_thread_priority(thread_id id, int32 priority)
{
	init_thread();

	int i;
	for (i = 0; i < MAX_THREADS; i++)
	{
		if (thread_table[i].thread == id)
		{
			thread_table[i].priority = priority;
			return B_OK;
		}
	}

	return B_BAD_THREAD_ID;
}


status_t
snooze(bigtime_t timeout)
{
	int err;
	
	err = usleep((unsigned long)timeout);

	if (err < 0 && errno == EINTR)
		return B_INTERRUPTED;

	return B_OK;
}


status_t
snooze_etc(bigtime_t amount, int timeBase, uint32 flags)
{
	// TODO: determine what timeBase and flags do
	return snooze(amount);
}


status_t
wait_for_thread(thread_id id, status_t *_returnCode)
{

		if (thread_table[i].thread == id)
		{
			if (pthread_join(thread_table[i].pth, (void**)_returnCode) == 0)
				return B_OK;
		}
	
	return B_BAD_THREAD_ID;
}


status_t
suspend_thread(thread_id id)
{

			pthread_kill(thread_table[i].pth, SIGSTOP);
	

	return B_BAD_THREAD_ID;
}


status_t
resume_thread(thread_id id)
{

					pthread_kill(thread_table[i].pth, SIGCONT);
	

	return B_BAD_THREAD_ID;
}


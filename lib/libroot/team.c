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
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


status_t 
get_team_info(team_id team, team_info *info) {

    struct kinfo_proc2 proc;
    size_t size = sizeof(proc);
    int mib[6] = {CTL_KERN, KERN_PROC2, KERN_PROC_PID, team, sizeof(proc), 1};

    if (sysctl(mib, 6, &proc, &size, NULL, 0) < 0) {
        return B_BAD_TEAM_ID; 
    }


    info->team = proc.p_pid;
    info->uid = proc.p_uid;
    info->gid = proc.p_gid;
    strncpy(info->args, proc.p_comm, sizeof(info->args) - 1);
    info->args[sizeof(info->args) - 1] = '\0'; // Ensure null termination

    return B_OK;
}


status_t 
get_next_team_info(int32_t *cookie, team_info *info) {

    static struct kinfo_proc2 *proc_list = NULL;
    static size_t proc_count = 0;
    
    if (*cookie == 0) {
        int mib[6] = {CTL_KERN, KERN_PROC2, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), 0};

        size_t size = 0;
        if (sysctl(mib, 6, NULL, &size, NULL, 0) < 0) return -1;

        proc_list = malloc(size);
        if (!proc_list) return -1;

        mib[5] = size / sizeof(struct kinfo_proc2);
        if (sysctl(mib, 6, proc_list, &size, NULL, 0) < 0) {
            free(proc_list);
            return -1;
        }
        proc_count = size / sizeof(struct kinfo_proc2);
    }

    if (*cookie >= (int32_t)proc_count) {
        free(proc_list);
        proc_list = NULL;
        proc_count = 0;
        return -1;
    }

    struct kinfo_proc2 *proc = &proc_list[*cookie];
    info->team = proc->p_pid;
    info->uid = proc->p_uid;
    info->gid = proc->p_gid;
    strncpy(info->args, proc->p_comm, sizeof(info->args) - 1);
    info->args[sizeof(info->args) - 1] = '\0';

    (*cookie)++;

    return 0;
}


status_t
kill_team(team_id team)
{
	status_t ret = B_OK;
	int err;
	 
	err = kill((pid_t)team, SIGKILL);
	if (err < 0 && errno == ESRCH)
		ret = B_BAD_TEAM_ID;

	return B_OK;
}



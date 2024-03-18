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
#include <sys/hsem.h>
#include <errno.h>

int handle_sem_error(int);


int handle_sem_error(int error_code) {
    switch (error_code) {
        case EINVAL:
            return B_BAD_VALUE;
        case ETIMEDOUT:
            return B_TIMED_OUT;
        case EAGAIN:
            return B_WOULD_BLOCK;
        case ENOMEM:
            return B_NO_MEMORY;
        case ENOSPC:
            return B_NO_MORE_SEMS;
        case ESRCH:
            return B_BAD_TEAM_ID;
        case EACCES:
            return B_PERMISSION_DENIED;
        case ENOENT:
        default:
            return B_BAD_SEM_ID;
    }
}


extern sem_id create_sem(int32 count, const char *name) {
    sem_id ret = _create_sem(count, name);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t delete_sem(sem_id id) {
    status_t ret = _delete_sem(id);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t acquire_sem(sem_id id) {
    status_t ret = _acquire_sem(id);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t acquire_sem_etc(sem_id id, int32 count, uint32 flags, bigtime_t timeout) {
    status_t ret = _acquire_sem_etc(id, count, flags, timeout);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t release_sem(sem_id id) {
    status_t ret = _release_sem(id);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t release_sem_etc(sem_id id, int32 count, uint32 flags) {
    status_t ret = _release_sem_etc(id, count, flags);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t get_sem_count(sem_id id, int32 *threadCount) {
    status_t ret = _get_sem_count(id, threadCount);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t set_sem_owner(sem_id id, team_id team) {
    status_t ret = _set_sem_owner(id, team);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t get_sem_info(sem_id id, struct sem_info *info) {
    status_t ret = _get_sem_info(id, info);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

extern status_t get_next_sem_info(team_id team, int32 *cookie, struct sem_info *info) {
    status_t ret = _get_next_sem_info(team, cookie, info);

    if (ret == -1) {
        return handle_sem_error(errno);
    } else {
        return ret;
    }
}

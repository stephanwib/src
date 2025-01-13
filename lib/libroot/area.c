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
#include <sys/area.h>
#include <errno.h>

int handle_area_error(int);


int handle_area_error(int error_code) {
    switch (error_code) {
        case EINVAL:
            return B_BAD_VALUE;
        case ENOMEM:
        case ENOSPC:
            return B_NO_MEMORY;
        case EACCES:
            return B_PERMISSION_DENIED;
        case ENOENT:
        default:
            return B_ERROR;
    }
}

extern area_id create_area(const char *name, void **startAddress,
                            uint32 addressSpec, size_t size, uint32 lock,
                            uint32 protection) {
    area_id ret = _create_area(name, startAddress, addressSpec, size, lock, protection);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern area_id clone_area(const char *name, void **destAddress,
                           uint32 addressSpec, uint32 protection, area_id source) {
    area_id ret = _clone_area(name, destAddress, addressSpec, protection, source);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern area_id find_area(const char *name) {
    area_id ret = _find_area(name);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern area_id area_for(void *address) {
    area_id ret = _area_for(address);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern int delete_area(area_id id) {
    int ret = _delete_area(id);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern int resize_area(area_id id, size_t newSize) {
    int ret = _resize_area(id, newSize);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern int set_area_protection(area_id id, uint32 newProtection) {
    int ret = _set_area_protection(id, newProtection);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern int get_area_info(area_id id, area_info *areaInfo) {
    int ret = _get_area_info(id, areaInfo);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

extern int get_next_area_info(pid_t pid, ssize_t *cookie, area_info *areaInfo) {
    int ret = _get_next_area_info(pid, cookie, areaInfo);

    if (ret == -1) {
        return handle_area_error(errno);
    } else {
        return ret;
    }
}

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
#include <sys/port.h>
#include <errno.h>

int handle_port_error(int);


int handle_port_error(int error_code) {
    switch (error_code) {
        case EINVAL:
            return B_BAD_VALUE;
        case ETIMEDOUT:
            return B_TIMED_OUT;
        case EAGAIN:
            return B_WOULD_BLOCK;
        case EINTR:
            return B_INTERRUPTED;
        case ENOENT:
        default:
            return B_BAD_PORT_ID;
    }
}


extern port_id create_port(int32 capacity, const char *name) {
    status_t ret = _create_port(capacity, name);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern status_t close_port(port_id port) {
    status_t ret = _close_port(port);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern status_t delete_port(port_id port) {
    status_t ret = _delete_port(port);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern port_id find_port(const char *port_name) {
    status_t ret = _find_port(port_name);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern status_t get_port_info(port_id port, port_info *info) {
    status_t ret = _get_port_info(port, info);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern status_t get_next_port_info(team_id pid, uint32 *cookie, port_info *info) {
    status_t ret = _get_next_port_info((pid_t)pid, cookie, info);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern ssize_t port_buffer_size(port_id port) {
    ssize_t ret = _port_buffer_size(port);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern ssize_t port_buffer_size_etc(port_id port, uint32 flags, bigtime_t timeout) {
    ssize_t ret = _port_buffer_size_etc(port, flags, timeout / 1000);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern ssize_t port_count(port_id port) {
    int ret = _port_count(port);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern ssize_t read_port(port_id port, int32 *msg_code, void *msg_buffer, size_t buffer_size) {
    ssize_t ret = _read_port(port, msg_code, msg_buffer, buffer_size);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern ssize_t read_port_etc(port_id port, int32 *msg_code, void *msg_buffer, size_t buffer_size, uint32 flags, bigtime_t timeout) {
    ssize_t ret = _read_port_etc(port, msg_code, msg_buffer, buffer_size, flags, timeout / 1000);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern status_t set_port_owner(port_id port, team_id pid) {
    status_t ret = _set_port_owner(port, (pid_t)pid);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern status_t write_port(port_id port, int32 msg_code, const void *msg_buffer, size_t buffer_size) {
    ssize_t ret = _write_port(port, msg_code, msg_buffer, buffer_size);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

extern status_t write_port_etc(port_id port, int32 msg_code, const void *msg_buffer, size_t buffer_size, uint32 flags, bigtime_t timeout) {
    ssize_t ret = _write_port_etc(port, msg_code, msg_buffer, buffer_size, flags, timeout / 1000);

    if (ret == -1) {
        return handle_port_error(errno);
    } else {
        return ret;
    }
}

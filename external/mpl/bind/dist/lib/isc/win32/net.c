/*	$NetBSD: net.c,v 1.7 2022/09/23 12:15:34 christos Exp $	*/

/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0.  If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <errno.h>
#include <unistd.h>

#include <isc/log.h>
#include <isc/net.h>
#include <isc/once.h>
#include <isc/strerr.h>
#include <isc/string.h>
#include <isc/util.h>

/*%
 * Definitions about UDP port range specification.  This is a total mess of
 * portability variants: some use sysctl (but the sysctl names vary), some use
 * system-specific interfaces, some have the same interface for IPv4 and IPv6,
 * some separate them, etc...
 */

/*%
 * The last resort defaults: use all non well known port space
 */
#ifndef ISC_NET_PORTRANGELOW
#define ISC_NET_PORTRANGELOW 32768
#endif /* ISC_NET_PORTRANGELOW */
#ifndef ISC_NET_PORTRANGEHIGH
#define ISC_NET_PORTRANGEHIGH 65535
#endif /* ISC_NET_PORTRANGEHIGH */

static isc_once_t once = ISC_ONCE_INIT;
static isc_once_t once_ipv6only = ISC_ONCE_INIT;
static isc_once_t once_ipv6pktinfo = ISC_ONCE_INIT;
static isc_result_t ipv4_result = ISC_R_NOTFOUND;
static isc_result_t ipv6_result = ISC_R_NOTFOUND;
static isc_result_t ipv6only_result = ISC_R_NOTFOUND;
static isc_result_t ipv6pktinfo_result = ISC_R_NOTFOUND;

void
InitSockets(void);

static isc_result_t
try_proto(int domain) {
	SOCKET s;
	char strbuf[ISC_STRERRORSIZE];
	int errval;

	s = socket(domain, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		errval = WSAGetLastError();
		switch (errval) {
		case WSAEAFNOSUPPORT:
		case WSAEPROTONOSUPPORT:
		case WSAEINVAL:
			return (ISC_R_NOTFOUND);
		default:
			strerror_r(errval, strbuf, sizeof(strbuf));
			UNEXPECTED_ERROR(__FILE__, __LINE__,
					 "socket() failed: %s", strbuf);
			return (ISC_R_UNEXPECTED);
		}
	}

	closesocket(s);

	return (ISC_R_SUCCESS);
}

static void
initialize_action(void) {
	InitSockets();
	ipv4_result = try_proto(PF_INET);
	ipv6_result = try_proto(PF_INET6);
}

static void
initialize(void) {
	RUNTIME_CHECK(isc_once_do(&once, initialize_action) == ISC_R_SUCCESS);
}

isc_result_t
isc_net_probeipv4(void) {
	initialize();
	return (ipv4_result);
}

isc_result_t
isc_net_probeipv6(void) {
	initialize();
	return (ipv6_result);
}

isc_result_t
isc_net_probeunix(void) {
	return (ISC_R_NOTFOUND);
}

static void
try_ipv6only(void) {
#ifdef IPV6_V6ONLY
	SOCKET s;
	int on;
	char strbuf[ISC_STRERRORSIZE];
#endif /* ifdef IPV6_V6ONLY */
	isc_result_t result;

	result = isc_net_probeipv6();
	if (result != ISC_R_SUCCESS) {
		ipv6only_result = result;
		return;
	}

#ifndef IPV6_V6ONLY
	ipv6only_result = ISC_R_NOTFOUND;
	return;
#else  /* ifndef IPV6_V6ONLY */
	/* check for TCP sockets */
	s = socket(PF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__, "socket() failed: %s",
				 strbuf);
		ipv6only_result = ISC_R_UNEXPECTED;
		return;
	}

	on = 1;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on,
		       sizeof(on)) < 0) {
		ipv6only_result = ISC_R_NOTFOUND;
		goto close;
	}

	closesocket(s);

	/* check for UDP sockets */
	s = socket(PF_INET6, SOCK_DGRAM, 0);
	if (s == INVALID_SOCKET) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__, "socket() failed: %s",
				 strbuf);
		ipv6only_result = ISC_R_UNEXPECTED;
		return;
	}

	on = 1;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on,
		       sizeof(on)) < 0) {
		ipv6only_result = ISC_R_NOTFOUND;
		goto close;
	}

	ipv6only_result = ISC_R_SUCCESS;

close:
	closesocket(s);
	return;
#endif /* IPV6_V6ONLY */
}

static void
initialize_ipv6only(void) {
	RUNTIME_CHECK(isc_once_do(&once_ipv6only, try_ipv6only) ==
		      ISC_R_SUCCESS);
}

#ifdef __notyet__
/*
 * XXXMPA requires win32/socket.c to be updated to support
 * WSASendMsg and WSARecvMsg which are themselves Winsock
 * and compiler version dependent.
 */
static void
try_ipv6pktinfo(void) {
	SOCKET s;
	int on;
	char strbuf[ISC_STRERRORSIZE];
	isc_result_t result;
	int optname;

	result = isc_net_probeipv6();
	if (result != ISC_R_SUCCESS) {
		ipv6pktinfo_result = result;
		return;
	}

	/* we only use this for UDP sockets */
	s = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET) {
		strerror_r(errno, strbuf, sizeof(strbuf));
		UNEXPECTED_ERROR(__FILE__, __LINE__, "socket() failed: %s",
				 strbuf);
		ipv6pktinfo_result = ISC_R_UNEXPECTED;
		return;
	}

#ifdef IPV6_RECVPKTINFO
	optname = IPV6_RECVPKTINFO;
#else  /* ifdef IPV6_RECVPKTINFO */
	optname = IPV6_PKTINFO;
#endif /* ifdef IPV6_RECVPKTINFO */
	on = 1;
	if (setsockopt(s, IPPROTO_IPV6, optname, (const char *)&on,
		       sizeof(on)) < 0) {
		ipv6pktinfo_result = ISC_R_NOTFOUND;
		goto close;
	}

	ipv6pktinfo_result = ISC_R_SUCCESS;

close:
	closesocket(s);
	return;
}

static void
initialize_ipv6pktinfo(void) {
	RUNTIME_CHECK(isc_once_do(&once_ipv6pktinfo, try_ipv6pktinfo) ==
		      ISC_R_SUCCESS);
}
#endif /* __notyet__ */

isc_result_t
isc_net_probe_ipv6only(void) {
	initialize_ipv6only();
	return (ipv6only_result);
}

isc_result_t
isc_net_probe_ipv6pktinfo(void) {
#ifdef __notyet__
	initialize_ipv6pktinfo();
#endif /* __notyet__ */
	return (ipv6pktinfo_result);
}

isc_result_t
isc_net_getudpportrange(int af, in_port_t *low, in_port_t *high) {
	int result = ISC_R_FAILURE;

	REQUIRE(low != NULL && high != NULL);

	UNUSED(af);

	if (result != ISC_R_SUCCESS) {
		*low = ISC_NET_PORTRANGELOW;
		*high = ISC_NET_PORTRANGEHIGH;
	}

	return (ISC_R_SUCCESS); /* we currently never fail in this function */
}

void
isc_net_disableipv4(void) {
	initialize();
	if (ipv4_result == ISC_R_SUCCESS) {
		ipv4_result = ISC_R_DISABLED;
	}
}

void
isc_net_disableipv6(void) {
	initialize();
	if (ipv6_result == ISC_R_SUCCESS) {
		ipv6_result = ISC_R_DISABLED;
	}
}

void
isc_net_enableipv4(void) {
	initialize();
	if (ipv4_result == ISC_R_DISABLED) {
		ipv4_result = ISC_R_SUCCESS;
	}
}

void
isc_net_enableipv6(void) {
	initialize();
	if (ipv6_result == ISC_R_DISABLED) {
		ipv6_result = ISC_R_SUCCESS;
	}
}

unsigned int
isc_net_probedscp(void) {
	return (0);
}

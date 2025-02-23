/*	$NetBSD: byaddr_test.c,v 1.7 2022/09/23 12:15:23 christos Exp $	*/

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

/*! \file
 */

#include <stdbool.h>
#include <stdlib.h>

#include <isc/app.h>
#include <isc/commandline.h>
#include <isc/managers.h>
#include <isc/mem.h>
#include <isc/netaddr.h>
#include <isc/print.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/byaddr.h>
#include <dns/cache.h>
#include <dns/dispatch.h>
#include <dns/events.h>
#include <dns/forward.h>
#include <dns/resolver.h>
#include <dns/result.h>
#include <dns/view.h>

static void
done(isc_task_t *task, isc_event_t *event) {
	dns_byaddrevent_t *bevent;
	dns_byaddr_t *byaddr;
	dns_name_t *name;

	REQUIRE(event->ev_type == DNS_EVENT_BYADDRDONE);
	bevent = (dns_byaddrevent_t *)event;

	UNUSED(task);

	printf("byaddr event result = %s\n", isc_result_totext(bevent->result));

	if (bevent->result == ISC_R_SUCCESS) {
		for (name = ISC_LIST_HEAD(bevent->names); name != NULL;
		     name = ISC_LIST_NEXT(name, link))
		{
			char text[DNS_NAME_FORMATSIZE];
			dns_name_format(name, text, sizeof(text));
			printf("%s\n", text);
		}
	}

	byaddr = event->ev_sender;
	dns_byaddr_destroy(&byaddr);
	isc_event_free(&event);

	isc_app_shutdown();
}

int
main(int argc, char *argv[]) {
	isc_mem_t *mctx = NULL;
	bool verbose = false;
	unsigned int workers = 2;
	isc_nm_t *netmgr = NULL;
	isc_taskmgr_t *taskmgr = NULL;
	isc_task_t *task = NULL;
	isc_timermgr_t *timermgr = NULL;
	dns_view_t *view = NULL;
	int ch;
	isc_socketmgr_t *socketmgr = NULL;
	dns_dispatchmgr_t *dispatchmgr = NULL;
	isc_netaddr_t na;
	dns_byaddr_t *byaddr = NULL;
	isc_result_t result;
	unsigned int options = 0;
	dns_cache_t *cache;

	RUNTIME_CHECK(isc_app_start() == ISC_R_SUCCESS);

	dns_result_register();

	isc_mem_create(&mctx);

	while ((ch = isc_commandline_parse(argc, argv, "nvw:")) != -1) {
		switch (ch) {
		case 'n':
			/*
			 * We only try nibbles, so do nothing for this option.
			 */
			break;
		case 'v':
			verbose = true;
			break;
		case 'w':
			workers = (unsigned int)atoi(isc_commandline_argument);
			break;
		}
	}

	if (verbose) {
		printf("%u workers\n", workers);
		printf("IPv4: %s\n", isc_result_totext(isc_net_probeipv4()));
		printf("IPv6: %s\n", isc_result_totext(isc_net_probeipv6()));
	}

	RUNTIME_CHECK(isc_managers_create(mctx, workers, 0, &netmgr,
					  &taskmgr) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_task_create(taskmgr, 0, &task) == ISC_R_SUCCESS);
	isc_task_setname(task, "byaddr", NULL);

	RUNTIME_CHECK(dns_dispatchmgr_create(mctx, &dispatchmgr) ==
		      ISC_R_SUCCESS);

	RUNTIME_CHECK(isc_timermgr_create(mctx, &timermgr) == ISC_R_SUCCESS);
	RUNTIME_CHECK(isc_socketmgr_create(mctx, &socketmgr) == ISC_R_SUCCESS);

	RUNTIME_CHECK(dns_cache_create(mctx, mctx, taskmgr, timermgr,
				       dns_rdataclass_in, "", "rbt", 0, NULL,
				       &cache) == ISC_R_SUCCESS);

	RUNTIME_CHECK(dns_view_create(mctx, dns_rdataclass_in, "default",
				      &view) == ISC_R_SUCCESS);

	{
		unsigned int attrs;
		dns_dispatch_t *disp4 = NULL;
		dns_dispatch_t *disp6 = NULL;

		if (isc_net_probeipv4() == ISC_R_SUCCESS) {
			isc_sockaddr_t any4;

			isc_sockaddr_any(&any4);

			attrs = DNS_DISPATCHATTR_IPV4 | DNS_DISPATCHATTR_UDP;
			RUNTIME_CHECK(
				dns_dispatch_getudp(dispatchmgr, socketmgr,
						    taskmgr, &any4, 512, 6,
						    1024, 17, 19, attrs, attrs,
						    &disp4) == ISC_R_SUCCESS);
			INSIST(disp4 != NULL);
		}

		if (isc_net_probeipv6() == ISC_R_SUCCESS) {
			isc_sockaddr_t any6;

			isc_sockaddr_any6(&any6);

			attrs = DNS_DISPATCHATTR_IPV6 | DNS_DISPATCHATTR_UDP;
			RUNTIME_CHECK(
				dns_dispatch_getudp(dispatchmgr, socketmgr,
						    taskmgr, &any6, 512, 6,
						    1024, 17, 19, attrs, attrs,
						    &disp6) == ISC_R_SUCCESS);
			INSIST(disp6 != NULL);
		}

		RUNTIME_CHECK(dns_view_createresolver(view, taskmgr, 10, 1,
						      socketmgr, timermgr, 0,
						      dispatchmgr, disp4,
						      disp6) == ISC_R_SUCCESS);

		if (disp4 != NULL) {
			dns_dispatch_detach(&disp4);
		}
		if (disp6 != NULL) {
			dns_dispatch_detach(&disp6);
		}
	}

	{
		struct in_addr ina;
		isc_sockaddr_t sa;
		isc_sockaddrlist_t sal;

		ISC_LIST_INIT(sal);
		ina.s_addr = inet_addr("127.0.0.1");
		isc_sockaddr_fromin(&sa, &ina, 53);
		ISC_LIST_APPEND(sal, &sa, link);

		RUNTIME_CHECK(dns_fwdtable_add(view->fwdtable, dns_rootname,
					       &sal, dns_fwdpolicy_only) ==
			      ISC_R_SUCCESS);
	}

	dns_view_setcache(view, cache, false);
	dns_view_freeze(view);

	dns_cache_detach(&cache);

	printf("address = %s\n", argv[isc_commandline_index]);
	na.family = AF_INET;
	if (inet_pton(AF_INET, argv[isc_commandline_index],
		      (char *)&na.type.in) != 1) {
		na.family = AF_INET6;
		if (inet_pton(AF_INET6, argv[isc_commandline_index],
			      (char *)&na.type.in6) != 1) {
			printf("unknown address format\n");
			exit(1);
		}
	}

	result = dns_byaddr_create(mctx, &na, view, options, task, done, NULL,
				   &byaddr);
	if (result != ISC_R_SUCCESS) {
		printf("dns_byaddr_create() returned %s\n",
		       isc_result_totext(result));
		RUNTIME_CHECK(0);
	}

	(void)isc_app_run();

	/*
	 * XXXRTH if we get a control-C before we get to isc_app_run(),
	 * we're in trouble (because we might try to destroy things before
	 * they've been created.
	 */

	dns_view_detach(&view);

	isc_task_shutdown(task);
	isc_task_detach(&task);

	dns_dispatchmgr_destroy(&dispatchmgr);

	isc_managers_destroy(&netmgr, &taskmgr);

	isc_socketmgr_destroy(&socketmgr);
	isc_timermgr_destroy(&timermgr);

	if (verbose) {
		isc_mem_stats(mctx, stdout);
	}
	isc_mem_destroy(&mctx);

	isc_app_finish();

	return (0);
}

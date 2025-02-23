/*	$NetBSD: dlz_filesystem_driver.c,v 1.7 2022/09/23 12:15:27 christos Exp $	*/

/*
 * Copyright (C) 2002 Stichting NLnet, Netherlands, stichting@nlnet.nl.
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

/*
 * Copyright (C) 1999-2001, 2016  Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifdef DLZ_FILESYSTEM
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <isc/dir.h>
#include <isc/mem.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/result.h>
#include <dns/sdlz.h>

#include <dlz/dlz_filesystem_driver.h>
#include <named/globals.h>

static dns_sdlzimplementation_t *dlz_fs = NULL;

typedef struct config_data {
	char *basedir;
	int basedirsize;
	char *datadir;
	int datadirsize;
	char *xfrdir;
	int xfrdirsize;
	int splitcnt;
	char separator;
	char pathsep;
	isc_mem_t *mctx;
} config_data_t;

typedef struct dir_entry dir_entry_t;

struct dir_entry {
	char dirpath[PATH_MAX];
	ISC_LINK(dir_entry_t) link;
};

typedef ISC_LIST(dir_entry_t) dlist_t;

/* forward reference */

static void
fs_destroy(void *driverarg, void *dbdata);

/*
 * Private methods
 */

static bool
is_safe(const char *input) {
	unsigned int i;
	unsigned int len = strlen(input);

	/* check that only allowed characters  are in the domain name */
	for (i = 0; i < len; i++) {
		/* '.' is allowed, but has special requirements */
		if (input[i] == '.') {
			/* '.' is not allowed as first char */
			if (i == 0) {
				return (false);
			}
			/* '..', two dots together is not allowed. */
			if (input[i - 1] == '.') {
				return (false);
			}
			/* '.' is not allowed as last char */
			if (i == len - 1) {
				return (false);
			}
			/* only 1 dot in ok location, continue at next char */
			continue;
		}
		/* '-' is allowed, continue at next char */
		if (input[i] == '-') {
			continue;
		}
		/* 0-9 is allowed, continue at next char */
		if (input[i] >= '0' && input[i] <= '9') {
			continue;
		}
		/* A-Z uppercase is allowed, continue at next char */
		if (input[i] >= 'A' && input[i] <= 'Z') {
			continue;
		}
		/* a-z lowercase is allowed, continue at next char */
		if (input[i] >= 'a' && input[i] <= 'z') {
			continue;
		}

		/*
		 * colon needs to be allowed for IPV6 client
		 * addresses.  Not dangerous in domain names, as not a
		 * special char.
		 */
		if (input[i] == ':') {
			continue;
		}

		/*
		 * '@' needs to be allowed for in zone data.  Not
		 * dangerous in domain names, as not a special char.
		 */
		if (input[i] == '@') {
			continue;
		}

		/*
		 * if we reach this point we have encountered a
		 * disallowed char!
		 */
		return (false);
	}
	/* everything ok. */
	return (true);
}

static void
create_path_helper(char *out, const char *in, config_data_t *cd) {
	char *tmpString;
	char *tmpPtr;
	int i;

	tmpString = isc_mem_strdup(named_g_mctx, in);

	/*
	 * don't forget is_safe guarantees '.' will NOT be the
	 * first/last char
	 */
	while ((tmpPtr = strrchr(tmpString, '.')) != NULL) {
		i = 0;
		while (tmpPtr[i + 1] != '\0') {
			if (cd->splitcnt < 1) {
				strcat(out, (char *)&tmpPtr[i + 1]);
			} else {
				strncat(out, (char *)&tmpPtr[i + 1],
					cd->splitcnt);
			}
			strncat(out, (char *)&cd->pathsep, 1);
			if (cd->splitcnt == 0) {
				break;
			}
			if (strlen((char *)&tmpPtr[i + 1]) <=
			    (unsigned int)cd->splitcnt) {
				break;
			}
			i += cd->splitcnt;
		}
		tmpPtr[0] = '\0';
	}

	/* handle the "first" label properly */
	i = 0;
	tmpPtr = tmpString;
	while (tmpPtr[i] != '\0') {
		if (cd->splitcnt < 1) {
			strcat(out, (char *)&tmpPtr[i]);
		} else {
			strncat(out, (char *)&tmpPtr[i], cd->splitcnt);
		}
		strncat(out, (char *)&cd->pathsep, 1);
		if (cd->splitcnt == 0) {
			break;
		}
		if (strlen((char *)&tmpPtr[i]) <= (unsigned int)cd->splitcnt) {
			break;
		}
		i += cd->splitcnt;
	}

	isc_mem_free(named_g_mctx, tmpString);
}

/*%
 * Checks to make sure zone and host are safe.  If safe, then
 * hashes zone and host strings to build a path.  If zone / host
 * are not safe an error is returned.
 */

static isc_result_t
create_path(const char *zone, const char *host, const char *client,
	    config_data_t *cd, char **path) {
	char *tmpPath;
	int pathsize;
	int len;
	bool isroot = false;

	/* we require a zone & cd parameter */
	REQUIRE(zone != NULL);
	REQUIRE(cd != NULL);
	/* require path to be a pointer to NULL */
	REQUIRE(path != NULL && *path == NULL);
	/*
	 * client and host may both be NULL, but they can't both be
	 * NON-NULL
	 */
	REQUIRE((host == NULL && client == NULL) ||
		(host != NULL && client == NULL) ||
		(host == NULL && client != NULL));

	/* special case for root zone */
	if (strcmp(zone, ".") == 0) {
		isroot = true;
	}

	/* if the requested zone is "unsafe", return error */
	if (!isroot && !is_safe(zone)) {
		return (ISC_R_FAILURE);
	}

	/* if host was passed, verify that it is safe */
	if (host != NULL && !is_safe(host)) {
		return (ISC_R_FAILURE);
	}

	/* if client was passed, verify that it is safe */
	if (client != NULL && !is_safe(client)) {
		return (ISC_R_FAILURE);
	}

	/* Determine how much memory the split up string will require */
	if (host != NULL) {
		len = strlen(zone) + strlen(host);
	} else if (client != NULL) {
		len = strlen(zone) + strlen(client);
	} else {
		len = strlen(zone);
	}

	/*
	 * even though datadir and xfrdir will never be in the same
	 * string we only waste a few bytes by allocating for both,
	 * and then we are safe from buffer overruns.
	 */
	pathsize = len + cd->basedirsize + cd->datadirsize + cd->xfrdirsize + 4;

	/* if we are splitting names, we will need extra space. */
	if (cd->splitcnt > 0) {
		pathsize += len / cd->splitcnt;
	}

	tmpPath = isc_mem_allocate(named_g_mctx, pathsize * sizeof(char));

	/*
	 * build path string.
	 * start out with base directory.
	 */
	strcpy(tmpPath, cd->basedir);

	/* add zone name - parsed properly */
	if (!isroot) {
		create_path_helper(tmpPath, zone, cd);
	}

	/*
	 * When neither client or host is passed we are building a
	 * path to see if a zone is supported.  We require that a zone
	 * path have the "data dir" directory contained within it so
	 * that we know this zone is really supported.  Otherwise,
	 * this zone may not really be supported because we are
	 * supporting a delagated sub zone.
	 *
	 * Example:
	 *
	 * We are supporting long.domain.com and using a splitcnt of
	 * 0.  the base dir is "/base-dir/" and the data dir is
	 * "/.datadir" We want to see if we are authoritative for
	 * domain.com.  Path /base-dir/com/domain/.datadir since
	 * /base-dir/com/domain/.datadir does not exist, we are not
	 * authoritative for the domain "domain.com".  However we are
	 * authoritative for the domain "long.domain.com" because the
	 * path /base-dir/com/domain/long/.datadir does exist!
	 */

	/* if client is passed append xfr dir, otherwise append data dir */
	if (client != NULL) {
		strcat(tmpPath, cd->xfrdir);
		strncat(tmpPath, (char *)&cd->pathsep, 1);
		strcat(tmpPath, client);
	} else {
		strcat(tmpPath, cd->datadir);
	}

	/* if host not null, add it. */
	if (host != NULL) {
		strncat(tmpPath, (char *)&cd->pathsep, 1);
		create_path_helper(tmpPath, host, cd);
	}

	/* return the path we built. */
	*path = tmpPath;

	return (ISC_R_SUCCESS);
}

static isc_result_t
process_dir(isc_dir_t *dir, void *passback, config_data_t *cd,
	    dlist_t *dir_list, unsigned int basedirlen) {
	char tmp[PATH_MAX + NAME_MAX];
	int astPos;
	struct stat sb;
	isc_result_t result = ISC_R_FAILURE;
	char *endp;
	char *type;
	char *ttlStr;
	char *data;
	char host[NAME_MAX];
	char *tmpString;
	char *tmpPtr;
	int ttl;
	int i;
	int len;
	dir_entry_t *direntry;
	bool foundHost;

	tmp[0] = '\0'; /* set 1st byte to '\0' so strcpy works right. */
	host[0] = '\0';
	foundHost = false;

	/* copy base directory name to tmp. */
	strcpy(tmp, dir->dirname);

	/* dir->dirname will always have '*' as the last char. */
	astPos = strlen(dir->dirname) - 1;

	/* if dir_list != NULL, were are performing a zone xfr */
	if (dir_list != NULL) {
		/* if splitcnt == 0, determine host from path. */
		if (cd->splitcnt == 0) {
			if (strlen(tmp) - 3 > basedirlen) {
				tmp[astPos - 1] = '\0';
				tmpString = (char *)&tmp[basedirlen + 1];
				/* handle filesystem's special wildcard "-"  */
				if (strcmp(tmpString, "-") == 0) {
					strcpy(host, "*");
				} else {
					/*
					 * not special wildcard -- normal name
					 */
					while ((tmpPtr = strrchr(
							tmpString,
							cd->pathsep)) != NULL) {
						if ((strlen(host) +
						     strlen(tmpPtr + 1) + 2) >
						    NAME_MAX) {
							continue;
						}
						strcat(host, tmpPtr + 1);
						strcat(host, ".");
						tmpPtr[0] = '\0';
					}
					if ((strlen(host) + strlen(tmpString) +
					     1) <= NAME_MAX) {
						strcat(host, tmpString);
					}
				}

				foundHost = true;
				/* set tmp again for use later */
				strcpy(tmp, dir->dirname);
			}
		} else {
			/*
			 * if splitcnt != 0 determine host from
			 * ".host" directory entry
			 */
			while (isc_dir_read(dir) == ISC_R_SUCCESS) {
				if (strncasecmp(".host", dir->entry.name, 5) ==
				    0) {
					/*
					 * handle filesystem's special
					 * wildcard "-"
					 */
					if (strcmp((char *)&dir->entry.name[6],
						   "-") == 0) {
						strlcpy(host, "*",
							sizeof(host));
					} else {
						strlcpy(host,
							(char *)&dir->entry
								.name[6],
							sizeof(host));
					}
					foundHost = true;
					break;
				}
			}
			/* reset dir list for use later */
			isc_dir_reset(dir);
		} /* end of else */
	}

	while (isc_dir_read(dir) == ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_DEBUG(1),
			      "Filesystem driver Dir name:"
			      " '%s' Dir entry: '%s'\n",
			      dir->dirname, dir->entry.name);

		/* skip any entries starting with "." */
		if (dir->entry.name[0] == '.') {
			continue;
		}

		/*
		 * get rid of '*', set to NULL.  Effectively trims
		 * string from previous loop to base directory only
		 * while still leaving memory for concat to be
		 * performed next.
		 */

		tmp[astPos] = '\0';

		/* add name to base directory name. */
		strcat(tmp, dir->entry.name);

		/* make sure we can stat entry */
		if (stat(tmp, &sb) == 0) {
			/* if entry is a directory */
			if ((sb.st_mode & S_IFDIR) != 0) {
				/*
				 * if dir list is NOT NULL, add dir to
				 * dir list
				 */
				if (dir_list != NULL) {
					direntry = isc_mem_get(
						named_g_mctx,
						sizeof(dir_entry_t));
					strcpy(direntry->dirpath, tmp);
					ISC_LINK_INIT(direntry, link);
					ISC_LIST_APPEND(*dir_list, direntry,
							link);
					result = ISC_R_SUCCESS;
				}
				continue;

				/*
				 * if entry is a file be sure we do
				 * not add entry to DNS results if we
				 * are performing a zone xfr and we
				 * could not find a host entry.
				 */
			} else if (dir_list != NULL && !foundHost) {
				continue;
			}
		} else { /* if we cannot stat entry, skip it. */
			continue;
		}

		type = dir->entry.name;
		ttlStr = strchr(type, cd->separator);
		if (ttlStr == NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "Filesystem driver: "
				      "%s could not be parsed properly",
				      tmp);
			return (ISC_R_FAILURE);
		}

		/* replace separator char with NULL to split string */
		ttlStr[0] = '\0';
		/* start string after NULL of previous string */
		ttlStr = (char *)&ttlStr[1];

		data = strchr(ttlStr, cd->separator);
		if (data == NULL) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "Filesystem driver: "
				      "%s could not be parsed properly",
				      tmp);
			return (ISC_R_FAILURE);
		}

		/* replace separator char with NULL to split string */
		data[0] = '\0';

		/* start string after NULL of previous string */
		data = (char *)&data[1];

		/* replace all cd->separator chars with a space. */
		len = strlen(data);

		for (i = 0; i < len; i++) {
			if (data[i] == cd->separator) {
				data[i] = ' ';
			}
		}

		/* convert text to int, make sure it worked right */
		ttl = strtol(ttlStr, &endp, 10);
		if (*endp != '\0' || ttl < 0) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "Filesystem driver "
				      "ttl must be a positive number");
		}

		/* pass data back to Bind */
		if (dir_list == NULL) {
			result = dns_sdlz_putrr((dns_sdlzlookup_t *)passback,
						type, ttl, data);
		} else {
			result = dns_sdlz_putnamedrr(
				(dns_sdlzallnodes_t *)passback, (char *)host,
				type, ttl, data);
		}

		/* if error, return error right away */
		if (result != ISC_R_SUCCESS) {
			return (result);
		}
	} /* end of while loop */

	return (result);
}

/*
 * SDLZ interface methods
 */

static isc_result_t
fs_allowzonexfr(void *driverarg, void *dbdata, const char *name,
		const char *client) {
	isc_result_t result;
	char *path;
	struct stat sb;
	config_data_t *cd;
	path = NULL;

	UNUSED(driverarg);

	cd = (config_data_t *)dbdata;

	if (create_path(name, NULL, client, cd, &path) != ISC_R_SUCCESS) {
		return (ISC_R_NOTFOUND);
	}

	if (stat(path, &sb) != 0) {
		result = ISC_R_NOTFOUND;
		goto complete_AXFR;
	}

	if ((sb.st_mode & S_IFREG) != 0) {
		result = ISC_R_SUCCESS;
		goto complete_AXFR;
	}

	result = ISC_R_NOTFOUND;

complete_AXFR:
	isc_mem_free(named_g_mctx, path);
	return (result);
}

static isc_result_t
fs_allnodes(const char *zone, void *driverarg, void *dbdata,
	    dns_sdlzallnodes_t *allnodes) {
	isc_result_t result;
	dlist_t *dir_list;
	config_data_t *cd;
	char *basepath;
	unsigned int basepathlen;
	struct stat sb;
	isc_dir_t dir;
	dir_entry_t *dir_entry;
	dir_entry_t *next_de;

	basepath = NULL;
	dir_list = NULL;

	UNUSED(driverarg);
	UNUSED(allnodes);

	cd = (config_data_t *)dbdata;

	/* allocate memory for list */
	dir_list = isc_mem_get(named_g_mctx, sizeof(dlist_t));

	/* initialize list */
	ISC_LIST_INIT(*dir_list);

	if (create_path(zone, NULL, NULL, cd, &basepath) != ISC_R_SUCCESS) {
		result = ISC_R_NOTFOUND;
		goto complete_allnds;
	}

	/* remove path separator at end of path so stat works properly */
	basepathlen = strlen(basepath);

	if (stat(basepath, &sb) != 0) {
		result = ISC_R_NOTFOUND;
		goto complete_allnds;
	}

	if ((sb.st_mode & S_IFDIR) == 0) {
		result = ISC_R_NOTFOUND;
		goto complete_allnds;
	}

	/* initialize and open directory */
	isc_dir_init(&dir);
	result = isc_dir_open(&dir, basepath);

	/* if directory open failed, return error. */
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "Unable to open %s directory to read entries.",
			      basepath);
		result = ISC_R_FAILURE;
		goto complete_allnds;
	}

	/* process the directory */
	result = process_dir(&dir, allnodes, cd, dir_list, basepathlen);

	/* close the directory */
	isc_dir_close(&dir);

	if (result != ISC_R_SUCCESS) {
		goto complete_allnds;
	}

	/* get first dir entry from list. */
	dir_entry = ISC_LIST_HEAD(*dir_list);
	while (dir_entry != NULL) {
		result = isc_dir_open(&dir, dir_entry->dirpath);
		/* if directory open failed, return error. */
		if (result != ISC_R_SUCCESS) {
			isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
				      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
				      "Unable to open %s "
				      "directory to read entries.",
				      basepath);
			result = ISC_R_FAILURE;
			goto complete_allnds;
		}

		/* process the directory */
		result = process_dir(&dir, allnodes, cd, dir_list, basepathlen);

		/* close the directory */
		isc_dir_close(&dir);

		if (result != ISC_R_SUCCESS) {
			goto complete_allnds;
		}

		dir_entry = ISC_LIST_NEXT(dir_entry, link);
	} /* end while */

complete_allnds:
	/* clean up entries from list. */
	dir_entry = ISC_LIST_HEAD(*dir_list);
	while (dir_entry != NULL) {
		next_de = ISC_LIST_NEXT(dir_entry, link);
		isc_mem_put(named_g_mctx, dir_entry, sizeof(dir_entry_t));
		dir_entry = next_de;
	} /* end while */
	isc_mem_put(named_g_mctx, dir_list, sizeof(dlist_t));

	if (basepath != NULL) {
		isc_mem_free(named_g_mctx, basepath);
	}

	return (result);
}

static isc_result_t
fs_findzone(void *driverarg, void *dbdata, const char *name,
	    dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo) {
	isc_result_t result;
	char *path;
	struct stat sb;
	path = NULL;

	UNUSED(driverarg);
	UNUSED(methods);
	UNUSED(clientinfo);

	if (create_path(name, NULL, NULL, (config_data_t *)dbdata, &path) !=
	    ISC_R_SUCCESS)
	{
		return (ISC_R_NOTFOUND);
	}

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(1),
		      "Filesystem driver Findzone() Checking for path: '%s'\n",
		      path);

	if (stat(path, &sb) != 0) {
		result = ISC_R_NOTFOUND;
		goto complete_FZ;
	}

	if ((sb.st_mode & S_IFDIR) != 0) {
		result = ISC_R_SUCCESS;
		goto complete_FZ;
	}

	result = ISC_R_NOTFOUND;

complete_FZ:

	isc_mem_free(named_g_mctx, path);
	return (result);
}

static isc_result_t
fs_lookup(const char *zone, const char *name, void *driverarg, void *dbdata,
	  dns_sdlzlookup_t *lookup, dns_clientinfomethods_t *methods,
	  dns_clientinfo_t *clientinfo) {
	isc_result_t result;
	char *path;
	struct stat sb;
	isc_dir_t dir;
	path = NULL;

	UNUSED(driverarg);
	UNUSED(lookup);
	UNUSED(methods);
	UNUSED(clientinfo);

	if (strcmp(name, "*") == 0) {
		/*
		 * handle filesystem's special wildcard "-"
		 */
		result = create_path(zone, "-", NULL, (config_data_t *)dbdata,
				     &path);
	} else {
		result = create_path(zone, name, NULL, (config_data_t *)dbdata,
				     &path);
	}

	if (result != ISC_R_SUCCESS) {
		return (ISC_R_NOTFOUND);
	}

	/* remove path separator at end of path so stat works properly */
	path[strlen(path) - 1] = '\0';

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(1),
		      "Filesystem driver lookup() Checking for path: '%s'\n",
		      path);

	if (stat(path, &sb) != 0) {
		result = ISC_R_NOTFOUND;
		goto complete_lkup;
	}

	if ((sb.st_mode & S_IFDIR) == 0) {
		result = ISC_R_NOTFOUND;
		goto complete_lkup;
	}

	/* initialize and open directory */
	isc_dir_init(&dir);
	result = isc_dir_open(&dir, path);

	/* if directory open failed, return error. */
	if (result != ISC_R_SUCCESS) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "Unable to open %s directory to read entries.",
			      path);
		result = ISC_R_FAILURE;
		goto complete_lkup;
	}

	/* process any records in the directory */
	result = process_dir(&dir, lookup, (config_data_t *)dbdata, NULL, 0);

	/* close the directory */
	isc_dir_close(&dir);

complete_lkup:

	isc_mem_free(named_g_mctx, path);
	return (result);
}

static isc_result_t
fs_create(const char *dlzname, unsigned int argc, char *argv[], void *driverarg,
	  void **dbdata) {
	config_data_t *cd;
	char *endp;
	int len;
	char pathsep;

	UNUSED(driverarg);
	UNUSED(dlzname);

	/* we require 5 command line args. */
	if (argc != 6) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "Filesystem driver requires "
			      "6 command line args.");
		return (ISC_R_FAILURE);
	}

	if (strlen(argv[5]) > 1) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "Filesystem driver can only "
			      "accept a single character for separator.");
		return (ISC_R_FAILURE);
	}

	/* verify base dir ends with '/' or '\' */
	len = strlen(argv[1]);
	if (argv[1][len - 1] != '\\' && argv[1][len - 1] != '/') {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "Base dir parameter for filesystem driver "
			      "should end with %s",
			      "either '/' or '\\' ");
		return (ISC_R_FAILURE);
	}

	/* determine and save path separator for later */
	if (argv[1][len - 1] == '\\') {
		pathsep = '\\';
	} else {
		pathsep = '/';
	}

	/* allocate memory for our config data */
	cd = isc_mem_get(named_g_mctx, sizeof(config_data_t));

	/* zero the memory */
	memset(cd, 0, sizeof(config_data_t));

	cd->pathsep = pathsep;

	/* get and store our base directory */
	cd->basedir = isc_mem_strdup(named_g_mctx, argv[1]);
	cd->basedirsize = strlen(cd->basedir);

	/* get and store our data sub-dir */
	cd->datadir = isc_mem_strdup(named_g_mctx, argv[2]);
	cd->datadirsize = strlen(cd->datadir);

	/* get and store our zone xfr sub-dir */
	cd->xfrdir = isc_mem_strdup(named_g_mctx, argv[3]);
	cd->xfrdirsize = strlen(cd->xfrdir);

	/* get and store our directory split count */
	cd->splitcnt = strtol(argv[4], &endp, 10);
	if (*endp != '\0' || cd->splitcnt < 0) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DLZ, ISC_LOG_ERROR,
			      "Directory split count must be zero (0) "
			      "or a positive number");
	}

	/* get and store our separator character */
	cd->separator = *argv[5];

	/* attach config data to memory context */
	isc_mem_attach(named_g_mctx, &cd->mctx);

	/* pass back config data */
	*dbdata = cd;

	/* return success */
	return (ISC_R_SUCCESS);
}

static void
fs_destroy(void *driverarg, void *dbdata) {
	isc_mem_t *mctx;
	config_data_t *cd;

	UNUSED(driverarg);

	cd = (config_data_t *)dbdata;

	/*
	 * free memory for each section of config data that was
	 * allocated
	 */
	if (cd->basedir != NULL) {
		isc_mem_free(named_g_mctx, cd->basedir);
	}

	if (cd->datadir != NULL) {
		isc_mem_free(named_g_mctx, cd->datadir);
	}

	if (cd->xfrdir != NULL) {
		isc_mem_free(named_g_mctx, cd->xfrdir);
	}

	/* hold memory context to use later */
	mctx = cd->mctx;

	/* free config data memory */
	isc_mem_putanddetach(&mctx, cd, sizeof(config_data_t));
}

static dns_sdlzmethods_t dlz_fs_methods = {
	fs_create,
	fs_destroy,
	fs_findzone,
	fs_lookup,
	NULL,
	fs_allnodes,
	fs_allowzonexfr,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

/*%
 * Wrapper around dns_sdlzregister().
 */
isc_result_t
dlz_fs_init(void) {
	isc_result_t result;

	/*
	 * Write debugging message to log
	 */
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(2), "Registering DLZ filesystem driver.");

	result = dns_sdlzregister("filesystem", &dlz_fs_methods, NULL,
				  DNS_SDLZFLAG_RELATIVEOWNER |
					  DNS_SDLZFLAG_RELATIVERDATA,
				  named_g_mctx, &dlz_fs);
	if (result != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "dns_sdlzregister() failed: %s",
				 isc_result_totext(result));
		result = ISC_R_UNEXPECTED;
	}

	return (result);
}

/*%
 * Wrapper around dns_sdlzunregister().
 */
void
dlz_fs_clear(void) {
	/*
	 * Write debugging message to log
	 */
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DLZ,
		      ISC_LOG_DEBUG(2), "Unregistering DLZ filesystem driver.");

	if (dlz_fs != NULL) {
		dns_sdlzunregister(&dlz_fs);
	}
}

#endif /* ifdef DLZ_FILESYSTEM */

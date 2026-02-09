/*------------------------------------------------------------------------------
//	Copyright (c) 2004-2025, Bill Hayden
//
//	Permission is hereby granted, free of charge, to any person obtaining a
//	copy of this software and associated documentation files (the "Software"),
//	to deal in the Software without restriction, including without limitation
//	the rights to use, copy, modify, merge, publish, distribute, sublicense,
//	and/or sell copies of the Software, and to permit persons to whom the
//	Software is furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in
//	all copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//	DEALINGS IN THE SOFTWARE.
//
//	File Name:		fs.cpp
//	Authors:		Bill Hayden (hayden@haydentech.com)
//----------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>


#include "Errors.h"

#include "fs_attr.h"
#include "fs_info.h"
#include "TypeConstants.h"


status_t _kstart_watching_vnode_(dev_t device, ino_t node,
								 uint32 flags, port_id port, int32 handlerToken);
status_t _kstop_watching_vnode_(dev_t device, ino_t node,
								port_id port, int32 handlerToken);
status_t _kstop_notifying_(port_id port, int32 handlerToken);



ssize_t
read_pos(int fd, off_t pos, void *buffer, size_t count)
{
	off_t origPos = lseek(fd, 0, SEEK_CUR);
	if (origPos < 0)
		return -1;
	
	if (lseek(fd, pos, SEEK_SET) < 0)
		return -1;
	
	ssize_t result = read(fd, buffer, count);
	
	// Restore original position (best effort)
	lseek(fd, origPos, SEEK_SET);
	return result;
}

ssize_t 
write_pos(int fd, off_t pos, const void *buffer, size_t count)
{
	off_t origPos = lseek(fd, 0, SEEK_CUR);
	if (origPos < 0)
		return -1;
	
	if (lseek(fd, pos, SEEK_SET) < 0)
		return -1;
	
	ssize_t result = write(fd, buffer, count);
	
	// Restore original position (best effort)
	lseek(fd, origPos, SEEK_SET);
	return result;
}



// We're in a bit of a bind here since dev_t is unsigned on Linux (XXX NetBSD?), but
// was signed on BeOS. So we treat -1 as invalid, and everything else as valid.
dev_t
dev_for_path(const char *path)
{
	if (!path) {
		return (dev_t)-1;
	}
	struct stat st;
	if (stat(path, &st) != 0) {
		return (dev_t)-1;
	}
	return st.st_dev;
}

dev_t
next_dev(int32 *pos)
{
	if (!pos || *pos < 0)
		return (dev_t)-1;

	struct statvfs *mnts;
	int count = getmntinfo(&mnts, MNT_NOWAIT);
	if (count <= 0)
		return (dev_t)-1;

	int32 targetIndex = *pos;
	int32 found = 0;
	dev_t result = (dev_t)-1;

	/* Deduplication list */
	dev_t seen[256];
	int seenCount = 0;

	for (int i = 0; i < count; i++) {
		struct stat st;

		if (stat(mnts[i].f_mntonname, &st) != 0)
			continue;

		/* dedup */
		int alreadySeen = 0;
		for (int j = 0; j < seenCount; j++) {
			if (seen[j] == st.st_dev) {
				alreadySeen = 1;
				break;
			}
		}
		if (alreadySeen)
			continue;

		if (seenCount < (int)(sizeof(seen) / sizeof(seen[0])))
			seen[seenCount++] = st.st_dev;

		if (found == targetIndex) {
			result = st.st_dev;
			*pos = targetIndex + 1; /* advance cookie */
			break;
		}

		found++;
	}

	return result;
}

int
fs_stat_dev(dev_t dev, fs_info *info)
{
	int i, ret = -1, count;
	struct statvfs *mnts;
	
	if (dev == (dev_t)-1 || info == NULL) {
		errno = B_BAD_VALUE;
		return -1;
	}

	count = getmntinfo(&mnts, MNT_NOWAIT);
	if (count <= 0) {
		return B_BAD_VALUE;
	}

	for (i = 0; i < count; i++) {
		struct stat st;

		if (stat(mnts[i].f_mntonname, &st) != 0)
			continue;

		if (st.st_dev != dev)
			continue;

		/* Found matching mount */
		memset(info, 0, sizeof(*info));
		info->dev = dev;

		info->block_size   = (off_t)mnts[i].f_bsize;
		info->total_blocks = (off_t)mnts[i].f_blocks;
		info->free_blocks  = (off_t)mnts[i].f_bfree;

		/* Device name (e.g. /dev/wd0a) */
		strncpy(info->device_name,
			mnts[i].f_mntfromname,
			sizeof(info->device_name) - 1);

		/* Volume name: basename of mount point */
		const char *base = strrchr(mnts[i].f_mntonname, '/');
		if (base && base[1] != '\0')
			strncpy(info->volume_name,
				base + 1,
				sizeof(info->volume_name) - 1);
		else
			strncpy(info->volume_name,
				mnts[i].f_mntonname,
				sizeof(info->volume_name) - 1);

		/* Filesystem name (e.g. ffs, nfs, tmpfs) */
		strncpy(info->fsh_name,
			mnts[i].f_fstypename,
			sizeof(info->fsh_name) - 1);

		/* Flags */
		info->flags = 0;
		if (mnts[i].f_flag & ST_RDONLY)
			info->flags |= B_FS_IS_READONLY;

		ret = 0;
		break;
	}

	errno = (ret == 0) ? 0 : B_BAD_VALUE;
	return ret;
}

ssize_t
fs_write_attr(int fd, const char *attribute, uint32 type, off_t pos, const void *buffer, size_t writeBytes)
{
	if (!attribute) {
		errno = B_BAD_VALUE;
		return -1;
	}
	
	if (strlen(attribute) > B_ATTR_NAME_LENGTH) {
		// Setting errno a B_ value intentionally to match BeBook API
		errno = B_NAME_TOO_LONG;
		return -1;
	}

	char attrName[B_ATTR_NAME_LENGTH];
	snprintf(attrName, sizeof(attrName), "user.%s", attribute);
	int err = fsetxattr(fd, attrName, buffer, writeBytes, 0);
	if (err != 0) {
		// Setting errno a B_ value intentionally to match BeBook API
		errno = B_BAD_VALUE;
		return (ssize_t)-1;
	}
	
	errno = 0;
	return (ssize_t)writeBytes;
}


ssize_t
fs_read_attr(int fd, const char *attribute, uint32 type, off_t pos, void *buffer, size_t readBytes)
{
	if (!attribute) {
		errno = B_BAD_VALUE;
		return -1;
	}
	
	if (strlen(attribute) > B_ATTR_NAME_LENGTH) {
		// Setting errno a B_ value intentionally to match BeBook API
		errno = B_NAME_TOO_LONG;
		return -1;
	}

	char attrName[B_ATTR_NAME_LENGTH];
	snprintf(attrName, sizeof(attrName), "user.%s", attribute);

	ssize_t err = fgetxattr(fd, attrName, buffer, readBytes);
	if (err < 0) {
		// Setting errno a B_ value intentionally to match BeBook API
		errno = B_ENTRY_NOT_FOUND;
		return (ssize_t)-1;
	}

	errno = 0;
	return err;
}



int
fs_remove_attr(int fd, const char *attribute)
{
	if (!attribute) {
		errno = B_BAD_VALUE;
		return -1;
	}
	
	if (strlen(attribute) > B_ATTR_NAME_LENGTH) {
		// Setting errno a B_ value intentionally to match BeBook API
		errno = B_NAME_TOO_LONG;
		return -1;
	}

	char attrName[B_ATTR_NAME_LENGTH];
	snprintf(attrName, sizeof(attrName), "user.%s", attribute);
	int err = fremovexattr(fd, attrName);
	if (err < 0) {
		// Setting errno a B_ value intentionally to match BeBook API
		errno = B_ENTRY_NOT_FOUND;
		return -1;
	}

	errno = 0;
	return B_OK;
}



int
fs_stat_attr(int fd, const char *attribute, struct attr_info *attrInfo)
{
	if (!attribute) {
		errno = B_BAD_VALUE;
		return -1;
	}
	
	char attrName[B_ATTR_NAME_LENGTH];
	snprintf(attrName, sizeof(attrName), "user.%s", attribute);

	int size = fgetxattr(fd, attrName, NULL, 0);

	if (size < 0)
		return B_ENTRY_NOT_FOUND;

	if (attrInfo) {
		attrInfo->size = size;
		attrInfo->type = B_RAW_TYPE;
	}

	return B_OK;
}



/*
int
fs_stat_index(dev_t device, const char *name, struct index_info *indexInfo)
{
	//XXX not implemented, comes from kerne/fs_attr.h?
	return B_ERROR;
}

*/

status_t _kstart_watching_vnode_(dev_t device, ino_t node,
											uint32 flags, port_id port,
											int32 handlerToken)
{
	return B_ERROR;
}

/*!	\brief Unsubscribes a target from watching a node.
	\param device The device the node resides on (node_ref::device).
	\param node The node ID of the node (node_ref::device).
	\param port The port of the target (a looper port).
	\param handlerToken The token of the target handler. \c -2, if the
		   preferred handler of the looper is the target.
	\return \c B_OK, if everything went fine, another error code otherwise.
*/
status_t _kstop_watching_vnode_(dev_t device, ino_t node,
										   port_id port, int32 handlerToken)
{
	return B_ERROR;
}


/*!	\brief Unsubscribes a target from node and mount monitoring.
	\param port The port of the target (a looper port).
	\param handlerToken The token of the target handler. \c -2, if the
		   preferred handler of the looper is the target.
	\return \c B_OK, if everything went fine, another error code otherwise.
*/
status_t _kstop_notifying_(port_id port, int32 handlerToken)
{
	return B_ERROR;
}

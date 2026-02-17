//------------------------------------------------------------------------------
//	Copyright (c) 2004-2024, Bill Hayden
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
//	File Name:		image.cpp
//	Authors:		Bill Hayden (hayden@haydentech.com)
//------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/statvfs.h>
#include "Errors.h"

#include "image.h"
#include <dlfcn.h>


thread_id 
load_image(int32 argc, const char **argv, const char **envp) {

    int i;
    pid_t pid;

    if ((pid = fork()) < 0) {
        return B_ERROR;
    }
    else if (pid > 0) {
        return (thread_id)pid;
    }
    else {
     
        // Create writable copies of argv and envp
        char *new_argv[argc + 1];
        char *new_envp[256]; // Assuming a reasonable limit for envp entries

        for (i = 0; i < argc; i++) {
            new_argv[i] = strdup(argv[i]);
        }
        new_argv[argc] = NULL;

        // Copy envp
        
        for (i = 0; envp[i] != NULL && i < 255; i++) {
            new_envp[i] = strdup(envp[i]);
        }
        new_envp[i] = NULL;

        execvpe(new_argv[0], new_argv, new_envp);

        perror("execvpe failed");
        return B_ERROR;
    }

    return B_ERROR; /* NOTREACHED */
}



image_id
load_add_on(const char* path)
{
	void* hdll = dlopen(path, RTLD_LAZY);

	if (!hdll)
		printf("load_add_on(): dlopen('%s', RTLD_LAZY) failed: %s\n", path, dlerror());

	return hdll;
}


status_t
unload_add_on(image_id imageID)
{
	void* hdll = (void*)imageID;
	return dlclose(hdll) ? B_ERROR : B_OK;
}


status_t
get_image_symbol(image_id imid, const char* name, int32 sclass, void** pptr)
{
	void* hdll = (void*)imid;
	const char* err = NULL;

	*pptr = dlsym(hdll, name);
	err = dlerror();
	if (err)
	{
		printf("get_image_symbol(): dlsym('%s') failed: %s\n", name, err);
		return B_BAD_IMAGE_ID;
	}

	return B_OK;
}



status_t
_get_image_info(image_id image, image_info *info, size_t size)
{
	printf("_get_image_info(): UNIMPLEMENTED\n");
	return B_ERROR;

#if 0
	if (!info || size != sizeof(image_info))
		return B_BAD_VALUE;

	if (!image)
		return B_BAD_IMAGE_ID;

	Dl_info dl_info;
	if (dladdr(image, &dl_info) == 0)
		return B_BAD_IMAGE_ID;

	void* text_start = dl_info.dli_fbase;
	void* text_end = NULL;
	void* data_start = text_start;
	void* data_end = NULL;
	char image_path[512] = {0};
	if (dl_info.dli_fname)
		strncpy(image_path, dl_info.dli_fname, sizeof(image_path) - 1);

	/* Fill in the image_info structure with best-effort data */
	info->id = image;
	info->type = B_LIBRARY_IMAGE;
	info->sequence = 0;
	info->init_order = 0;
	info->init_routine = NULL;
	info->term_routine = NULL;
	info->device = 0;
	info->node = 0;

	if (image_path[0] != '\0') {
		strncpy(info->name, image_path, MAXPATHLEN - 1);
		info->name[MAXPATHLEN - 1] = '\0';
	} else {
		info->name[0] = '\0';
	}

	info->text = text_start;
	info->data = data_start;
	info->text_size = text_end ? (int32)((char*)text_end - (char*)text_start) : 0;
	info->data_size = data_end ? (int32)((char*)data_end - (char*)data_start) : 0;

	return B_OK;
#endif
}



status_t
_get_next_image_info(team_id team, int32 *cookie, image_info *info, size_t size)
{
	// Cosmoe-specific implementation
	// Only supports 1 image
	
    struct statvfs vfs;
	char buffer[64];

	snprintf(buffer, 64, "/proc/%d/exe", (team == B_CURRENT_TEAM) ? getpid() : team);

    if (statvfs("/proc", &vfs) != 0) {
        fprintf(stderr, "_get_next_image_info: cannot statvfs(/proc): %s\n",
                strerror(errno));
        return B_ERROR;
    }

	if (strcmp(vfs.f_fstypename, "procfs") != 0) {
        fprintf(stderr, "_get_next_image_info: /proc is not a procfs mount (found: %s)\n",
                vfs.f_fstypename);
        return B_ERROR;
    }

	if (cookie && (*cookie == 0))
	{
		*cookie += 1;
		info->type = B_APP_IMAGE;
		info->id = NULL;	// Cosmoe returns some info, but doesn't actually dlopen the image
		ssize_t len = readlink(buffer, info->name, MAXPATHLEN - 1);

		if (len != -1)
		{
			info->name[len] = '\0';
			return B_OK;
		}
	}

	// TODO: pull additional images from /proc/<pid>/maps or /proc/self/maps
	// See also https://github.com/blackle/whereami for public domain code

	printf("_get_next_image_info(): requested functionality is unimplemented\n");
	return B_ERROR;
}


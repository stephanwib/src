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



#include <sys/param.h>
#include <sys/syscallargs.h>
#include <sys/proc.h>
#include <sys/area.h>
#include <sys/kmem.h>
#include <sys/kauth.h>

#include <uvm/uvm.h>

const  int                      area_max                  = 8192;
static int                      next_area_id              = 1;
static int                      area_total_count          = 0;
static kmutex_t                 area_mutex                __cacheline_aligned;
static LIST_HEAD(, karea)       karea_list                __cacheline_aligned;

void
area_init(void) 
{

    LIST_INIT(&karea_list);
    mutex_init(&area_mutex, MUTEX_DEFAULT, IPL_NONE);
}

static struct karea *
karea_lookup_byid(area_id id)
{
    struct karea *ka;

    KASSERT(mutex_owned(&area_mutex));
    LIST_FOREACH(ka, &karea_list, ka_entry)
    {
        if (ka->ka_id == id)
        {
            return ka;
        }
    }
    return NULL;
}

static void
fill_area_info(const struct karea *ka, struct area_info *info)
{
    *info = (struct area_info) {
        .area = ka->ka_id,
        .pid = ka->ka_owner,
        .size = ka->ka_size,
        .lock = ka->ka_lock,
        .protection = ka->ka_protection,
        .ram_size = 0,
        .copy_count = 0,
        .in_count = 0,
        .out_count = 0,
        .address = (void*)ka->ka_va
    };

    (void)strlcpy(info->name, ka->ka_name, AREA_MAX_NAME_LENGTH);
}

static int
create_or_clone_area(struct lwp *l, const char *name, void **startAddress, 
                     uint32_t addressSpec, size_t size, uint32_t lock, uint32_t protection, 
                     area_id source_area_id, register_t *retval)
{
    int error, flags = 0;
    size_t namelen = 0;
    vm_prot_t prot = VM_PROT_NONE;
    vaddr_t va;
    void *address;
    char namebuf[AREA_MAX_NAME_LENGTH];
    struct karea *ka, *search;
    bool is_clone = (source_area_id != -1);

    /* XXX: Not sure if the original implementation allows zero size areas.
    /  We can not map something zero-sized as it crashes the kernel. */
    if (!is_clone && (size == 0))
        return EINVAL;

    if (name != NULL) {
        error = copyinstr(name, namebuf, sizeof(namebuf), &namelen);
        if (error)
            return error;
    }
  
    /* Reject mappings unavailable to user-mode
    /  Remap options with the same meaning */
    switch (addressSpec) {
	case AREA_EXACT_ADDRESS:
	    /* XXX: UVM takes this as a hint only */
	    flags |= UVM_FLAG_FIXED;
        case AREA_ANY_ADDRESS:
	case AREA_RANDOMIZED_ANY_ADDRESS:
            break;
	case AREA_BASE_ADDRESS:
	case AREA_RANDOMIZED_BASE_ADDRESS:
	    /* XXX: base addresses probably not supported by UVM */
	    break;
	case AREA_ANY_KERNEL_ADDRESS:
	default:
 	    return EINVAL;
    }

    /* Map area protection flags to UVM flags */
    if (protection & AREA_READ_AREA)
        prot |= VM_PROT_READ;
    if (protection & AREA_WRITE_AREA)
        prot |= VM_PROT_WRITE;
    if (protection & AREA_EXECUTE_AREA)
        prot |= VM_PROT_EXECUTE;

    // We are provided a pointer to a user-mode pointer, so load its content into our local pointer
    error = copyin(startAddress, &address, sizeof(void *));
    if (error)
        return error;
    va = (vaddr_t)address;

    /* Ensure the requested address and size are aligned */
    if ((va % PAGE_SIZE != 0) || (size % PAGE_SIZE != 0))
        return EINVAL;
	
    ka = kmem_alloc(sizeof(struct karea), KM_SLEEP);
    if (ka == NULL)
        return ENOMEM;

    *ka = (struct karea){
        .ka_va = 0,
        .ka_size = size,
        .ka_lock = lock,
        .ka_protection = protection,
        .ka_owner = l->l_proc->p_pid,
        .ka_uid = kauth_cred_getuid(l->l_cred),
        .ka_gid = kauth_cred_getgid(l->l_cred),
        .ka_uobj = NULL,
    };

    strlcpy(ka->ka_name,
            (namelen == 0) ? "unnamed area" : namebuf,
            AREA_MAX_NAME_LENGTH);

    mutex_enter(&area_mutex);

    if (is_clone) {
        struct karea *source_area = karea_lookup_byid(source_area_id);        
        if (source_area == NULL) {
	    mutex_exit(&area_mutex);
            kmem_free(ka, sizeof(struct karea));
            return EINVAL;
        }

	    KASSERT(source_area->ka_uobj != NULL);
            ka->ka_uobj = source_area->ka_uobj;
printf("size of source area: %ld\n", source_area->ka_size);
	    ka->ka_size = source_area->ka_size;
	    
    }
    else {
        ka->ka_uobj = uao_create(size, 0);
        if (ka->ka_uobj == NULL) {
	    mutex_exit(&area_mutex);
            kmem_free(ka, sizeof(struct karea));
            return ENOMEM;
        }
    }

    /* Map the UVM object into the process address space */
    uao_reference(ka->ka_uobj);
    error = uvm_map(&l->l_proc->p_vmspace->vm_map, &va, ka->ka_size, ka->ka_uobj, 0, 0,
                    UVM_MAPFLAG(prot, prot, UVM_INH_SHARE, UVM_ADV_RANDOM, flags));
    if (error) {
printf("Error in uvm_map\n");
	    mutex_exit(&area_mutex);
        uao_detach(ka->ka_uobj);
        kmem_free(ka, sizeof(struct karea));
        return error;
    }

    /* If the address specification was exact but the address was adjusted, unmap */
    if ((addressSpec == AREA_EXACT_ADDRESS) && (va != (vaddr_t)address)) {
printf("Error requested adress does not match\n");
    	mutex_exit(&area_mutex);
        uvm_unmap(&l->l_proc->p_vmspace->vm_map, va, va + size);
        uao_detach(ka->ka_uobj);
        kmem_free(ka, sizeof(struct karea));
        return EINVAL;
    }

    /* Wire pages if requested */
    if (lock >= AREA_LAZY_LOCK) {
        error = uvm_obj_wirepages(ka->ka_uobj, 0, size, NULL);
        if (error) {
printf("Error in wirepages\n");
	        mutex_exit(&area_mutex);
            uvm_unmap(&l->l_proc->p_vmspace->vm_map, va, va + size);
            uao_detach(ka->ka_uobj);
            kmem_free(ka, sizeof(struct karea));
            return error;
        }
    }

    ka->ka_va = va;

    if (area_total_count >= area_max) {
        mutex_exit(&area_mutex);
        uvm_unmap(&l->l_proc->p_vmspace->vm_map, va, va + size);
        uao_detach(ka->ka_uobj);
        kmem_free(ka, sizeof(struct karea));
        return ENOSPC;
    }

    do {
        next_area_id++;

	/* Do not issue a negative area id */
	if (next_area_id < 0)
	    next_area_id = 1;

    } while (__predict_false((search = karea_lookup_byid(next_area_id)) != NULL));

    ka->ka_id = next_area_id;

    LIST_INSERT_HEAD(&karea_list, ka, ka_entry);
    area_total_count++;

    mutex_exit(&area_mutex);

    *retval = ka->ka_id;
    error = copyout(&va, startAddress, sizeof(void *));
    return error;
}

int
sys__create_area(struct lwp *l, const struct sys__create_area_args *uap, register_t *retval)
{
    /*
     * _create_area: Create a memory area with specified attributes.
     * {
     *      syscallarg(const char *) name;
     *      syscallarg(void **) startAddress;
     *      syscallarg(uint32_t) addressSpec;
     *      syscallarg(size_t) size;
     *      syscallarg(uint32_t) lock;
     *      syscallarg(uint32_t) protection;
     * }
     */

    return create_or_clone_area(l, SCARG(uap, name), SCARG(uap, startAddress),
                                SCARG(uap, addressSpec), SCARG(uap, size),
                                SCARG(uap, lock), SCARG(uap, protection), -1, retval);
}

int
sys__clone_area(struct lwp *l, const struct sys__clone_area_args *uap, register_t *retval)
{
    /*
     * _clone_area: Clone an existing memory area.
     * {
     *      syscallarg(const char *) name;
     *      syscallarg(void **) destAddress;
     *      syscallarg(uint32_t) addressSpec;
     *      syscallarg(uint32_t) protection;
     *      syscallarg(area_id) source;
     * }
     */

    return create_or_clone_area(l, SCARG(uap, name), SCARG(uap, destAddress),
                                SCARG(uap, addressSpec), 0, 0, SCARG(uap, protection),
                                SCARG(uap, source), retval);
}


area_id
sys__find_area(struct lwp *l, const struct sys__find_area_args *uap, register_t *retval)
{
    /*
     * _find_area: Search for a memory area by name.
     * {
     *      syscallarg(const char *) name;
     * }
     */
   
    const char *name = SCARG(uap, name);
    struct karea *ka;
    
    mutex_enter(&area_mutex);
    
    LIST_FOREACH(ka, &karea_list, ka_entry) {
        if (strcmp(ka->ka_name, name) == 0) {
            *retval = ka->ka_id;
            mutex_exit(&area_mutex);
	    return 0;
        }
    }
   
    mutex_exit(&area_mutex);

    return ENOENT; 
}

area_id
sys__area_for(struct lwp *l, const struct sys__area_for_args *uap, register_t *retval)
{

    /*
     * _area_for: Given an address, return the identifier of the containing memory area.
     * {
     *      syscallarg(void *) address;
     * }
     */
    
   void *address = SCARG(uap, address);
   struct karea *ka;
    
    mutex_enter(&area_mutex);
    LIST_FOREACH(ka, &karea_list, ka_entry) {
        if (ka->ka_owner == l->l_proc->p_pid &&
            ka->ka_va <= (vaddr_t)address &&
            (vaddr_t)address < ka->ka_va + ka->ka_size) {
                *retval = ka->ka_id;
                mutex_exit(&area_mutex);
                return 0;
        }
    }

    mutex_exit(&area_mutex);

    return ENOENT;
}

int
sys__delete_area(struct lwp *l, const struct sys__delete_area_args *uap, register_t *retval)
{
    /*
     * _delete_area: Delete the specified memory area.
     * {
     *      syscallarg(area_id) id;
     * }
     */

    area_id id = SCARG(uap, id);

    mutex_enter(&area_mutex);
    struct karea *ka = karea_lookup_byid(id);

    if (ka == NULL) {
        mutex_exit(&area_mutex);
        return EINVAL;
    }
        
    if (ka->ka_owner != l->l_proc->p_pid) {
        mutex_exit(&area_mutex);
        return EACCES;
    }
    
    if (ka->ka_uobj != NULL) {
        uvm_unmap(&l->l_proc->p_vmspace->vm_map, ka->ka_va, ka->ka_va + ka->ka_size);
        uao_detach(ka->ka_uobj);
    }

    LIST_REMOVE(ka, ka_entry);
    area_total_count--;
    mutex_exit(&area_mutex);

    kmem_free(ka, sizeof(struct karea));

    return 0;
}

int
sys__resize_area(struct lwp *l, const struct sys__resize_area_args *uap, register_t *retval)
{
    /*
     * _resize_area: Change the size of the specified memory area.
     * {
     *      syscallarg(area_id) id;
     *      syscallarg(size_t) newSize;
     * }
     */

    // XXX: Not implemented at the moment.
    
    return ENOMEM;
}

int
sys__set_area_protection(struct lwp *l, const struct sys__set_area_protection_args *uap, register_t *retval)
{
    /*
     * _set_area_protection: Modify the protection settings of the specified memory area.
     * {
     *      syscallarg(area_id) id;
     *      syscallarg(uint32_t) newProtection;
     * }
     */

    area_id id = SCARG(uap, id);
    uint32_t newProtection = SCARG(uap, newProtection);
    struct karea *ka;
    vm_prot_t prot = VM_PROT_NONE;
    int error = 0;

    if (newProtection & AREA_READ_AREA)
        prot |= VM_PROT_READ;
    if (newProtection & AREA_WRITE_AREA)
        prot |= VM_PROT_WRITE;
    if (newProtection & AREA_EXECUTE_AREA)
        prot |= VM_PROT_EXECUTE;

    mutex_enter(&area_mutex);

    ka = karea_lookup_byid(id);
    if (ka == NULL) {
        mutex_exit(&area_mutex);
        return EINVAL;
    }

    if (ka->ka_owner != l->l_proc->p_pid) {
        mutex_exit(&area_mutex);
        return EPERM;
    }

    error = uvm_map_protect(&l->l_proc->p_vmspace->vm_map, ka->ka_va, ka->ka_va + ka->ka_size, prot, true);
    if (error) {
        mutex_exit(&area_mutex);
        return error;
    }

    ka->ka_protection = newProtection;

    mutex_exit(&area_mutex);

    return 0;
}

int
sys__get_area_info(struct lwp *l, const struct sys__get_area_info_args *uap, register_t *retval)
{
    /*
     * _get_area_info: Retrieve information about the specified memory area.
     * {
     *      syscallarg(area_id) id;
     *      syscallarg(area_info *) areaInfo;
     * }
     */

    area_id id = SCARG(uap, id);
    struct area_info *area_info_user = SCARG(uap, areaInfo);
    struct area_info area_info_kernel;
    int error;
    
    mutex_enter(&area_mutex);
    struct karea *ka = karea_lookup_byid(id);
    mutex_exit(&area_mutex);

    if (ka == NULL)
        return EINVAL;
    
    fill_area_info(ka, &area_info_kernel);

    error = copyout(&area_info_kernel, area_info_user, sizeof(struct area_info));
   
    return error;
}

int
sys__get_next_area_info(struct lwp *l, const struct sys__get_next_area_info_args *uap, register_t *retval)
{
    /*
     * _get_next_area_info: Iterate through memory areas of a process and retrieve information about the next area.
     * {
     *      syscallarg(pid_t) pid;
     *      syscallarg(ssize_t *) cookie;
     *      syscallarg(area_info *) areaInfo;
     * }
     */

    pid_t pid = SCARG(uap, pid);
    ssize_t *cookie = SCARG(uap, cookie);
    struct area_info *user_area_info = SCARG(uap, areaInfo);
    // size_t size = SCARG(uap, size);

    int error;
    uint32_t skip, iter_cookie;
    struct karea *ka;
    struct area_info area_info_kernel;

    // Copy in the initial cookie state
    error = copyin(cookie, &skip, sizeof(uint32_t));
    if (error)
        return error;

    iter_cookie = skip;  // Keep the initial cookie state, will be incremented for the next run

    mutex_enter(&area_mutex);
    
    LIST_FOREACH(ka, &karea_list, ka_entry) {
        if (ka->ka_owner == pid) {
            if (skip == 0) {

                fill_area_info(ka, &area_info_kernel);
                mutex_exit(&area_mutex);

                error = copyout(&area_info_kernel, user_area_info, sizeof(struct area_info));
                if (error)
                    return error;
                
                iter_cookie++;
                error = copyout(&iter_cookie, cookie, sizeof(uint32_t));
                if (error)
                    return error;
                
                return 0;
            } else {
                skip--;
            }
        }
    }

    // Nothing found
    mutex_exit(&area_mutex);
    
    return ENOENT;

}

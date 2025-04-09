
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <kvm.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <uvm/uvm_extern.h>
#include <OS.h>
#include <Errors.h>

static int
map_lwp_state(int lwp_state) {

    switch (lwp_state) {

        case LSIDL:
            return B_THREAD_READY;
        case LSRUN:
        case LSONPROC:
            return B_THREAD_RUNNING;
        case LSSLEEP:
            return B_THREAD_ASLEEP;
        case LSSTOP:
        case LSSUSPENDED:
            return B_THREAD_SUSPENDED;
        case LSZOMB:
            return B_THREAD_ASLEEP;
        default:
            return B_THREAD_RUNNING;
    }

}

status_t 
get_thread_info(thread_id thread, thread_info *info) {

    int i;
    int lwp_count = 0;
    kvm_t *kd = NULL;
    struct kinfo_lwp *lwps;
    
    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (kd == NULL)
        return B_BAD_VALUE;

    lwps = kvm_getlwps(kd, getpid(), 0, sizeof(struct kinfo_lwp), &lwp_count);
    kvm_close(kd);

    if (!lwps || lwp_count == 0)
        return B_BAD_VALUE;
    
    for (i = 0; i < lwp_count; i++) {
	    
        if (lwps[i].l_lid == (int)thread) {
		
            *info = (thread_info){
                .thread = lwps[i].l_lid,
                .team = lwps[i].l_pid,
                .state = map_lwp_state(lwps[i].l_stat),
                .priority = lwps[i].l_priority,
                .sem = -1,
                .user_time = lwps[i].l_rtime_sec * 1000000LL + lwps[i].l_rtime_usec,
                .kernel_time = 0,
                .stack_base = NULL,
                .stack_end = NULL
            };
		
            strlcpy(info->name, lwps[i].l_name, B_OS_NAME_LENGTH);
		
            return B_OK;
        }
    }

    return B_BAD_VALUE;
}

status_t 
get_next_thread_info(team_id team, int32_t *cookie, thread_info *info) {
    kvm_t *kd = NULL;
    struct kinfo_lwp *lwp, *lwps;
    int lwp_count = 0;

    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (!kd)
        return B_BAD_VALUE;

    lwps = kvm_getlwps(kd, team, 0, sizeof(struct kinfo_lwp), &lwp_count);
    kvm_close(kd);
        
    if (!lwps || lwp_count == 0)
        return B_BAD_VALUE;

    if (*cookie >= lwp_count)
        return B_BAD_VALUE;
    
    lwp = &lwps[*cookie];
    
    *info = (thread_info){
        .thread = lwp->l_lid,
        .team = lwp->l_pid,
        .state = map_lwp_state(lwp->l_stat),
        .priority = lwp->l_priority,
        .sem = -1,
        .user_time = lwp->l_rtime_sec * 1000000LL + lwp->l_rtime_usec,
        .kernel_time = 0,
        .stack_base = NULL,
        .stack_end = NULL
    };

    strlcpy(info->name, lwp->l_name, B_OS_NAME_LENGTH);

    (*cookie)++;
	
    return B_OK;
}



status_t
get_team_info(team_id team, team_info *info) {
    
    int count = 0;
    kvm_t *kd;
    struct kinfo_proc2 *proc, *procs;

    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (!kd)
        return B_BAD_TEAM_ID;

    procs = kvm_getproc2(kd, KERN_PROC_PID, team,
                         sizeof(struct kinfo_proc2), &count);
    kvm_close(kd);

    if (!procs || count == 0)
        return B_BAD_TEAM_ID;
    

    proc = &procs[0];

    *info = (team_info){
        .team                = proc->p_pid,
        .thread_count        = proc->p_nlwps,
        .image_count         = 0,
        .area_count          = 0,
        .debugger_nub_thread = -1,
        .debugger_nub_port   = -1,
      //  .argc                = proc->p_nargv,
        .uid                 = proc->p_uid,
        .gid                 = proc->p_gid
    };

    strlcpy(info->args, proc->p_comm, sizeof(info->args));
    
    return B_OK;
}


status_t
get_next_team_info(int32_t *cookie, team_info *info) {
  
    int nprocs = 0;
    struct kinfo_proc2 *proc, *procs;
	
    kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (!kd) {
        return B_BAD_TEAM_ID;
    }

    procs = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &nprocs);
    kvm_close(kd);

    if (!procs) {
        fprintf(stderr, "kvm_getproc2 failed: %s\n", kvm_geterr(kd));
        return B_BAD_TEAM_ID;
    }

    if (*cookie < 0 || *cookie >= nprocs)
        return B_BAD_TEAM_ID;

    proc = &procs[*cookie];
    *info = (team_info){
        .team = proc->p_pid,
        .thread_count = proc->p_nlwps,
        .argc = proc->p_acflag, // again placeholder
        .uid = proc->p_uid,
        .gid = proc->p_gid,
    };
	
    strlcpy(info->args, proc->p_comm, sizeof(info->args));

    (*cookie)++;

    return B_OK;
}

/* 
 * Macro to convert page counts to kilobytes.
 * (Multiply the number of pages by the page size and divide by 1024.)
 */
#define pagetok(x, ps) (((uint64_t)(x) * (ps)) / 1024)

status_t get_system_info(system_info *info)
{
    if (!info)
        return -1;

    int ret;
    size_t size;

    /*------------------------------------------------------------------
     * 1. Boot Time
     *------------------------------------------------------------------*/
    struct timeval boottime;
    size = sizeof(boottime);
    ret = sysctlbyname("kern.boottime", &boottime, &size, NULL, 0);
    if (ret < 0) {
        perror("sysctl kern.boottime failed");
        return -1;
    }
    info->boot_time = ((bigtime_t)boottime.tv_sec * 1000000LL) + boottime.tv_usec;

    /*------------------------------------------------------------------
     * 2. CPU Count
     *------------------------------------------------------------------*/
    int ncpu = 0;
    size = sizeof(ncpu);
    ret = sysctlbyname("hw.ncpu", &ncpu, &size, NULL, 0);
    if (ret < 0) {
        perror("sysctl hw.ncpu failed");
        return -1;
    }
    info->cpu_count = (uint32_t) ncpu;

    /*------------------------------------------------------------------
     * 3. Memory Statistics via vm.uvmexp2
     *------------------------------------------------------------------*/
    int mib[2] = {CTL_VM, VM_UVMEXP2};
    struct uvmexp_sysctl uvmexp;
    size = sizeof(uvmexp);
    ret = sysctl(mib, 2, &uvmexp, &size, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "sysctl VM_UVMEXP2 failed: %s\n", strerror(errno));
        return -1;
    }
    /* 
     * Use uvmexp.pagesize from the sysctl result (this should match getpagesize()).
     */
    unsigned int page_size = uvmexp.pagesize;

    /* Total accessible pages, in kilobytes */
    info->max_pages = uvmexp.npages;

    /* Used pages: for this example we consider active + wired pages as “in use” */
    info->used_pages = uvmexp.active + uvmexp.wired;

    /* Cached pages: we use the inactive pages */
    info->cached_pages = uvmexp.inactive;

    /* Block cache pages: we use file cache pages */
    info->block_cache_pages = uvmexp.filepages;

    /* Ignored pages: not available – set to 0 */
    info->ignored_pages = 0;

    /* Needed memory: not available – set to 0 */
    info->needed_memory = 0;

    /* Free memory: free pages converted to Kbytes */
    info->free_memory = pagetok(uvmexp.free, page_size);

    /*------------------------------------------------------------------
     * 4. Swap Statistics
     *------------------------------------------------------------------*/
    info->max_swap_pages = uvmexp.swpages;
    info->free_swap_pages = uvmexp.swpages - uvmexp.swpginuse;

    /*------------------------------------------------------------------
     * 5. Page Faults
     * (Not available; set to 0)
     *------------------------------------------------------------------*/
    info->page_faults = uvmexp.faults;

    /*------------------------------------------------------------------
     * 6. Semaphores, Ports, Threads, and Teams
     * (Not available; set all to 0)
     *------------------------------------------------------------------*/
    info->max_sems = 0;
    info->used_sems = 0;
    info->max_ports = 0;
    info->used_ports = 0;
    info->max_threads = 0;
    info->used_threads = 0;
    info->max_teams = 0;
    info->used_teams = 0;

    /*------------------------------------------------------------------
     * 7. Kernel Information
     *------------------------------------------------------------------*/
    {
        char kern_version[256];
        size = sizeof(kern_version);
        ret = sysctlbyname("kern.version", kern_version, &size, NULL, 0);
        if (ret < 0) {
            strncpy(info->kernel_name, "unknown", sizeof(info->kernel_name));
            info->kernel_name[sizeof(info->kernel_name) - 1] = '\0';
        } else {
            /* Copy up to B_FILE_NAME_LENGTH characters */
            strncpy(info->kernel_name, kern_version, B_FILE_NAME_LENGTH - 1);
            info->kernel_name[B_FILE_NAME_LENGTH - 1] = '\0';
        }
    }
    /* For build date, build time, kernel_version, and ABI, we don’t have direct sysctl calls.
       Set these to empty or 0. */
    info->kernel_build_date[0] = '\0';
    info->kernel_build_time[0] = '\0';
    info->kernel_version = 0;
    info->abi = 0;

    return 0;
}


int32
is_computer_on(void)
{
	return true;
}


double
is_computer_on_fire(void)
{
	return 0.63739;
}


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <kvm.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <fcntl.h>
#include <unistd.h>
#include <uvm/uvm_extern.h>
#include <OS.h>

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


    }

}

status_t get_thread_info(thread_id thread, thread_info *info) {

    int i;
    int lwp_count = 0;
    kvm_t *kd = NULL;
    
    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (kd == NULL)
        return -1;


    struct kinfo_lwp *lwps = kvm_getlwps(kd, getpid(), 0, sizeof(struct kinfo_lwp), &lwp_count);
    if (!lwps || lwp_count == 0) {
        kvm_close(kd);
        return -1;
    }

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
            return 0;
        }
    }

    kvm_close(kd);
    return -1;
}

status_t get_next_thread_info(team_id team, int32_t *cookie, thread_info *info) {
    static kvm_t *kd = NULL;
    static struct kinfo_lwp *lwps = NULL;
    static int lwp_count = 0;

    if (*cookie == 0) {
        if (kd)
            kvm_close(kd);
        kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
        if (!kd)
            return -1;

        lwps = kvm_getlwps(kd, team, 0, sizeof(struct kinfo_lwp), &lwp_count);
        if (!lwps || lwp_count == 0) {
            kvm_close(kd);
            kd = NULL;
            return -1;
        }
    }

    if (*cookie >= lwp_count) {
        kvm_close(kd);
        kd = NULL;
        return -1;  // No more threads
    }

    struct kinfo_lwp *lwp = &lwps[*cookie];
    (*cookie)++;

    /* Initialize the thread_info structure using a designated initializer */
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

    if (lwp->l_name)
        strlcpy(info->name, lwp->l_name, B_OS_NAME_LENGTH);
    else
        info->name[0] = '\0';

    return 0;
}



status_t get_team_info(team_id team, team_info *info) {
    
    int count = 0;
    kvm_t *kd;

    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (!kd)
        return -1;

    struct kinfo_proc2 *procs = kvm_getproc2(kd, KERN_PROC_PID, team,
                                              sizeof(struct kinfo_proc2), &count);
    if (!procs || count == 0) {
        kvm_close(kd);
        return -1;
    }

    struct kinfo_proc2 *proc = &procs[0];

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

    kvm_close(kd);
    
    return 0;
}


status_t get_next_team_info(int *cookie, team_info *info) {
    
    static kvm_t *kd = NULL;
    static struct kinfo_proc2 *procs = NULL;
    static int proc_count = 0;

    if (!info || !cookie)
        return -1;

    if (*cookie == 0) {
        if (kd)
            kvm_close(kd);
        kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
        if (!kd)
            return -1;

        procs = kvm_getproc2(kd, KERN_PROC_ALL, 0,
                             sizeof(struct kinfo_proc2), &proc_count);
        if (!procs || proc_count == 0) {
            kvm_close(kd);
            return -1;
        }
    }

    if (*cookie >= proc_count) {
        kvm_close(kd);
        kd = NULL;
        return -1;
    }

    struct kinfo_proc2 *proc = &procs[*cookie];
    (*cookie)++;

    *info = (team_info){
        .team                = proc->p_pid,
        .thread_count        = proc->p_nlwps,
        .image_count         = 0,
        .area_count          = 0,
        .debugger_nub_thread = -1,
        .debugger_nub_port   = -1,
    //    .argc                = proc->p_nargv,
        .uid                 = proc->p_uid,
        .gid                 = proc->p_gid
    };

    strlcpy(info->args, proc->p_comm, sizeof(info->args));

    return 0;
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

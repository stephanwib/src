
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

status_t get_thread_info(thread_id thread, thread_info *info) {
    if (!info) return -1;

    kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (!kd) return -1;

    struct kinfo_lwp *lwps;
    int count;
    pid_t pid = getpid();

    // Get thread info by LWP ID
    lwps = kvm_getlwps(kd, pid, thread, sizeof(struct kinfo_lwp), &count);
    if (!lwps || count == 0) {
        kvm_close(kd);
        return -1; // Thread not found
    }

    struct kinfo_lwp *lwp = &lwps[0];

    // Fill the thread_info struct
    info->thread = lwp->l_lid;
    info->team = lwp->l_pid; // LWP belongs to a process (team)
    info->state = lwp->l_stat; // Thread state
    info->priority = lwp->l_priority;
    info->sem = -1; // No direct semaphore ID mapping
    info->user_time = lwp->l_rtime_sec * 1000000LL + lwp->l_rtime_usec; // Convert to microseconds
    info->kernel_time = 0; // Not directly available
    info->stack_base = NULL; // Not directly available
    info->stack_end = NULL; // Not directly available

    // Retrieve thread name
    if (lwp->l_name) {
        strncpy(info->name, lwp->l_name, B_OS_NAME_LENGTH - 1);
        info->name[B_OS_NAME_LENGTH - 1] = '\0';
    } else {
        info->name[0] = '\0';
    }

    kvm_close(kd);
    return 0;
}

// Iterate through all threads
extern status_t get_next_thread_info(team_id team, int32_t *cookie, thread_info *info) {
    static kvm_t *kd = NULL;
    static struct kinfo_lwp *lwps = NULL;
    static int lwp_count = 0;

    if (!info || !cookie) return -1;

    if (*cookie == 0) {
        if (kd) kvm_close(kd);
        kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
        if (!kd) return -1;

        lwps = kvm_getlwps(kd, team, 0, sizeof(struct kinfo_lwp), &lwp_count);
        if (!lwps || lwp_count == 0) {
            kvm_close(kd);
            kd = NULL;
            return -1; // No threads found for this team
        }
    }

    if (*cookie >= lwp_count) {
        kvm_close(kd);
        kd = NULL;
        return -1; // No more threads
    }

    struct kinfo_lwp *lwp = &lwps[*cookie];
    (*cookie)++;

    info->thread = lwp->l_lid;
    info->team = lwp->l_pid;
    info->state = lwp->l_stat;
    info->priority = lwp->l_priority;
    info->sem = -1;
    info->user_time = lwp->l_rtime_sec * 1000000LL + lwp->l_rtime_usec;
    info->kernel_time = 0;
    info->stack_base = NULL;
    info->stack_end = NULL;

    if (lwp->l_name) {
        strncpy(info->name, lwp->l_name, B_OS_NAME_LENGTH - 1);
        info->name[B_OS_NAME_LENGTH - 1] = '\0';
    } else {
        info->name[0] = '\0';
    }

    return 0; // Success
}



int get_team_info(team_id team, team_info *info) {
    if (!info) return -1;

    kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
    if (!kd) return -1;

    struct kinfo_proc2 *procs;
    int count;

    // Get process info
    procs = kvm_getproc2(kd, KERN_PROC_PID, team, sizeof(struct kinfo_proc2), &count);
    if (!procs || count == 0) {
        kvm_close(kd);
        return -1; // Process not found
    }

    struct kinfo_proc2 *proc = &procs[0];

    // Fill the team_info struct
    info->team = proc->p_pid;
    info->thread_count = proc->p_nlwps;  // Number of threads (LWPs)
    info->image_count = 0;               // Not directly available
    info->area_count = 0;                // Not directly available
    info->debugger_nub_thread = -1;      // Not applicable
    info->debugger_nub_port = -1;        // Not applicable
    // info->argc = proc->p_nargv;          // Number of arguments
    info->uid = proc->p_uid;             // User ID
    info->gid = proc->p_gid;             // Group ID

    // Retrieve command-line arguments (limited to 64 bytes)
    if (proc->p_comm) {
        strncpy(info->args, proc->p_comm, sizeof(info->args) - 1);
        info->args[sizeof(info->args) - 1] = '\0';
    } else {
        info->args[0] = '\0';
    }

    kvm_close(kd);
    return 0;
}


// Iterate through all processes
int get_next_team_info(int *cookie, team_info *info) {
    static kvm_t *kd = NULL;
    static struct kinfo_proc2 *procs = NULL;
    static int proc_count = 0;

    if (!info) return -1;

    if (*cookie == 0) {
        if (kd) kvm_close(kd);
        kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, NULL);
        if (!kd) return -1;

        procs = kvm_getproc2(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), &proc_count);
        if (!procs || proc_count == 0) {
            kvm_close(kd);
            kd = NULL;
            return -1; // No processes found
        }
    }

    if (*cookie >= proc_count) {
        kvm_close(kd);
        kd = NULL;
        return -1; // No more processes
    }

    struct kinfo_proc2 *proc = &procs[*cookie];
    (*cookie)++;

    info->team = proc->p_pid;
    info->thread_count = proc->p_nlwps;
    info->image_count = 0;
    info->area_count = 0;
    info->debugger_nub_thread = -1;
    info->debugger_nub_port = -1;
    // info->argc = proc->p_nargv;
    info->uid = proc->p_uid;
    info->gid = proc->p_gid;

    if (proc->p_comm) {
        strncpy(info->args, proc->p_comm, sizeof(info->args) - 1);
        info->args[sizeof(info->args) - 1] = '\0';
    } else {
        info->args[0] = '\0';
    }

    return 0;
}


/* 
 * Macro to convert page counts to kilobytes.
 * (Multiply the number of pages by the page size and divide by 1024.)
 */
#define pagetok(x, ps) (((uint64_t)(x) * (ps)) / 1024)

int get_system_info(system_info *info)
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
    info->max_pages = pagetok(uvmexp.npages, page_size);

    /* Used pages: for this example we consider active + wired pages as “in use” */
    info->used_pages = pagetok(uvmexp.active + uvmexp.wired, page_size);

    /* Cached pages: we use the inactive pages */
    info->cached_pages = pagetok(uvmexp.inactive, page_size);

    /* Block cache pages: we use file cache pages */
    info->block_cache_pages = pagetok(uvmexp.filepages, page_size);

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

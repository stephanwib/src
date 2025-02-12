
#include <stdio.h>
#include <string.h>
#include <kvm.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <fcntl.h>
#include <unistd.h>
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
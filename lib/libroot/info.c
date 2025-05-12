
#include <stdio.h>
#include <stdlib.h>
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




/* Following functions taken from Cosmoe
* Copyright (c) 2003 Tom Marshall, 2003-2024 Bill Hayden
* XXX: NetBSD variant should be rewritten to using /dev/cpuctl
*/


status_t 
get_cpu_topology_info(cpu_topology_node_info* topologyInfos, uint32* topologyInfoCount)
{
*topologyInfoCount = 3;

if (topologyInfos == NULL)
return B_ERROR;

topologyInfos[0].type = B_TOPOLOGY_ROOT;

#if defined(__x86_64__) || defined(_M_X64)
topologyInfos[0].data.root.platform = B_CPU_x86_64;
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
topologyInfos[0].data.root.platform = B_CPU_x86;
#elif defined(__aarch64__) || defined(_M_ARM64)
topologyInfos[0].data.root.platform = B_CPU_ARM_64;
#elif defined(mips) || defined(__mips__) || defined(__mips)
topologyInfos[0].data.root.platform = B_CPU_MIPS;
#elif defined(__sh__)
topologyInfos[0].data.root.platform = B_CPU_SH;
#elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
topologyInfos[0].data.root.platform = B_CPU_PPC;
#elif defined(__PPC64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
topologyInfos[0].data.root.platform = B_CPU_PPC_64;
#elif defined(__sparc__) || defined(__sparc)
topologyInfos[0].data.root.platform = B_CPU_SPARC;
#elif defined(__m68k__)
topologyInfos[0].data.root.platform = B_CPU_M68K,
#else
topologyInfos[0].data.root.platform = B_CPU_UNKNOWN;
#endif

topologyInfos[1].type = B_TOPOLOGY_PACKAGE;

#if defined(__x86_64__) || defined(_M_X64)
topologyInfos[1].data.package.vendor = B_CPU_VENDOR_INTEL;
#elif defined(__aarch64__) || defined(_M_ARM64)
topologyInfos[1].data.package.vendor = B_CPU_VENDOR_ARM;
#endif

topologyInfos[2].type = B_TOPOLOGY_CORE;

FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
if (cpuinfo != NULL)
{
char line[256];
float speed;
int model;

while (fgets(line, sizeof(line), cpuinfo))
{
if (sscanf(line, "cpu MHz		: %f", &speed) == 1)
{
topologyInfos[2].data.core.default_frequency = (uint64)(speed * 1000000.0);
}

if (sscanf(line, "model		: %d", &model) == 1)
{
topologyInfos[2].data.core.model = model;
}
}

fclose(cpuinfo);
}

return B_OK;
}


status_t 
_get_cpu_info_etc(uint32 firstCPU, uint32 cpuCount, cpu_info* info, size_t size)
{
if (info == NULL)
return B_ERROR;

if (size != sizeof(cpu_info))
return B_ERROR;

FILE*         fp;
int           ncpu;
char          buf[80];
char*         p;

ncpu = 1;
if( (fp = fopen( "/proc/cpuinfo", "r" )) != NULL )
{
while( fgets( buf, sizeof(buf), fp ) != NULL )
{
if ( strncmp( buf, "processor\t", 10 ) == 0 )
{
ncpu++;
}

if (strncmp( buf, "cpu MHz\t", 8 ) == 0)
{
p = strchr( buf, ':' );
if( p != NULL )
{
info->current_frequency = atoi( p+2 );
}
}
}
fclose( fp );
}

#if 0
bigtime_t     systime;
bigtime_t     idletime;
unsigned long n1, n2, n3, nidle;

psInfo->cpu_count = ncpu;

if( (fp = fopen( "/proc/stat", "r" )) != NULL )
{
while( fgets( buf, sizeof(buf), fp ) != NULL )
{
if( ncpu == 1 && strncmp( buf, "cpu ", 4 ) == 0 )
{
/* there are no cpuN lines, use the overall stat */
sscanf( buf+4, "%lu %lu %lu %lu", &n1, &n2, &n3, &nidle );
idletime = (bigtime_t)nidle * 10000LL;
info->cpu_infos[0].active_time = systime - idletime;
break;
}

if( strncmp( buf, "cpu", 3 ) == 0 )
{
sscanf( buf+3, "%d %lu %lu %lu %lu", &ncpu, &n1, &n2, &n3, &nidle );
if( ncpu < info->cpu_count )
{
idletime = (bigtime_t)nidle * 10000LL;
info->cpu_infos[ncpu].active_time = systime - idletime;
}
}
}
fclose( fp );
}
#endif


info->enabled = true;
return B_OK;
}

#if defined(__i386__) || defined(__x86_64__)
status_t
get_cpuid(cpuid_info *info, uint32 eaxRegister, uint32 cpuNum)
{
return B_ERROR;
}
#endif



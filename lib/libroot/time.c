

#include <OS.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>

bigtime_t system_time() {
    struct timeval boottime;
    size_t size = sizeof(boottime);
    struct timeval now;
    struct timezone timezone;
    
    if (sysctlbyname("kern.boottime", &boottime, &size, NULL, 0) != 0) {
        return -1;
    }

    (void)gettimeofday(&now, &timezone);

    // Calculate the uptime in microseconds
    time_t seconds = now.tv_sec - boottime.tv_sec;
    suseconds_t microseconds = now.tv_usec - boottime.tv_usec;
    return (bigtime_t)seconds * 1000000 + microseconds;
}


uint32 real_time_clock() {
    struct timeval now;
    struct timezone timezone;
    
    (void)gettimeofday(&now, &timezone);
        
    return tv.tv_sec;
}

// Get the current real-time clock in microseconds
bigtime_t real_time_clock_usecs() {
    struct timeval now;
    struct timezone timezone;
    
    (void)gettimeofday(&now, &timezone);

    return (bigtime_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

// Set the real-time clock to a new value
void set_real_time_clock(int32 new_time) {
    struct timeval tv;
    struct timezone timezone;
    
    tv.tv_sec = new_time;
    tv.tv_usec = 0;

    // XXX: Call to settimeofday() may fail due to several reasons, but this void function
    // does not allow to report back errors
    
    (void)settimeofday(&tv, &timezone);
}

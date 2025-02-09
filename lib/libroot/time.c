

#include <OS.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>


bigtime_t system_time(void) {
    struct timeval boottime;
    size_t size = sizeof(boottime);
    struct timeval now;
    struct timezone tz;
    
    if (sysctlbyname("kern.boottime", &boottime, &size, NULL, 0) != 0) {
        return -1;
    }

    (void)gettimeofday(&now, &tz);

    // Calculate the uptime in microseconds
    time_t seconds = now.tv_sec - boottime.tv_sec;
    suseconds_t microseconds = now.tv_usec - boottime.tv_usec;
    return (bigtime_t)seconds * 1000000 + microseconds;
}



unsigned long real_time_clock(void) {
    struct timeval now;
    struct timezone tz;
    
    (void)gettimeofday(&now, &tz);
        
    return now.tv_sec;
}



bigtime_t real_time_clock_usecs(void) {
    struct timeval now;
    struct timezone tz;
    
    (void)gettimeofday(&now, &tz);

    return (bigtime_t)now.tv_sec * 1000000 + now.tv_usec;
}


void set_real_time_clock(unsigned long new_time) {
    struct timeval tv;
    struct timezone tz;
    
    tv.tv_sec = new_time;
    tv.tv_usec = 0;

    // XXX: Call to settimeofday() may fail due to several reasons, but this void function
    // does not allow to report back errors
    
    (void)settimeofday(&tv, &tz);
}

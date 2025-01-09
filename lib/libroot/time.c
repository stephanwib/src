


#include <sys/sysctl.h>
#include <sys/time.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>

bigtime_t system_time() {
    struct timeval boottime;
    size_t size = sizeof(boottime);
    struct timeval now;
    
    if (sysctlbyname("kern.boottime", &boottime, &size, NULL, 0) != 0) {
        return -1;
    }

    if (gettimeofday(&now, NULL) != 0) {
        return -1;
    }

    // Calculate the uptime in microseconds
    time_t seconds = now.tv_sec - boottime.tv_sec;
    suseconds_t microseconds = now.tv_usec - boottime.tv_usec;
    return (bigtime_t)seconds * 1000000 + microseconds;
}


time_t real_time_clock() {
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        return (time_t)-1;
    }

    return tv.tv_sec;
}

// Get the current real-time clock in microseconds
bigtime_t real_time_clock_usecs() {
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        return -1;
    }

    return (bigtime_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

// Set the real-time clock to a new value
void set_real_time_clock(int32 new_time) {
    struct timeval tv;

    tv.tv_sec = new_time;
    tv.tv_usec = 0;

    // Use settimeofday to update the system clock
    if (settimeofday(&tv, NULL) != 0) {
        return;
    }

    return;
}

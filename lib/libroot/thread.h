


#include <sys/queue.h>

#define MSG_PRIVATE_BUFFER_SIZE     1024

enum THREAD_MESSAGE {
    THR_MSG_ABSENT  = 0,
    THR_MSG_INTERN,
    THR_MSG_EXTERN
};

typedef struct thread_message {
    int32                       tm_code;                                /* private message code */
    char                        tm_buffer[MSG_PRIVATE_BUFFER_SIZE];     /* small message private buffer  */
    const void                  *tm_external_buffer;                    /* large message external buffer */
    pthread_cond_t              *tm_msg_cv;                             /* wait for message event */
} thread_message;

typedef struct haiku_thread {
    pthread_t                   ht_pt;             /* POSIX thread*/
    lwpid_t                     ht_lid;            /* kernel LWP ID */
    LIST_ENTRY(haiku_thread)    ht_entry;    /* libroot thread list entry */
    int                         ht_message;        /* has private thread message */
    thread_message              ht_msg;            /* thread private message for send_data() / receive_data() */

} haiku_thread;

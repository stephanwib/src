


#include <sys/queue.h>

#define MSG_PRIVATE_BUFFER_SIZE     1024

enum THREAD_STATE {
    THR_ACTIVE,
    THR_ENDING
};

enum THREAD_MESSAGE {
    THR_MSG_ABSENT  = 0,
    THR_MSG_INTERN,
    THR_MSG_EXTERN
};

typedef struct thread_message {
    int32                       tm_code;                                /* private message code */
    char                        tm_buffer[MSG_PRIVATE_BUFFER_SIZE];     /* small message private buffer  */
    size_t                      tm_size;                                /* private data bytes */
    void                       *tm_external_buffer;                    /* large message external buffer */
    thread_id                   tm_sender;                              /* thread ID of the sender */
} thread_message;

typedef struct haiku_thread {
    pthread_t                   ht_pt;             /* POSIX thread*/
    lwpid_t                     ht_lid;            /* kernel LWP ID */
    LIST_ENTRY(haiku_thread)    ht_entry;          /* libroot thread list entry */
    int                         ht_state;          /* state of this thread */
    pthread_cond_t              ht_cv;             /* state change event */
    int                         ht_waiters;        /* threads waiting on this object */
    int                         ht_message;        /* has private thread message */
    thread_message              ht_msg;            /* thread private message for send_data() / receive_data() */

} haiku_thread;

#ifndef _WAF
#define _WAF

#include <pthread.h>

#define WAF_BUFF 256

typedef void (*waf_hook)(char *buff, int size, void *args);

typedef enum{
    NO_BUFF, LINE_BUFF, FULL_BUFF
} waf_mode;

typedef struct _waf{
    int stdin_pipe[2];
    int stdout_pipe[2];
    int stderr_pipe[2];
    pthread_mutex_t mutex;
    waf_mode mode;
    waf_hook stdin_hook;
    void *stdin_args;
    waf_hook stdout_hook;
    void *stdout_args;
    waf_hook stderr_hook;
    void *stderr_args;
} waf_t;

waf_t *create_waf();
void delete_waf(waf_t *waf);

int start_stream_waf(waf_t *waf, const char *cmd, char* const argv[], char* const envp[]);

#endif

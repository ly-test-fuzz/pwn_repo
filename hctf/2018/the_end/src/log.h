#ifndef _LOG
#define _LOG

#include <stdio.h>

typedef enum{
    NORMAL, INPUT, OUTPUT, ERROR
} log_type;

typedef struct _log_t{
    FILE *fp;
    const char *name;
    log_type status;
} log_t;

log_t *open_log(const char *log_name);
void close_log(log_t *log);

void write_log(log_t *log, char *buff, int size, log_type type);

#endif

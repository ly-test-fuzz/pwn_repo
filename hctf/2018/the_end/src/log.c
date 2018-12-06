#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "log.h"


log_t *open_log(const char *log_name){
    log_t *log = (log_t *)malloc(sizeof(struct _log_t));

    if(log == NULL){
        perror("malloc log memory fail");
        exit(errno);
    }

    log->fp = fopen(log_name, "a+");

    if(log->fp == NULL){
        free(log);
        perror("open log file fail");
        exit(errno);
    }

    log->name = log_name;
    log->status = NORMAL;

    return log;
}

void close_log(log_t *log){
    if(log->fp != NULL){
        fclose(log->fp);
        log->fp = NULL;
    }

    log->name = NULL;
    log->status = NORMAL;

    free(log);
}

void write_log(log_t *log, char *buff, int size, log_type type){
    char tmp[8];
    if(type != log->status && type == INPUT){
        fwrite("\n[Input]\n", 9, 1, log->fp);
        log->status = INPUT;
    }else if(type != log->status && type == OUTPUT){
        fwrite("\n[Output]\n", 10, 1, log->fp);
        log->status = OUTPUT;
    }else if(type != log->status && type == ERROR){
        fwrite("\n[Error]\n", 9, 1, log->fp);
        log->status = ERROR;
    }

    // write log
    fwrite(buff, size, 1, log->fp);
    fflush(log->fp);
}

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "waf.h"
#include "log.h"


void input(char *, int, void *);
void output(char *, int, void *);
void errput(char *, int, void *);


const char *log_name = "waf_log";
const char *elf_name = "./pwn";


int main(int argc, char **argv){
    waf_t *waf = create_waf();
    log_t *log = open_log(log_name);

    waf->mode = NO_BUFF;
    waf->stdin_hook = &input;
    waf->stdin_args = log;
    waf->stdout_hook = &output;
    waf->stdout_args = log;
    waf->stderr_hook = &errput;
    waf->stderr_args = log;

    char buff[256];
    time_t t = time(NULL);
    sprintf(buff, "\n----------\n%s----------\n", ctime(&t));
    write_log(log, buff, strlen(buff), NORMAL);

    return start_stream_waf(waf, elf_name, NULL, NULL);
}

void input(char *buff, int size, void *args){
    log_t *log = (log_t *)args;

    write_log(log, buff, size, INPUT);
}

void output(char *buff, int size, void *args){
    log_t *log = (log_t *)args;
    write_log(log, buff, size, OUTPUT);
}

void errput(char *buff, int size, void *args){
    log_t *log = (log_t *)args;

    write_log(log, buff, size, ERROR);
}

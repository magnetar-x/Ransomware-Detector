#ifndef EVENT_DEFS_H
#define EVENT_DEFS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Syscall type definitions
#define SYS_OPEN   1
#define SYS_WRITE  2
#define SYS_RENAME 3
#define SYS_UNLINK 4

struct fs_event_t {
    unsigned long long ts;
    unsigned int pid;
    unsigned int uid;
    int syscall_type; 
    unsigned long bytes_req;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif

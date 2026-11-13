#ifndef EVENT_DEFS_H
#define EVENT_DEFS_H

#define MAX_FILENAME_LEN 256
#define PAYLOAD_SAMPLE_SIZE 64
#define TASK_COMM_LEN 16

enum event_type_e {
    EVENT_OPEN   = 1,
    EVENT_WRITE  = 2,
    EVENT_RENAME = 3,
    EVENT_UNLINK = 4,
    EVENT_CLOSE  = 5
};

struct file_event_t {
    unsigned long long timestamp_ns;
    unsigned int pid;
    unsigned int tid;
    unsigned int uid;
    unsigned int event_type;
    int fd;
    unsigned long long bytes_count;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char new_filename[MAX_FILENAME_LEN];
    unsigned char payload_sample[PAYLOAD_SAMPLE_SIZE];
};

#endif // EVENT_DEFS_H

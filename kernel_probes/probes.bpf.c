#include <linux/ptrace.h>
#include <linux/unistd.h>
#include "../common/event_defs.h"

struct open_args_t {
    char filename[MAX_FILENAME_LEN];
};

struct path_value_t {
    char filename[MAX_FILENAME_LEN];
};

/* Keys are tgid/tid pairs for fd mappings, and tids for pending openat calls. */
BPF_HASH(pending_open, u32, struct open_args_t);
BPF_HASH(fd_paths, u64, struct path_value_t);
BPF_HASH(ignored_pids, u32, u8);
BPF_PERF_OUTPUT(events);

static __always_inline u32 current_tgid(void)
{
    return (u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline u32 current_tid(void)
{
    return (u32)bpf_get_current_pid_tgid();
}

static __always_inline u64 fd_key(u32 tgid, int fd)
{
    return ((u64)tgid << 32) | (u32)fd;
}

static __always_inline int is_ignored(void)
{
    u32 pid = current_tgid();
    return ignored_pids.lookup(&pid) != 0;
}

static __always_inline int is_pseudo_path(const char *path)
{
    char prefix[6] = {};
    bpf_probe_read_kernel(prefix, sizeof(prefix), path);
    return (prefix[0] == '/' && prefix[1] == 'p' && prefix[2] == 'r' && prefix[3] == 'o' && prefix[4] == 'c') ||
           (prefix[0] == '/' && prefix[1] == 's' && prefix[2] == 'y' && prefix[3] == 's') ||
           (prefix[0] == '/' && prefix[1] == 'd' && prefix[2] == 'e' && prefix[3] == 'v') ||
           (prefix[0] == '/' && prefix[1] == 'r' && prefix[2] == 'u' && prefix[3] == 'n');
}

static __always_inline void init_event(struct file_event_t *event, u32 type)
{
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_tgid();
    event->tid = current_tid();
    event->uid = (u32)(bpf_get_current_uid_gid() & 0xffffffff);
    event->event_type = type;
    event->fd = -1;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

static __always_inline void submit_path_event(void *ctx, u32 type, const char *path)
{
    struct file_event_t event = {};
    init_event(&event, type);
    bpf_probe_read_user(&event.filename, sizeof(event.filename), path);
    if (is_pseudo_path(event.filename))
        return;
    events.perf_submit(ctx, &event, sizeof(event));
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    if (is_ignored())
        return 0;
    struct open_args_t value = {};
    bpf_probe_read_user(&value.filename, sizeof(value.filename), args->filename);
    u32 tid = current_tid();
    pending_open.update(&tid, &value);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat)
{
    if (is_ignored())
        return 0;
    u32 tid = current_tid();
    struct open_args_t *pending = pending_open.lookup(&tid);
    if (!pending)
        return 0;

    int fd = args->ret;
    if (fd >= 0) {
        struct file_event_t event = {};
        init_event(&event, EVENT_OPEN);
        event.fd = fd;
        __builtin_memcpy(event.filename, pending->filename, sizeof(event.filename));
        if (!is_pseudo_path(event.filename)) {
            struct path_value_t value = {};
            __builtin_memcpy(value.filename, event.filename, sizeof(value.filename));
            u64 key = fd_key(event.pid, fd);
            fd_paths.update(&key, &value);
            events.perf_submit(args, &event, sizeof(event));
        }
    }
    pending_open.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    if (is_ignored())
        return 0;
    u32 pid = current_tgid();
    int fd = args->fd;
    u64 key = fd_key(pid, fd);
    struct path_value_t *path = fd_paths.lookup(&key);
    struct file_event_t event = {};
    init_event(&event, EVENT_WRITE);
    event.fd = fd;
    event.bytes_count = args->count;
    bpf_probe_read_user(&event.payload_sample, sizeof(event.payload_sample), args->buf);
    if (path)
        __builtin_memcpy(event.filename, path->filename, sizeof(event.filename));
    if (is_pseudo_path(event.filename))
        return 0;
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat)
{
    if (is_ignored())
        return 0;
    struct file_event_t event = {};
    init_event(&event, EVENT_RENAME);
    bpf_probe_read_user(&event.filename, sizeof(event.filename), args->oldname);
    bpf_probe_read_user(&event.new_filename, sizeof(event.new_filename), args->newname);
    if (!is_pseudo_path(event.filename) && !is_pseudo_path(event.new_filename))
        events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2)
{
    if (is_ignored())
        return 0;
    struct file_event_t event = {};
    init_event(&event, EVENT_RENAME);
    bpf_probe_read_user(&event.filename, sizeof(event.filename), args->oldname);
    bpf_probe_read_user(&event.new_filename, sizeof(event.new_filename), args->newname);
    if (!is_pseudo_path(event.filename) && !is_pseudo_path(event.new_filename))
        events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    if (is_ignored())
        return 0;
    submit_path_event(args, EVENT_UNLINK, args->pathname);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close)
{
    if (is_ignored())
        return 0;
    u32 pid = current_tgid();
    int fd = args->fd;
    u64 key = fd_key(pid, fd);
    struct path_value_t *path = fd_paths.lookup(&key);
    if (path) {
        struct file_event_t event = {};
        init_event(&event, EVENT_CLOSE);
        event.fd = fd;
        __builtin_memcpy(event.filename, path->filename, sizeof(event.filename));
        if (!is_pseudo_path(event.filename))
            events.perf_submit(args, &event, sizeof(event));
        fd_paths.delete(&key);
    }
    return 0;
}

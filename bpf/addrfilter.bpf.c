//go:build exclude

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <stdbool.h>

#define MAX_KILL_ENTRIES 4096
#define MAX_FOLLOW_ENTRIES 1024

enum stat_type {
    GET_CUR_TASK_FAILED, /* when the bpf helper get_current_task fails */
    TP_ENTERED,  /* every time syscall is entered */
    IGNORE_PID,  /* dont filter, PID isn't being traced */
    KILL_RINGBUF_RESERVE_FAILED,
    PID_READ_FAILED,
    STAT_END,
};

#define N_STAT_TYPES STAT_END
enum stat_type *unused_stat_type __attribute__((unused));


/*  stat_map holds stats about program execution.
    Write to it with the `record_stat` helper.

    stat_map needs to be configured in userspace with all fields zerod  */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, N_STAT_TYPES);
    __uint(map_flags, 0);
} stats_map SEC(".maps");


/*  protect_map contains PID(s) that the filter should be applied to.

    protect_map only determines whether a process should be filtered or not.
    it contains no information about the filter itself.
*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(bool));
	__uint(max_entries, MAX_FOLLOW_ENTRIES);
	__uint(map_flags, 0);
} protect_map SEC(".maps");


/*
kill_map contains PIDs for the frontend to kill

killing a process cannot be done from BPF, so the best
thing to do is let the frontend handle it.
*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_KILL_ENTRIES);
} kill_map SEC(".maps");


/* vm_range stores the start and end of a memory mapped region. */
struct vm_range {
    u64 start;
    u64 end;
};

struct vm_range *unused_vm_range __attribute__((unused));


/*  libc_ranges_map stores the memory location of libc for each process.

    It is used while walking the stack in-kernel to identify the first non-libc
    sycall call site, so that the correct filter can be applied.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(pid_t));
    __uint(value_size, sizeof(struct vm_range));
    __uint(max_entries, MAX_FOLLOW_ENTRIES);
    __uint(map_flags, 0);
} libc_ranges_map SEC(".maps");


/*   record_stat logs an event in the stats map. Fails silently!

    Every return statement should be preceeded by a call to record_stat.
*/
__always_inline void record_stat(enum stat_type stat) {
    u64 *s_count =bpf_map_lookup_elem(&stats_map, &stat);
    if (!s_count) {
        return;
    }

    __sync_fetch_and_add(s_count, 1);
}

/* kill is a helper which instructs the frontend to kill a PID. */
__always_inline void kill(pid_t pid) {
    pid_t *kill;
    kill = bpf_ringbuf_reserve(&kill_map, sizeof(pid_t), 0);
    if (!kill) {
        record_stat(KILL_RINGBUF_RESERVE_FAILED);
        return;
    }

    *kill = pid;

    bpf_ringbuf_submit(kill, 0);
}


SEC("raw_tp/sys_enter")
int addrfilter(struct bpf_raw_tracepoint_args *ctx) {
    record_stat(TP_ENTERED);

    pid_t pid;
    struct task_struct *task;

    task = (struct task_struct*)bpf_get_current_task();
    if (!task) {
        record_stat(GET_CUR_TASK_FAILED);
        return 1;
    }

    int res;
    res = bpf_probe_read(&pid, sizeof(pid), &task->tgid);
    if (res != 0) {
        record_stat(PID_READ_FAILED);
        return 1;
    }

    bool *protect = (bool *)bpf_map_lookup_elem(&protect_map, &pid);
    if (!protect) {
        record_stat(IGNORE_PID);
        return 0;
    }

   kill(pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

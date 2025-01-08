//go:build exclude

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include <stdbool.h>

#define MAX_KILL_ENTRIES 4096
#define MAX_FOLLOW_ENTRIES 1024
#define MAX_STACK_DEPTH 32

#define DEBUG 1

enum stat_type {
    GET_CUR_TASK_FAILED, /* when the bpf helper get_current_task fails */
    TP_ENTERED,  /* every time syscall is entered */
    IGNORE_PID,  /* dont filter, PID isn't being traced */
    KILL_RINGBUF_RESERVE_FAILED,  /* failed to reserve a slot in the kill ringbuffer */
    PID_READ_FAILED,  /* failed to read PID from current task */
    LIBC_NOT_LOADED,  /* Libc address space not loaded for current PID */
    GET_STACK_FAILED,  /* bpf_get_stack helper returned a non-0 error */
    CALLSITE_LIBC,  /* no non-libc call site could be found */
    STACK_TOO_SHORT, /* no non-libc call site could be found AND last read RP != 0*/
    STAT_END,  /* not an event: used to autogenerate number of stat types for frontend */
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


struct stack_trace_t {
    int frames_walked;
    u64 callsite;
    u64 stacktrace[MAX_STACK_DEPTH];
};

struct stack_trace_t *unused_st_dbg __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int32));
    __uint(value_size, sizeof(struct stack_trace_t));
    __uint(max_entries, 1);
    __uint(map_flags, 0);
} stack_dbg_map SEC(".maps");


/*   record_stat logs an event in the stats map. Fails silently!

    args:
        stat: statistic to log

    returns:
        void: This means that the update fails silently, but what is there
                to do if logging doesn't work?

    Every return statement should be preceeded by a call to record_stat.
*/
__always_inline void record_stat(enum stat_type stat) {
    u64 *s_count =bpf_map_lookup_elem(&stats_map, &stat);
    if (!s_count) {
        return;
    }

    __sync_fetch_and_add(s_count, 1);
}

/* kill is a helper which instructs the frontend to kill a PID.

    args:
        pid: pid of process to kill

    returns:
        void
*/
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


/*  find_syscall_site walks the stack to find the first non-libc return pointer.

    for this, it uses information from the libc_ranges_map.
    If identification fails, a reason will be logged by the function.

    args:
        ctx: pointer to raw tracepoint args (used by bpf_get_stack)
         rp: address to write syscall site to.
        pid: calling pid

    returns:
         0 on success,
        -1 on exit.
*/
__always_inline int find_syscall_site(struct bpf_raw_tracepoint_args *ctx, u64* rp, pid_t pid) {
    struct vm_range *libc_range = (struct vm_range *)bpf_map_lookup_elem(&libc_ranges_map, &pid);
    if (!libc_range) {
        record_stat(LIBC_NOT_LOADED);
        return -1;
    }

    const int32 zero = 0;
    struct stack_trace_t *r = (struct stack_trace_t*)bpf_map_lookup_elem(&stack_dbg_map, &zero);
    if (!r) {

        return -1;
    }

    int stack_size = bpf_get_stack(
        ctx,
        r->stacktrace,
        MAX_STACK_DEPTH * sizeof(u64),
        BPF_F_USER_STACK
    );
    if (stack_size <= 0) {
        record_stat(GET_STACK_FAILED);
        return -1;
    };

    int frames = stack_size / 8;  // each return pointer is 8B i.e. 64bit
    r->frames_walked = 0;

    for (int i = 0; i < frames; i++) {
        /* this is logically superfluous, but must be kept to keep the verifier happy */
        if (i >= sizeof(r->stacktrace) / sizeof(u64)) {
            return -1;
        }

        r->callsite = r->stacktrace[i];
        if (libc_range->start <= r->callsite && r->callsite < libc_range->end) {
            break;
        }

        r->frames_walked++;
    }

    rp = &r->callsite;
    if (rp == 0) {
        record_stat(CALLSITE_LIBC);
    }

    if (rp == 0 && r->stacktrace[frames-1] != 0) {
        record_stat(STACK_TOO_SHORT);
    }

    return 0;
}


SEC("raw_tp/sys_enter")
int addrfilter(struct bpf_raw_tracepoint_args *ctx) {
    record_stat(TP_ENTERED);

    u64* rp;
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

    res = find_syscall_site(ctx, rp, pid);
    if (res != 0) {
        return -1;
    }

    kill(pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

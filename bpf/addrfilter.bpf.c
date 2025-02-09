//go:build exclude

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <stdbool.h>


/* (Some) Numbers are all arbitrary. todo: make them meaningful */
#define MAX_KILL_ENTRIES 4096  // needs to be a page size multiple
#define MAX_FOLLOW_ENTRIES 1024  /* maximum number of processes that addrfilter will protect */
#define MAX_STACK_DEPTH 32
#define MAX_FILENAME_LEN 256
#define MAX_ADDRSPACE_LEN 128  /* maximum supported number of ways of "slicing up" address space */

#define SIGKILL 9

/* MAX_SYSCALL_NUMBER determined by taking the highest
   defined constant in /usr/include/asm/unistd_64.h */
#define MAX_SYSCALL_NUMBER 461


enum stat_type {
    GET_CUR_TASK_FAILED, /* when the bpf helper get_current_task fails */
    TP_ENTERED,  /* every time syscall is entered */
    IGNORE_PID,  /* don't filter, PID isn't being traced */
    KILL_RINGBUF_RESERVE_FAILED,  /* failed to reserve a slot in the kill ringbuffer */
    PID_READ_FAILED,  /* failed to read PID from current task */
    LIBC_NOT_LOADED,  /* Libc address space not loaded for current PID */
    GET_STACK_FAILED,  /* bpf_get_stack helper returned a non-0 error */
    CALLSITE_LIBC,  /* no non-libc call site could be found */
    STACK_TOO_SHORT, /* no non-libc call site could be found AND last read RP != 0 */
    NO_RP_MAPPING, /* rp didn't come from mapped space */
    FILENAME_TOO_LONG, /* filename was longer than MAX_FILENAME_LEN characters */
    FIND_VMA_FAILED, /* failed to find vma from rp */
    STAT_END,  /* not an event: used to autogenerate number of stat types for frontend */
};

#define N_STAT_TYPES STAT_END


/* stack_trace_t is used to report the stack trace of a
   blocked syscall to userspace.*/
struct stack_trace_t {
    int frames_walked;
    u64 callsite;
    u64 stacktrace[MAX_STACK_DEPTH];
};


/* vm_range stores the start and end of a memory mapped region */
struct vm_range {
    u64 start;
    u64 end;
    char filename[MAX_FILENAME_LEN];
};


struct vm_range *unused_vm_range __attribute__((unused));
enum stat_type *unused_stat_type __attribute__((unused));
struct stack_trace_t *unused_st_dbg __attribute__((unused));


/*  stat_map holds stats about program execution.
    write to it with the `record_stat` helper.

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


/*  libc_ranges_map stores the memory location of libc for each process.

    it is used while walking the stack in-kernel to identify the first non-libc
    sycall call site, so that the correct filter can be applied.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(pid_t));
    __uint(value_size, sizeof(struct vm_range));
    __uint(max_entries, MAX_FOLLOW_ENTRIES);
    __uint(map_flags, 0);
} libc_ranges_map SEC(".maps");


/* path_whitelist_map associates a path in /proc/PID/maps with a syscall whitelist.

  note that this is NOT PID SPECIFIC, as it would be too complicated to generate whitelists which are fork specific.
  thus, whitelists need to be generated with this behaviour in mind.

  that is, for each library, the whitelist must include all syscalls made by each fork.
  this design supports the address space of forks changing, but not whitelists changing.
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(char[MAX_FILENAME_LEN]));  /* keyed by pathname in process virtual address space */
    __uint(value_size, sizeof(bool[MAX_SYSCALL_NUMBER])); /* whitelist format: TRUE => allow syscall, FALSE => block syscall */
    __uint(max_entries, MAX_ADDRSPACE_LEN);  /* at most one whitelist for each "slice" of address space */
    __uint(map_flags, 0);
} path_whitelist_map SEC(".maps");


/* stack_dbg_map is used to hold the stacktrace on each system call.

  thus, the stacktrace that lead to the blocked system call is available to userspace.
*/
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
        void: this means that the update fails silently, but what is there
                to do if logging doesn't work?

    every return statement should be preceeded by a call to record_stat.
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
        // todo: record stat
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
        /* this is superfluous, but must be included to keep the verifier happy */
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
    if (*rp == 0) {
        record_stat(CALLSITE_LIBC);
    }

    // todo: report stack too short

    return 0;
}

/*  memory_filename contains a filename and its length.*/
struct memory_filename {
    char d_iname[MAX_FILENAME_LEN]; /* this is just the dname, not a whole path */
    int size;
};


/* get_dname retrieves the filename mapped to a memory region */
static long get_dname(struct task_struct *task, struct vm_area_struct *vma, struct memory_filename *data) {
    struct dentry *dentry;
    struct qstr d_name;

    if (!data) {
        return 0;
    }

    if (vma->vm_file) {
        dentry = vma->vm_file->f_path.dentry;

        if (bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name)) {
            return 0;
        }

        if (d_name.len >= MAX_FILENAME_LEN) {
            record_stat(FILENAME_TOO_LONG);
            return 0;
        }

        data->size = bpf_probe_read_kernel_str(data->d_iname, MAX_FILENAME_LEN + 1, d_name.name) <= 0;
        if (data->size <= 0) {
            return 0;
        }
    }

    return 0;
}

__always_inline int assign_filename(struct task_struct* task, u64 rp, struct memory_filename *mem_filename) {
    int res = bpf_find_vma(task, rp, get_dname, &mem_filename, 0);
    if  (res == -2) {
        // will not happen under normal operation, so log message is okay performance-wise.
        static const char fmt[] = "failed to map %d to a range in memory map: are libc ranges correct? %d";
        bpf_trace_printk(fmt, sizeof(fmt), res, rp);
        }
        if (res != 0) {
            record_stat(FIND_VMA_FAILED);
            return -1;
        }

    return 0;
}


SEC("raw_tp/sys_enter")
int addrfilter(struct bpf_raw_tracepoint_args *ctx) {
    record_stat(TP_ENTERED);

    u64* rp;
    pid_t pid;

    struct task_struct *task;
    struct memory_filename mem_filename = {};

    task = bpf_get_current_task_btf();
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

    if (!find_syscall_site(ctx, rp, pid)){
        return -1;
    }

    if (!rp) {
        return -1;
    }

    if (!assign_filename(task, *rp, &mem_filename)) {
        return -1;
    }

    // res = bpf_send_signal(SIGKILL);
    // if (res != 0) {
    //     kill(pid);
    // }

    kill(pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

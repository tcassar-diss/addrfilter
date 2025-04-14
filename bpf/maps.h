#ifndef MAPS_H
#define MAPS_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

#define ENOENT 2
// XXX: defining ENOENT bad practice; but conflicts caused by
// including <stdlib.h> which don't seem worth spending time to solve

/* (Some) Numbers are all arbitrary. todo: make them meaningful */
#define MAX_FOLLOW_ENTRIES                                                     \
  1024 /* maximum number of processes that addrfilter will protect */
#define MAX_STACK_DEPTH 32
#define MAX_FILENAME_LEN 256
#define MAX_ADDRSPACE_LEN                                                      \
  128 /* maximum supported number of ways of "slicing up" address space */
#define MAX_RINGBUF_ENTRIES 4096 /* has to be a multiple of page size */

#define SIGKILL 9

/* MAX_SYSCALL_NUMBER determined by taking the highest
   defined constant in /usr/include/asm/unistd_64.h */
#define MAX_SYSCALL_NUMBER 461
#define WHITELIST_LEN 58 /* ceil(461 / 8): bitmap for whitelist */

enum stat_type {
  GET_CUR_TASK_FAILED, /* when the bpf helper get_current_task fails */
  TP_ENTERED,          /* every time syscall is entered */
  GET_PROFILER_FAILED, /* ringbuf allocation for profiler failed */
  IGNORE_PID,          /* don't filter, PID isn't being traced */
  PID_READ_FAILED,     /* failed to read PID from current task */
  PPID_READ_FAILED,    /* failed to read PPID from current task */
  FOLLOW_FORK_FAILED,  /* failed to add a new element to protect_map */
  LIBC_NOT_LOADED,     /* Libc address space not loaded for current PID */
  STK_DBG_EMPTY,
  GET_STACK_FAILED, /* bpf_get_stack helper returned a non-0 error */
  CALLSITE_LIBC,    /* no non-libc call site could be found */
  STACK_TOO_SHORT, /* no non-libc call site could be found AND last read RP != 0
                    */
  NO_RP_MAPPING,   /* rp didn't come from mapped space */
  RP_NULL_AFTER_MAP, /* rp mapping failed silently (shouldn't happen!) */
  FILENAME_TOO_LONG, /* filename was longer than MAX_FILENAME_LEN characters */
  FIND_VMA_FAILED,   /* failed to find vma from rp */
  NO_VMA_BACKING_FILE,  /* RP was called from somewhere with no backing file */
  WHITELIST_MISSING,    /* no whitelist associated with memory address space
                           filename */
  SYSCALL_BLOCKED,      /* blocked a syscall */
  SEND_SIGNAL_FAILED,   /* bpf_send_signal returned non-zero value: backup kill
                           async*/
  KILLMODE_CFG_MISSING, /* no kill mode config set */
  WARN_FAILED_RINGBUF_FULL, /* warning userspace failed as ringbuf was full */
  STAT_END, /* not an event: used to autogenerate number of stat types for
               frontend */
};

#define N_STAT_TYPES STAT_END

enum config_type {
  KILL_MODE,
  CFG_END,
};

#define N_CONFIG_TYPES CFG_END

enum kill_mode { KILL_PID, KILL_ALL, WARN, KILL_MODE_END };

#define N_KILL_MODES KILL_MODE_END

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

/*   record_stat logs an event in the stats map. Fails silently!

    args:
        stat: statistic to log

    returns:
        void: this means that the update fails silently, but what is there
                to do if logging doesn't work?

    every return statement should be preceeded by a call to record_stat.
*/
static inline void record_stat(enum stat_type stat);

/*  cfg_map holds config information. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(int32));
  __uint(value_size, sizeof(int32));
  __uint(max_entries, N_CONFIG_TYPES);
  __uint(map_flags, 0);
} cfg_map SEC(".maps");

/* warn_buf is used to report PIDs to userspace.
 *
 * userspace can then decide what the best course of action is from there
 * (either warn or kill all processes in follow map)
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_RINGBUF_ENTRIES);
} warn_buf SEC(".maps");

static inline int warn_pid(pid_t pid);

/* profile_info reports timing info for profiling
 *
 * only activated when the PROFILE macro is defined
 * */
typedef struct {
  __u64 start;             // time on entry
  __u64 get_pid;           // time to get PID
  __u64 apply_filter;      // time to determine whether PID should have
                           //   syscalls filtered
  __u64 find_syscall_site; // time to walk stack and find syscall site
  __u64 assign_filename;   // time to assign filename to syscall site
                           //   (e.g. walk vma rbtree)
  __u64 assoc_whitelist;   // time to pull associated whitelist
  __u64 end;               // time to perform the filtering
} profile_info;

/* profile_buf is used to profile the BPF code
 *
 * Timestamps are taken after each operation and this is reported to userspace
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096 * MAX_RINGBUF_ENTRIES);
} profile_buf SEC(".maps");

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

/*  libc_range_maps stores the memory location of libc.

    libc_range will be the same across all processes being traced, as a base
    assumption of addrfilter is that libc won't change.

    addrfilter also assumes that the only way a new PID will end up in the
   follow map is by a fork in the originally traced process. since forking
   copies the parent's address space to the child's address space, libc will be
   consistent across all child processes.

    it is used while walking the stack in-kernel to identify the first non-libc
    sycall call site, so that the correct filter can be applied.
*/
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(int32));
  __uint(value_size, sizeof(struct vm_range));
  __uint(max_entries, 1);
  __uint(map_flags, 0);
} libc_range_map SEC(".maps");

/* syscall_whitelist is a bitmap where 1 <=> syscall _allowed_ */
struct syscall_whitelist {
  uint8_t bitmap[WHITELIST_LEN];
};

/* check_whitelist_field returns the 1 iff a syscall is allowed */
static inline bool check_whitelist_field(struct syscall_whitelist *entry,
                                         u64 field_index);

/* set_whitelist_field sets the relevant whitelist field to true */
static inline int set_whitelist_field(struct syscall_whitelist *entry,
                                      u64 field_index);

/* path_whitelist_map associates a filename from /proc/PID/maps with a syscall
  whitelist.

  note that this is NOT PID SPECIFIC, as it would be too complicated to generate
  whitelists which are fork specific. thus, whitelists need to be generated with
  this behaviour in mind.

  that is, for each library, the whitelist must include all syscalls made by
  each fork. this design supports the address space of forks changing, but not
  whitelists changing.
*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size,
         sizeof(char[MAX_FILENAME_LEN])); /* keyed by pathname in process
                                             virtual address space */
  __uint(value_size, sizeof(struct syscall_whitelist));
  __uint(max_entries, MAX_ADDRSPACE_LEN); /* at most one whitelist for each
                                             "slice" of address space */
  __uint(map_flags, 0);
} path_whitelist_map SEC(".maps");

/* stack_dbg_map is used to hold the stacktrace on each system call.

  thus, the stacktrace that lead to the blocked system call is available to
  userspace.
*/
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(int32));
  __uint(value_size, sizeof(struct stack_trace_t));
  __uint(max_entries, 1);
  __uint(map_flags, 0);
} stack_dbg_map SEC(".maps");

/*  memory_filename contains a filename and its length.*/
struct memory_filename {
  char d_iname[MAX_FILENAME_LEN]; /* this is just the dname, not a whole path */
  int size;
};

/* strcmp is a helper which safely compares two strings  for equality */
static inline int strcmp(const char *cs, const char *ct);

/* apply_filter decided whether to apply the filtering mechanism to a given pid.
 *  apply_filter also handles fork following:
 *   if a pid is not in the follow map but the parent is, trace_pid will
 *   apply the filter to the process. It will also add pid to the follow map
 *   such that fork following will apply to forks of forks of ... of forks.
 *
 * in the case where an operation fails (such as a PID_READ_FAILED),
 * then no filter is applied and the error is logged.
 */
static inline bool apply_filter(struct task_struct *task, pid_t pid);

/*  find_syscall_site walks the stack to find the first non-libc return pointer.

    for this, it uses information from the libc_range_map.
    If identification fails, a reason will be logged by the function.

    args:
        ctx: pointer to raw tracepoint args (used by bpf_get_stack)
         rp: address to write syscall site to.
        pid: calling pid

    returns:
         0 on success,
        -1 on exit.
*/
static inline int find_syscall_site(struct bpf_raw_tracepoint_args *ctx,
                                    u64 *rp, pid_t pid);

static inline int assign_filename(struct task_struct *task, u64 rp,
                                  struct memory_filename *mem_filename);

#endif

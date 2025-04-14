//go:build exclude

#include "../tracing_common.h"
#include "../tracing_common.bpf.c"

/* #define PROFILE */
/* #define DEBUG */

struct vm_range *unused_vm_range __attribute__((unused));
enum stat_type *unused_stat_type __attribute__((unused));
enum config_type *unused_config_type __attribute__((unused));
enum kill_mode *unused_kill_mode __attribute__((unused));
struct stack_trace_t *unused_st_dbg __attribute__((unused));
profile_info *unused_profile_info __attribute__((unused));
struct syscall_whitelist *unused_syscall_whitelist __attribute__((unused));

/* filter will appropriately "deal with" a blacklisted syscall */
static inline int filter(pid_t pid) {
  int32 key = KILL_MODE;

  int32 *killmode = (int32 *)bpf_map_lookup_elem(&cfg_map, &key);
  if (!killmode) {
    record_stat(KILLMODE_CFG_MISSING);
    // /* default to kill PID */
    if (bpf_send_signal(SIGKILL) != 0) {
      record_stat(SEND_SIGNAL_FAILED);
      return 0;
    };


    return -1;
  }

  if (*killmode == KILL_PID || *killmode == KILL_ALL) {
    if (*killmode == KILL_ALL) {
      warn_pid(pid);
    }

    if (bpf_send_signal(SIGKILL) != 0) {
      record_stat(SEND_SIGNAL_FAILED);
    };
  } else {
    warn_pid(pid);
  }

  return 0;
}

#ifdef PROFILE
#define CALL_PROF_SUBMIT(p)                                                    \
  if (prof) {                                                                  \
    bpf_ringbuf_submit(p, 0);                                                  \
  }
#define RECORD_TIMESTAMP(sec)                                                  \
  if (prof) {                                                                  \
    prof->sec = bpf_ktime_get_ns();                                            \
  }
#define CALL_PROF_DISCARD(p)                                                   \
  if (prof) {                                                                  \
    bpf_ringbuf_discard(p, BPF_RB_NO_WAKEUP);                                  \
  }
#else
#define CALL_PROF_SUBMIT(p)
#define RECORD_TIMESTAMP(sec)
#define CALL_PROF_DISCARD(p)
#endif

/* addrfilter only allows whitelisted system calls to begin execution.
 *
 * addrfilter runs before the kernel begins to process each system call.
 *
 * We check to see if the syscall was issued by a filtered process;
 * if so, we identify which area of the process's address space the
 * the call was made from.
 *
 * We then compare the syscall number with that area's whitelist. If
 * the syscall number isn't present, we kill the process/report the
 * event to userspace (config dependant).
 * */
SEC("raw_tp/sys_enter")
int addrfilter(struct bpf_raw_tracepoint_args *ctx) {
#ifdef PROFILE
  profile_info *prof = (profile_info *)bpf_ringbuf_reserve(
      &profile_buf, sizeof(profile_info), 0);

  if (!prof) {
    record_stat(GET_PROFILER_FAILED);
    static char no_spc[] =
        "failed to reserve space in profile ringbuf; nothing written";

    return 1;
  }
#endif

  RECORD_TIMESTAMP(start)

  record_stat(TP_ENTERED);

  u64 rp = 0;
  pid_t pid;

  struct task_struct *task;
  u64 syscall_nr = ctx->args[1];

  task = bpf_get_current_task_btf();
  if (!task) {
    record_stat(GET_CUR_TASK_FAILED);
    CALL_PROF_DISCARD(prof)
    return 1;
  }

  if (bpf_probe_read(&pid, sizeof(pid), &task->tgid) != 0) {
    record_stat(PID_READ_FAILED);
    CALL_PROF_DISCARD(prof);
    return false;
  }

  RECORD_TIMESTAMP(get_pid)

  if (!apply_filter(task, pid)) {
    record_stat(IGNORE_PID);
    CALL_PROF_DISCARD(prof);
    return 0;
  }

  RECORD_TIMESTAMP(apply_filter)

  if (find_syscall_site(ctx, &rp, pid) != 0) {
    CALL_PROF_SUBMIT(prof);
    return -1;
  }

  RECORD_TIMESTAMP(find_syscall_site)

  struct memory_filename mem_filename = {};
  if (assign_filename(task, rp, &mem_filename) != 0) {
    CALL_PROF_SUBMIT(prof);
    return -1;
  }

  RECORD_TIMESTAMP(assign_filename)

  struct syscall_whitelist *whitelist;
  whitelist = (struct syscall_whitelist *)bpf_map_lookup_elem(
      &path_whitelist_map, &mem_filename.d_iname);

  if (!whitelist) {
    record_stat(WHITELIST_MISSING);
    CALL_PROF_SUBMIT(prof);
    return 0;
  }

  RECORD_TIMESTAMP(assoc_whitelist)

  if (check_whitelist_field(whitelist, syscall_nr) == 1) {
    CALL_PROF_SUBMIT(prof);
    return 0;
  }

  record_stat(SYSCALL_BLOCKED);

  filter(pid);

#ifdef PROFILE
  if (prof) {
    prof->end = bpf_ktime_get_ns();
    bpf_ringbuf_submit(prof, 0);
  } else {
    static const char noprof[] = "no prof defined :(";
    bpf_trace_printk(noprof, sizeof(noprof), prof->start);
  }
#endif

  return 0;
}

char LICENSE[] SEC("license") = "GPL";

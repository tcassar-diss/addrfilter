//go:build exclude

#include "../maps.h"

/* #define PROFILE */
/* #define DEBUG */

struct vm_range *unused_vm_range __attribute__((unused));
enum stat_type *unused_stat_type __attribute__((unused));
enum config_type *unused_config_type __attribute__((unused));
enum kill_mode *unused_kill_mode __attribute__((unused));
struct stack_trace_t *unused_st_dbg __attribute__((unused));
profile_info *unused_profile_info __attribute__((unused));
struct syscall_whitelist *unused_syscall_whitelist __attribute__((unused));

static inline void record_stat(enum stat_type stat) {
  u64 *s_count = bpf_map_lookup_elem(&stats_map, &stat);
  if (!s_count) {
    return;
  }

  __sync_fetch_and_add(s_count, 1);
}

static inline int warn_pid(pid_t pid) {
  pid_t *p = (pid_t *)bpf_ringbuf_reserve(&warn_buf, sizeof(pid_t), 0);
  if (!p) {
    record_stat(WARN_FAILED_RINGBUF_FULL);
    return -1;
  }

  *p = pid;

  bpf_ringbuf_submit(p, 0);

  return 0;
}

static inline bool check_whitelist_field(struct syscall_whitelist *entry,
                                         u64 field_index) {
  if (field_index / 8 > 8) {
    return -1;
  }

  if (field_index % 8 > 8 || field_index % 8 < 0) {
    return -1;
  }

  return (entry->bitmap[field_index / 8] & (1 << (field_index % 8))) != 0;
}

static inline int strcmp(const char *cs, const char *ct) {
  unsigned char c1, c2;

  while (1) {
    c1 = *cs++;
    c2 = *ct++;
    if (c1 != c2)
      return c1 < c2 ? -1 : 1;
    if (!c1) {
      break;
    }
  }

  return 0;
}

static inline int find_syscall_site(struct bpf_raw_tracepoint_args *ctx,
                                    u64 *rp, pid_t pid) {
  const int32 zero = 0;
  struct vm_range *libc_range =
      (struct vm_range *)bpf_map_lookup_elem(&libc_range_map, &zero);
  if (!libc_range) {
    record_stat(LIBC_NOT_LOADED);
    return -1;
  }

  struct stack_trace_t *r =
      (struct stack_trace_t *)bpf_map_lookup_elem(&stack_dbg_map, &zero);
  if (!r) {
    record_stat(STK_DBG_EMPTY);
    return -1;
  }

  int stack_size = bpf_get_stack(
      ctx, r->stacktrace, MAX_STACK_DEPTH * sizeof(u64), BPF_F_USER_STACK);
  if (stack_size <= 0) {
    record_stat(GET_STACK_FAILED);
    return -1;
  };

  int frames = stack_size / 8; // each return pointer is 8B i.e. 64bit
  r->frames_walked = 0;

  for (int i = 0; i < frames; i++) {
    /* this is superfluous, but must be included to keep the verifier happy */
    if (i >= sizeof(r->stacktrace) / sizeof(u64)) {
      return -1;
    }

    r->callsite = r->stacktrace[i];
    if (!(libc_range->start <= r->callsite && r->callsite < libc_range->end)) {
      break;
    }

    r->frames_walked++;
  }

  if (r->callsite == 0) {
    record_stat(CALLSITE_LIBC);
  }

#ifdef DEBUG
  static const char fmt2[] = "syscall site found @ 0x%lx";
  bpf_trace_printk(fmt2, sizeof(fmt2), r->callsite);
#endif

  *rp = r->callsite;

  return 0;
}

/* get_dname retrieves the filename mapped to a memory region */
static long get_dname(struct task_struct *task, struct vm_area_struct *vma,
                      struct memory_filename *data) {
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

    data->size = bpf_probe_read_kernel_str(data->d_iname, MAX_FILENAME_LEN + 1,
                                           d_name.name) <= 0;
    if (data->size <= 0) {
      return 0;
    }
  }

  return 0;
}

static inline int assign_filename(struct task_struct *task, u64 rp,
                                  struct memory_filename *mem_filename) {
  int res = bpf_find_vma(task, rp, get_dname, mem_filename, 0);
  if (res == -ENOENT) {
    // can happen if task->mm is empty or if no range has the rp;
    if (task->mm == NULL) {
      static const char fmt[] = "memory area of task struct empty!";
      bpf_trace_printk(fmt, sizeof(fmt));
    }

    static const char fmt[] = "failed to map %d to a range in memory map: are "
                              "libc ranges (0x%xl - 0x%xl) correct? error -2";
    bpf_trace_printk(fmt, sizeof(fmt), rp);
  }
  if (res != 0) {
    record_stat(FIND_VMA_FAILED);
    return -1;
  }

#ifdef DEBUG
  static const char fmt[] = "assigned %d to %s";
  bpf_trace_printk(fmt, sizeof(fmt), rp, mem_filename->d_iname);
#endif /* DEBUG */

  if (strcmp(mem_filename->d_iname, "") == 0) {
    record_stat(NO_VMA_BACKING_FILE);
    return -1;
  }

  return 0;
}

static inline bool apply_filter(struct task_struct *task, pid_t pid) {
  pid_t ppid;

  if (bpf_probe_read(&ppid, sizeof(ppid), &task->parent->tgid) != 0) {
    record_stat(PPID_READ_FAILED);
    return false;
  }

  bool *parent_traced = (bool *)bpf_map_lookup_elem(&protect_map, &ppid);
  if (parent_traced) {
    bool tr = 1;

#ifdef DEBUG
    static char fmt[] = "adding PID %d to protect_map";
    bpf_trace_printk(fmt, sizeof(fmt), pid);
#endif

    if (bpf_map_update_elem(&protect_map, &ppid, &tr, 0) != 0) {
      record_stat(FOLLOW_FORK_FAILED);
    };
    return true;
  }

  bool *protect = (bool *)bpf_map_lookup_elem(&protect_map, &pid);
  if (!protect) {
    return false;
  }

  return true;
}

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

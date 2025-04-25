//go:build exclude

#include "tracing_common.h"

/* BPF toolchain doesn't provide a linker, so prototypes
 * defined in tracing_common.h are defined here.
 *
 * This file then needs to be manually included whenever implementations
 * in the header file are needed
 * */

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
  if (field_index / 8 >= WHITELIST_LEN) {
    return false; // Out of bounds, return false instead of error code
  }
  return (entry->bit_array[field_index / 8] & (1 << (field_index % 8))) != 0;
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

#ifdef DEBUG
  char fmt[] = "libc range: 0x%lx, 0x%lx";
  bpf_trace_printk(fmt, sizeof(fmt), libc_range->start, libc_range->end);
#endif

  struct stack_trace_t *r =
      (struct stack_trace_t *)bpf_map_lookup_elem(&stack_dbg_map, &zero);
  if (!r) {
    record_stat(STK_DBG_EMPTY);
    return -1;
  }

  r->callsite = 0;

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
    return -1;
  }

#ifdef DEBUG
  static const char fmt2[] = "syscall site found @ 0x%llx after %d frames";
  bpf_trace_printk(fmt2, sizeof(fmt2), r->callsite, r->frames_walked);
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

    static const char fmt[] =
        "failed to map 0x%llx to a range in memory map: are "
        "libc ranges (0x%llx - 0x%llx) correct? error -2";
    bpf_trace_printk(fmt, sizeof(fmt), rp);
  }
  if (res != 0) {
    record_stat(FIND_VMA_FAILED);
    return -1;
  }

#ifdef DEBUG
  static const char fmt[] = "assigned 0x%lx to %s";
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

//go:build exclude

#include "../tracing_common.bpf.c"
#include "../tracing_common.h"
#include <bpf/bpf_helpers.h>

struct vm_range *unused_vm_range __attribute__((unused));
struct syscall_whitelist *unused_syscall_whitelist __attribute__((unused));

static inline int set_whitelist_field(struct syscall_whitelist *entry,
                                      u64 field_index) {
  if (field_index / 8 > 8) {
    return -1;
  }
  if (field_index % 8 > 8 || field_index % 8 < 0) {
    return -1;
  }
  entry->bitmap[field_index / 8] |= (1 << (field_index % 8));
  return 0;
}

/* wlgen creates whitelists via dynamic analysis */
SEC("raw_tp/sys_enter")
int wlgen(struct bpf_raw_tracepoint_args *ctx) {
  u64 rp = 0;
  pid_t pid;

  struct task_struct *task;
  u64 syscall_nr = ctx->args[1];

  task = bpf_get_current_task_btf();
  if (!task) {
    return 1;
  }

  if (bpf_probe_read(&pid, sizeof(pid), &task->tgid) != 0) {
    return false;
  }

  if (!apply_filter(task, pid)) {
    return 0;
  }

  if (find_syscall_site(ctx, &rp, pid) != 0) {
    char fmt[] = "failed to find syscall site";
    bpf_trace_printk(fmt, sizeof(fmt));
    return -1;
  }

  struct memory_filename mem_filename = {};
  if (assign_filename(task, rp, &mem_filename) != 0) {
    char fmt[] = "failed to find syscall site";
    bpf_trace_printk(fmt, sizeof(fmt));

    return -1;
  }

  struct syscall_whitelist *whitelist;
  whitelist = (struct syscall_whitelist *)bpf_map_lookup_elem(
      &path_whitelist_map, &mem_filename.d_iname);

  if (!whitelist) {
    char fmt[] = "Here no whitelist %d!";
    bpf_trace_printk(fmt, sizeof(fmt), syscall_nr);

    // TODO: Create whitelist with file name as key
    return 0;
  }

  if (set_whitelist_field(whitelist, syscall_nr) != 0) {
    char fmt[] = "failed to set syscall_nr in whitelist";
    bpf_trace_printk(fmt, sizeof(fmt));

    return -1;
  }

  // TODO: write whitelist back to map

  char fmt[] = "Here %d!";
  bpf_trace_printk(fmt, sizeof(fmt), syscall_nr);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";

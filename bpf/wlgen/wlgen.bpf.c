//go:build exclude 


#include "../maps.h"

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
    
}


char LICENSE[] SEC("license") = "GPL";

# Fine-Grained System Call Filtering in Linux

## `seccomp` and it's issues

- System call (syscall) filters are used to secure applications from RCEs,
  supply chain attacks, and for sandboxing.
- `seccomp` exists, and is [widely used](https://en.wikipedia.org/wiki/Seccomp)
  to filter syscalls.
- The issue with `seccomp` is that **applications are large**. As applications
  grow in size, the set of syscalls they make also tends to grow.
- This means that a single syscall filter for the whole application **is
  necessarily permissive**.
- This **reduces the effectiveness of syscall filtering** to mitigate attacks.

## Per-`vma` filtering

- **Solution**: Use multiple syscall filters for a single process
- `addrfilter` assigns a filter to each file-backed memory region in the
  process's address space.
- This means that **each shared library has its own filter**

## Effective?

- `addrfilter` sees a **37.0% privilege reduction** for `redis`, and
  **23.7%** for `nginx` when compared to `seccomp`.

## Slow?

- Depends. High rates of syscalls => more slowdown.
  Worst seen in testing was a redis microbenchmark with 3B key size which saw a
  40% reduction in throughput. More details in the
  [report](https://www.github.com/tcassar-diss/report)

# addrfilter

System call filtering, finer grained than seccomp.

addrfilter makes it possible to define different filters based on _a process's address space_.

For instance, one can implement a custom filter for each shared library a process uses.


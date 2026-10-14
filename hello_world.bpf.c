#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle__sys_enter_execve(void *ctx){
    bpf_printk("[zhou] Hello, execve!");
    return 0;
}


char _lincense[] SEC("license") = "GPL";
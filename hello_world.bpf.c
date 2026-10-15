#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__syscalls__sys_enter_open(void *ctx){
    bpf_printk("[zhou] Hello, execve!");
    return 0;
}


char _lincense[] SEC("license") = "GPL";
// 目标 hook libc 中的函数

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe_hook.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} ringbuf SEC(".maps");




// 对pid进行hook 
// 查询so 位置 find / -type f -name "libc.so" 2>/dev/null
SEC("uretprobe//apex/com.android.runtime/lib64/bionic/libc.so:getpid")
int handler_hook_libc_exit__getpid(struct pt_regs *ctx){
    // 要获取返回值
    pid_t ret =  PT_REGS_RC(ctx); //自动拿回返回值
    
    //通过 ringbuf 传递数据
    struct event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if(!event) return 0;
    
    event->pid = ret;

    // 提交数据。提交 pid 数据
    bpf_ringbuf_submit(event, 0);
    return 0;
}

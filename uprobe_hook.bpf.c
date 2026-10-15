// 目标 hook libc 中的函数

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe_hook.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} ringbuf SEC(".maps");



// ------------------ 获取返回值 ------------

// 对pid进行hook 
// 查询so 位置 find / -type f -name "libc.so" 2>/dev/null
// SEC("uretprobe//apex/com.android.runtime/lib64/bionic/libc.so:getpid")
// int handler_hook_libc_exit__getpid(struct pt_regs *ctx){
//     // 要获取返回值
//     pid_t ret =  PT_REGS_RC(ctx); //自动拿回返回值

//     //通过 ringbuf 传递数据
//     struct event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
//     if(!event) return 0;

//     event->pid = ret;

//     // 提交数据。提交 pid 数据
//     bpf_ringbuf_submit(event, 0);
//     return 0;
// }

///------------------------- 获取参数 --------------
// 获取参数的方式一
// uprobe 获取入参
// SEC("uprobe//apex/com.android.runtime/lib64/bionic/libc.so:syscall")
// int handle_hook_libc_enter__syscall(struct pt_regs *ctx){
//     //
//     unsigned int sys_id =  PT_REGS_PARM1(ctx); //第一个参数，系统调用号

//     // 更加简便的方案


//     //通过 ringbuf 传递数据
//     struct event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
//     if(!event) return 0;

//     event->sys_id = sys_id;// 用户态的输出还没有改

//     // 提交数据。提交 pid 数据
//     bpf_ringbuf_submit(event, 0);
//     return 0;
// }


// 方式2
// SEC("uprobe//apex/com.android.runtime/lib64/bionic/libc.so:syscall")
// int BPF_UPROBE(handle_hook_libc_enter__syscall, long __number){
//     //通过 ringbuf 传递数据
//     struct event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
//     if(!event) return 0;
//     //BPF_UPROBE 这个宏第一个也是定义了一个 ctx ，不需要知己再定义了
//     event->pid = __number;// 直接就拿到系统调用号了。因为 BPF_UPROBE 宏内部自动做了参数解析

//     // 提交数据。提交 pid 数据
//     bpf_ringbuf_submit(event, 0);
//     return 0;
// }


// 继续测试 ,open函数
SEC("uprobe//apex/com.android.runtime/lib64/bionic/libc.so:open")
int BPF_UPROBE(handle_hook_libc_enter__syscall, const char* pathname, int flags){
    //通过 ringbuf 传递数据
    struct event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if(!event) return 0;

    // 从用户态读取数据到 event->data
    // 因为 pathname 传过来是指针，需要去用户态读取
    long path_len = bpf_probe_read_user_str(event->data, sizeof(event->data), pathname);
    if (path_len < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }


    // 提交数据。提交 pid 数据
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

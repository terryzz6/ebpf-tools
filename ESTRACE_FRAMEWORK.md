# estrace 框架开发参考

目标环境为 Pixel 6 / Android 13 / ARM64 Linux 5.10。其他设备必须重新确认
`raw_syscalls/sys_enter` 和 `sys_exit` 的 tracepoint 字段偏移、权限与构建工具链。

## 数据流

1. `estrace.bpf.c` 在 `sys_enter` 按 TID 将调用号及六个原始参数存入 `start` hash map。
   入口应用 PID（TGID）、TID、UID、调用号过滤，并跳过 `estrace` 自身进程。
2. `sys_exit` 根据 TID 匹配入口，应用 `-x` 失败过滤，构造 `estrace.h` 定义的
   `struct event`，通过 `bpf_perf_event_output()` 写入 `events` perf event array。
   无论是否输出事件，匹配到的入口数据都会删除。未命中入口的出口不会输出。
3. `estrace.c` 直接通过 libbpf 的 `perf_buffer__new()` / `perf_buffer__poll()`
   收包并报告丢失事件，不使用 ring buffer 或 `compat.c` 的兼容封装。
   用户态以 `syscall_name()` 映射 ARM64 调用名。

`-e` 打印六个十六进制原始参数。只有 ARM64 `openat`（调用号 56）的第二个参数
额外在入口用 `bpf_probe_read_user_str()` 读取，最多保存 191 字节并随 perf 事件
输出 `path="..."`；它是传入的路径字符串，不保证是绝对路径或最终打开的路径。
其他指针参数仍只显示地址。读取失败会显示原因码，过长的路径可能截断。`-c` 才在
出口调用 `bpf_get_stack(..., BPF_F_USER_STACK)`，由 BlazeSym 通过目标进程映射
解析最多 16 帧；失败时显示错误码或原始地址。`-n` 名称筛选在用户态执行，
其余过滤在 BPF 端完成。`-T` 显示事件被接收时的本地时间，不是系统调用发生时刻。

## 接口与构建

`estrace -h` 列出选项。常用示例：

```sh
make estrace
./estrace -p 1234 -s 56 -e -c -d 10
./estrace -x -U -T
```

构建得到 ARM64 静态可执行文件，不能在 x86_64 主机上直接运行。BPF 端使用
固定 tracepoint 偏移，不进行 CO-RE 字段访问；编译时使用 `arm64/vmlinux.h`，
目标设备不需要提供可读的 `/sys/kernel/btf/vmlinux`。仍需有加载 BPF、访问
tracepoint 和创建 perf event 的权限，Android SELinux 也可能拒绝。

设备侧检查布局：

```sh
su -c 'cat /sys/kernel/tracing/events/raw_syscalls/sys_enter/format'
su -c 'cat /sys/kernel/tracing/events/raw_syscalls/sys_exit/format'
```

若 tracefs 位于旧位置，改用 `/sys/kernel/debug/tracing/events/raw_syscalls/`。
加载失败应查看 libbpf/verifier 日志及 SELinux 拒绝记录；主机编译成功不能
证明设备能够运行。内核采集用户栈失败会显示 `user stack unavailable`；
采集成功但符号不可见时，检查 `/proc/<pid>/maps`、模块访问权限和调试符号。
大量追踪可能产生丢包，优先使用 `-p`、`-t` 或 `-s` 缩小范围。

`start` hash map 最多保留 10240 条并发入口；进程在调用出口前消失时条目
可能暂时留存，直到键复用或工具退出。跨架构移植需要检查固定布局和名称表。

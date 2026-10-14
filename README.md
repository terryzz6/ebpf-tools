# ebpf-tools

eBPF 工具源码及 ARM64 构建依赖。

`estrace` 的设计、构建、运行、排障和扩展说明见 [ESTRACE_FRAMEWORK.md](ESTRACE_FRAMEWORK.md)。

`.output/` 为构建时生成的中间文件，不纳入版本控制。

## Pixel 6 / Android 13 / ARM64 Linux 5.10

`estrace` 使用 perf buffer 和 ARM64 `raw_syscalls/sys_enter`、`sys_exit`
tracepoint 布局（调用编号偏移为 8 字节，返回值偏移为 16 字节），不再依赖读取设备的
`/sys/kernel/btf/vmlinux`，也不需要外部内核 BTF 文件。BPF 对象自身的
`.BTF` 调试和 map 类型信息仍保留。

入口事件输出系统调用名称、编号及最多 16 帧用户态堆栈；出口事件输出
系统调用名称、编号及返回值。两种事件尚未关联，当前不读取系统调用参数。
程序会忽略自身产生的系统调用，以免堆栈符号解析和打印递归触发追踪。

系统调用名使用编译时内置的 ARM64 名称表，未知编号显示 `unknown(编号)`。
入口用户栈使用 BlazeSym 按进程地址空间解析为函数名；需要设备允许读取
`/proc/<pid>/maps` 并能访问目标二进制或共享库。进程已退出、符号被剥离、
缺乏展开所需信息或 SELinux 限制时，可能只能显示地址、部分帧或
`user stack unavailable (code=...)`。这不是内核 BTF 问题。

```sh
make -B estrace
adb push estrace /data/local/tmp/estrace
adb shell
```

在设备 shell 中通过已安装的 root 工具运行：

```sh
su -c 'chmod 755 /data/local/tmp/estrace && /data/local/tmp/estrace'
```

`failed to read kernel BTF ...: -13` 表示读取被拒绝，不能据此认定
内核没有 BTF。移除 BTF 依赖也不会赋予加载 BPF、访问 tracepoint 和
打开 perf event 的权限；设备仍需要相应权限和允许这些操作的 SELinux 策略。
如果仍失败，请提供以下诊断输出及 `estrace` 的完整日志：

```sh
su -c 'id; id -Z; uname -a; getenforce'
su -c '/data/local/tmp/estrace'
su -c 'cat /sys/kernel/tracing/events/raw_syscalls/sys_enter/format'
su -c 'cat /sys/kernel/tracing/events/raw_syscalls/sys_exit/format'
su -c 'dmesg | grep "avc:.*denied" | tail -30'
```

若 tracefs 使用旧挂载点，tracepoint 格式文件位于
`/sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/format`。

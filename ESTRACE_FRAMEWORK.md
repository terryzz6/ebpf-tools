# estrace 框架开发参考

本文记录当前仓库中 `estrace` 的实际实现，作为后续开发系统调用追踪功能的起点。目标环境是 Pixel 6、Android 13、ARM64 Linux 5.10；其他设备需要重新确认 tracepoint 布局、权限与构建工具链。简明运行步骤见 [README.md](README.md)。

## 1. 当前能做什么

- 监听 `tracepoint/raw_syscalls/sys_enter` 和 `tracepoint/raw_syscalls/sys_exit`。
- 入口事件输出进程 PID、UID、任务名、系统调用名称/编号，以及最多 16 帧**用户态**调用栈。
- 出口事件输出进程 PID、UID、任务名、系统调用名称/编号及返回值；出口事件**不采集堆栈**。
- 内核态通过 perf event array 发送事件；用户态用 libbpf 的 perf buffer 接收事件，用 ARM64 内置表查询调用名称，用 BlazeSym 解析用户态函数名。
- 过滤 `estrace` 自己的进程，避免打印与符号解析产生新的追踪事件，导致持续放大。

当前**不**解析系统调用参数，不匹配同一次调用的进出事件，不计算耗时，也不采集内核态堆栈。程序没有命令行选项，直接运行 `./estrace`。这些限制是框架的现状，不是 Android 自动提供的功能。

## 2. 文件与数据流

| 文件 | 职责 |
| --- | --- |
| `estrace.bpf.c` | 定义两个 tracepoint 程序、perf 事件 map、自身 PID 过滤 map，采集系统调用事件及入口用户栈。 |
| `estrace.h` | 定义 BPF 和用户态共用的 `struct event`、事件类型、最大栈深度。 |
| `estrace.c` | 配置、加载并挂载 BPF 程序；接收事件、映射系统调用名、符号化堆栈并输出。 |
| `compat.c`、`compat.h` | 封装 perf buffer 的创建、注册回调、轮询和释放。 |
| `syscall_helpers.c`、`syscall_helpers.h` | 内置通用/ARM64 系统调用编号与名称表；本程序只调用 `syscall_name()`，不执行 `ausyscall`。 |
| `arm64/blazesym.h`、`arm64/lib/libblazesym.a.gz` | BlazeSym 的 C 接口和静态库压缩包，负责把用户态地址映射为函数符号。 |
| `arm64/vmlinux.h` | **编译时**使用的内核类型头文件；不代表设备运行时必须提供 BTF。 |
| `Makefile` | 编译 BPF、生成 skeleton、编译用户态并链接 Android ARM64 静态程序。 |

执行路径：

```text
sys_enter / sys_exit tracepoint
  -> estrace.bpf.c：过滤本程序、填写 struct event
  -> sys_enter 时使用 bpf_get_stack(..., BPF_F_USER_STACK) 采集地址
  -> bpf_perf_event_output -> events (BPF_MAP_TYPE_PERF_EVENT_ARRAY)
  -> compat.c：perf_buffer__poll -> 回调
  -> estrace.c：syscall_name + BlazeSym -> 英文输出
```

初始化顺序：`estrace_bpf__open()` → 创建 perf buffer 封装 → `estrace_bpf__load()` → 写入 `ignored_pid` map → 创建 symbolizer → `estrace_bpf__attach()` → 注册 perf 回调并轮询。退出时释放 buffer、skeleton 和 symbolizer；Ctrl-C 或 SIGTERM 让轮询结束。

## 3. 数据结构与 tracepoint 布局

`estrace.h` 的 `struct event` 在内核与用户态共享；修改字段时**必须同时重新构建 BPF 对象和用户态程序**。当前字段：

| 字段 | 含义 |
| --- | --- |
| `pid` | `bpf_get_current_pid_tgid()` 的高 32 位，即进程 TGID；不是线程 TID。 |
| `uid` | `bpf_get_current_uid_gid()` 的低 32 位。 |
| `type` | `EVENT_ENTER` 或 `EVENT_EXIT`。 |
| `stack_size` | `sys_enter` 中 `bpf_get_stack()` 返回的字节数；小于零时为采集失败的错误码。`sys_exit` 为零。 |
| `syscall_nr` | ARM64 系统调用编号；未知名称仍显示编号。 |
| `ret` | `sys_exit` 的系统调用返回值；`sys_enter` 不使用。 |
| `comm` | 最多 16 字节的当前任务名，不是完整可执行文件路径。 |
| `user_stack` | 最多 `STACK_DEPTH`（当前为 16）个用户态指令地址；并非已解析的字符串。 |

本项目不使用 CO-RE 访问 tracepoint 上下文，而在 `estrace.bpf.c` 中定义 ARM64 固定布局：公共字段偏移 0、调用编号偏移 8；`sys_exit` 返回值偏移 16，`sys_enter` 从偏移 16 开始是参数数组。目前入口程序**只读取调用编号**，没有读取参数数组。源码中的 `_Static_assert` 只保证本地结构布局，**不能证明目标设备的布局相同**。部署前通过设备上的 `raw_syscalls/sys_enter/format` 和 `raw_syscalls/sys_exit/format` 核对字段偏移；不匹配时先调整上下文结构，不要直接使用错误值。

目标设备无需可读的 `/sys/kernel/btf/vmlinux` 来完成此程序的 CO-RE 重定位；BPF 对象自身仍可包含 `.BTF`。**没有 BTF 依赖不等于没有权限要求**：加载 BPF、打开 perf event、挂载 tracepoint、访问目标进程的映射和二进制文件仍可能受到内核配置与 SELinux 限制。

## 4. 编译与部署

仓库的 `Makefile` 默认使用 `ARCH=arm64`，并把 `CLANG`、`LLVM_STRIP` 指向本机 Android NDK r27b 路径。需要存在 `bin/bpftool`、`arm64/vmlinux.h`、`arm64/lib/libbpf.a` 及 `arm64/lib/libblazesym.a.gz`，并能找到链接用的 ELF、zlib 等库。换电脑时检查默认路径，必要时使用 Make 变量覆盖：

```sh
make estrace
# 工具链位置不同的示例：
make estrace CLANG=/path/to/aarch64-linux-android30-clang LLVM_STRIP=/path/to/llvm-strip
```

编译顺序：`estrace.bpf.c` → `.output/estrace.bpf.o` → `.output/estrace.skel.h` → `.output/estrace.o` 与 `.output/syscall_helpers.o` → 根目录的 `estrace`。首次需要 BlazeSym 时，Makefile 会从跟踪的 `arm64/lib/libblazesym.a.gz` 解压出被忽略的 `libblazesym.a`。`estrace` 的链接还包含 `compat.o`、`libbpf.a`、`-lelf`、`-lz`、`-ldl` 和 `-lm`；产物为 Android ARM64 程序，**不能在 x86_64 主机直接运行**。需要查看实际编译命令可使用 `make V=1 estrace`；强制重编译可使用 `make -B estrace`。

```sh
adb push estrace /data/local/tmp/estrace
adb shell
su -c 'chmod 755 /data/local/tmp/estrace && /data/local/tmp/estrace'
```

退出可按 Ctrl-C；若目标 shell 的 `su -c` 不转发信号，请在设备上结束相应进程。不要把主机端解压出的 `libblazesym.a` 另行推送：它已静态链接进 `estrace`。

## 5. 输出如何理解

以下仅为**格式示意**，不是设备实测输出：

```text
tracing raw_syscalls/sys_enter and sys_exit; press Ctrl-C to exit
enter pid=15748 uid=10123 comm=myapp syscall=openat(56)
  open+0x344 (/apex/.../libc.so)
  main+0x20 (/data/local/tmp/myapp)
exit pid=15748 uid=10123 comm=myapp syscall=openat(56) ret=3
```

- `openat(56)` 中的名字来自编译时内置的 ARM64 表，括号内为调用编号；无法找到时显示 `unknown(编号)`。
- `open+0x344` 中的十六进制数是**相对函数起点的地址偏移**，不是源码行号；模块路径来自目标进程映射。Android ARM64 的 `openat` 系统调用也可能在用户态函数 `open()` 中发起。
- `ret` 为内核返回值；负值表示失败时对应的内核错误码，但框架不做 errno 名称转换。
- 入口与出口分别发送事件。输出顺序可能与其他进程、线程的事件交错；不要只根据相邻两行认定是一对调用。
- `lost N events on CPU #...` 表示 perf buffer 已丢事件；此时不能据输出判断某次调用是否缺失入口或出口。

## 6. 用户栈与符号化的边界

`sys_enter` 使用 `bpf_get_stack()` 将用户态地址放入事件；用户态通过 BlazeSym 的 `blaze_symbolize_process_abs_addrs()`，按 `pid` 查找进程的内存映射与模块。当前设置 `no_map_files=true`，优先使用 `/proc/<pid>/maps` 中的路径，而不依赖 `/proc/<pid>/map_files`。无法初始化 BlazeSym 或无法解析某帧时，仍显示地址和 `<no symbol>`；采集失败则显示 `user stack unavailable (code=...)`。看到名字取决于可访问的二进制/共享库及其符号信息，并不保证每个函数都能识别。

可能导致符号缺失的情况：进程在处理事件前退出；设备 SELinux 或文件权限不允许读取映射/模块；模块被剥离符号或已删除；目标运行在不同的挂载命名空间；无法可靠展开用户栈；设备内核不支持当前使用的栈采集方式。先区分**采集失败**（`user stack unavailable`）和**采集成功但解析失败**（`<no symbol>`、`symbolization failed`），再分别排查内核能力与文件权限。

追踪所有进程的每次 `sys_enter` 并解析堆栈代价较高，会增加 CPU、数据量和丢事件概率。后续若关注特定进程，优先在 BPF 端加 PID/UID 或调用编号过滤，再按需抓栈；不要仅在用户态过滤，因为那时采集与传输开销已经发生。

## 7. 常见故障排查

1. **编译找不到 `blazesym.h` 或静态库**：检查 `arm64/blazesym.h` 与 `arm64/lib/libblazesym.a.gz` 是否完整；Makefile 会从压缩包生成 `.a`，不需要自行另建一个未跟踪的大文件。
2. **`failed to read kernel BTF ...: -13`**：`-13` 表示读取被拒绝，不等于内核没有 BTF。确认使用的是当前构建的可执行文件，并检查其加载日志；当前框架不要求设备可读的内核 BTF。如果仍报 CO-RE 依赖，排查是否推送了旧版程序或引入了新的 CO-RE 访问。
3. **`failed to load BPF program` / `failed to attach BPF program`**：检查 root、SELinux、tracepoint 是否存在以及内核日志。设备是否支持栈采集还应结合 verifier 日志判断；不能只用主机编译成功推断设备能够加载。
4. **`user stack unavailable (code=...)`**：事件到达用户态但用户栈未采集成功；记录具体负值、设备内核日志及目标进程类型，确认内核配置、权限与栈展开条件。
5. **`<no symbol>` 或 `symbolization failed`**：确认 `/proc/<pid>/maps`、对应模块路径是否可读以及目标进程是否仍存在；strip、权限限制或挂载命名空间也会影响结果。
6. **输出过多或丢事件**：这是全系统 tracepoint；先加入内核态过滤，而不是直接提高打印频率。`compat.c` 中 `PERF_BUFFER_PAGES` 目前为每 CPU 64 页。

设备侧诊断示例（需要设备允许相应操作）：

```sh
adb shell
su -c 'id; id -Z; uname -a; getenforce'
su -c 'cat /sys/kernel/tracing/events/raw_syscalls/sys_enter/format'
su -c 'cat /sys/kernel/tracing/events/raw_syscalls/sys_exit/format'
su -c 'dmesg | grep "avc:.*denied" | tail -30'
```

若 tracefs 未挂载在 `/sys/kernel/tracing`，尝试 `/sys/kernel/debug/tracing/events/raw_syscalls/`。诊断时注意日志可能包含目标进程信息。

## 8. 后续扩展时怎么改

| 需求 | 首要修改点 | 需要注意 |
| --- | --- | --- |
| 只追踪特定 PID/UID/调用编号 | `estrace.bpf.c` 的入口与出口程序 | 在采栈和发送事件**之前**过滤；现有自身 PID 过滤 map 不要误删。 |
| 读取入口参数 | ARM64 `sys_enter` 的上下文结构及 `estrace.bpf.c` | 先核对设备 tracepoint `format`；用户指针不能直接解引用，按 BPF 访问规则读取。 |
| 关联进出、计算耗时 | BPF map + `estrace.h` + `estrace.c` | 使用完整 `pid_tgid` 区分线程；处理缺失出口、丢事件及进程退出后的清理。 |
| 增加事件字段或堆栈深度 | `estrace.h`、采集和打印逻辑 | 两侧 ABI 必须一致；BPF 栈空间、perf 事件体积和性能都会受影响。 |
| 改用不同架构/内核 | `Makefile`、调用名表及 tracepoint 上下文 | 当前固定布局和名称表为 ARM64 设计，不能直接认为其他架构兼容。 |

修改后的最小验证流程：执行 `make estrace`、`git diff --check`；部署到**目标设备**查看 BPF 加载/挂载结果，用有代表性的系统调用核对名称、返回值与栈；最后检查错误路径与丢事件提示。主机上的编译成功不能替代 Android 设备验证。

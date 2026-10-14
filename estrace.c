// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "blazesym.h"
#include "compat.h"
#include "estrace.h"
#include "estrace.skel.h"
#include "syscall_helpers.h"

#define POLL_TIMEOUT_MS 100

/* 收到 Ctrl-C 后，让主循环正常退出并释放资源。 */
static volatile sig_atomic_t exiting;
static blaze_symbolizer *symbolizer;

/* libbpf 默认会输出较多调试信息，这里只保留必要日志。 */
static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

static void handle_signal(int signal)
{
	(void)signal;
	exiting = 1;
}

/* 符号化入口事件采集到的用户态地址；失败时仍输出原始地址。 */
static void print_user_stack(const struct event *event)
{
	struct blaze_symbolize_src_process src = {
		.type_size = sizeof(src),
		.pid = event->pid,
		.no_map_files = true,
	};
	const struct blaze_syms *syms = NULL;
	uint64_t addrs[STACK_DEPTH];
	size_t frame, count;

	if (event->stack_size <= 0) {
		printf("  user stack unavailable (code=%d)\n", event->stack_size);
		return;
	}

	count = (size_t)event->stack_size / sizeof(event->user_stack[0]);
	if (count > STACK_DEPTH)
		count = STACK_DEPTH;
	/* __u64 与 uint64_t 在 ARM64 上宽度相同，但 C 类型不一定相同。 */
	memcpy(addrs, event->user_stack, count * sizeof(addrs[0]));
	if (symbolizer)
		syms = blaze_symbolize_process_abs_addrs(symbolizer, &src,
							addrs, count);
	if (!syms && symbolizer)
		printf("  symbolization failed: %s\n", blaze_err_str(blaze_err_last()));

	for (frame = 0; frame < count; frame++) {
		const struct blaze_sym *sym = syms && frame < syms->cnt ? &syms->syms[frame] : NULL;

		if (sym && sym->name)
			printf("  %s+0x%zx (%s)\n", sym->name, sym->offset,
			       sym->module ? sym->module : "unknown module");
		else
			printf("  0x%llx <no symbol>\n",
			       (unsigned long long)event->user_stack[frame]);
	}
	if (syms)
		blaze_syms_free(syms);
}

/* 处理 BPF 程序通过 perf buffer 发送到用户态的事件。 */
static int handle_event(void *ctx, void *data, size_t data_size)
{
	struct event event;
	char syscall_buf[64] = {};
	const char *name = syscall_buf;

	(void)ctx;

	/* perf buffer 中的数据地址不保证满足 struct event 的对齐要求。 */
	if (data_size < sizeof(event)) {
		fprintf(stderr, "event data is too short: %zu\n", data_size);
		return -1;
	}

	memcpy(&event, data, sizeof(event));
	/* ARM64 使用内置系统调用名表，不依赖设备安装 ausyscall。 */
	if (event.syscall_nr < 0 || event.syscall_nr > UINT_MAX ||
	    syscall_name((unsigned)event.syscall_nr, syscall_buf, sizeof(syscall_buf)))
		name = "unknown";
	if (event.type == EVENT_ENTER) {
		printf("enter pid=%u uid=%u comm=%s syscall=%s(%lld)\n",
		       event.pid, event.uid, event.comm, name, (long long)event.syscall_nr);
		print_user_stack(&event);
	} else if (event.type == EVENT_EXIT) {
		printf("exit pid=%u uid=%u comm=%s syscall=%s(%lld) ret=%lld\n",
		       event.pid, event.uid, event.comm, name,
		       (long long)event.syscall_nr, (long long)event.ret);
	}
	return 0;
}

/* 报告 perf buffer 因处理不及时而丢失的事件数量。 */
static void handle_lost_events(void *ctx, int cpu, __u64 lost_count)
{
	(void)ctx;
	fprintf(stderr, "lost %llu events on CPU #%d\n",
		(unsigned long long)lost_count, cpu);
}

int main(void)
{
	struct bpf_buffer *buffer = NULL;
	struct estrace_bpf *obj = NULL;
	__u32 map_key = 0;
	__u32 self_pid = getpid();
	int err = 0;

	libbpf_set_print(libbpf_print_fn);

	/* 打开 BPF 对象。当前版本不依赖设备上的内核 BTF。 */
	obj = estrace_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* 创建 perf buffer，用于接收内核态 BPF 程序发送的事件。 */
	buffer = bpf_buffer__new(obj->maps.events);
	if (!buffer) {
		fprintf(stderr, "failed to create perf buffer: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* 将 BPF 程序加载进内核。 */
	err = estrace_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF program: %s\n", strerror(-err));
		goto cleanup;
	}

	/* 先设置自身进程过滤，再挂载两个 tracepoint。 */
	err = bpf_map_update_elem(bpf_map__fd(obj->maps.ignored_pid),
				  &map_key, &self_pid, BPF_ANY);
	if (err) {
		fprintf(stderr, "failed to configure PID filter: %s\n", strerror(errno));
		goto cleanup;
	}

	/* 符号化失败时保留地址输出，不影响系统调用追踪。 */
	symbolizer = blaze_symbolizer_new();
	if (!symbolizer)
		fprintf(stderr, "failed to initialize symbolizer; showing raw addresses\n");

	/* 将入口和出口两个 tracepoint 程序一起挂载。 */
	err = estrace_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF program: %s\n", strerror(-err));
		goto cleanup;
	}

	/* 注册事件回调。 */
	err = bpf_buffer__open(buffer, handle_event, handle_lost_events, NULL);
	if (err) {
		fprintf(stderr, "failed to open perf buffer: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, handle_signal) == SIG_ERR ||
	    signal(SIGTERM, handle_signal) == SIG_ERR) {
		fprintf(stderr, "failed to install signal handler: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	printf("tracing raw_syscalls/sys_enter and sys_exit; press Ctrl-C to exit\n");
	while (!exiting) {
		err = bpf_buffer__poll(buffer, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "failed to poll perf buffer: %s\n", strerror(-err));
			break;
		}
		err = 0;
	}

cleanup:
	/* 无论中途哪一步失败，都统一释放用户态资源。 */
	bpf_buffer__free(buffer);
	estrace_bpf__destroy(obj);
	if (symbolizer)
		blaze_symbolizer_free(symbolizer);
	return err ? 1 : 0;
}

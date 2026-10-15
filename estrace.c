#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "blazesym.h"
#include "estrace.h"
#include "estrace.skel.h"
#include "syscall_helpers.h"

#define PERF_BUFFER_PAGES 64
#define POLL_TIMEOUT_MS 100

static volatile sig_atomic_t exiting;
static blaze_symbolizer *symbolizer;

static struct {
	__u32 pid;
	__u32 tid;
	__u32 uid;
	__s64 sys_id;
	unsigned duration;
	bool verbose;
	bool timestamp;
	bool print_uid;
	bool args;
	bool failed;
	bool callers;
	const char *name;
} env = {
	.uid = INVALID_UID,
	.sys_id = -1,
};

static void usage(const char *program)
{
	printf("Usage: %s [-T U e x c v] [-p PID] [-t TID] [-u UID] [-s SysID] [-d SECONDS] [-n NAME]\n"
	       "  -T  print time of receipt    -U  print UID\n"
	       "  -e  print six raw syscall arguments (hex)\n"
	       "      openat also prints its pathname by default (up to 191 bytes)\n"
	       "  -x  only failed syscalls    -c  symbolize user stack on exit\n"
	       "  -p  process PID             -t  thread TID\n"
	       "  -u  UID                     -s  syscall number (0 is valid)\n"
	       "  -d  duration in seconds     -n  process name substring\n"
	       "  -v  verbose libbpf output   -h  show this help\n", program);
}

static int parse_number(const char *text, unsigned long long maximum,
			unsigned long long *value)
{
	char *end;

	if (!text[0] || text[0] == '-')
		return -1;
	errno = 0;
	*value = strtoull(text, &end, 10);
	return errno || *end || *value > maximum ? -1 : 0;
}

static int parse_args(int argc, char **argv)
{
	unsigned long long value;
	int option;

	while ((option = getopt(argc, argv, "hTUexcvp:t:u:s:d:n:")) != -1) {
		switch (option) {
		case 'h': usage(argv[0]); return 1;
		case 'T': env.timestamp = true; break;
		case 'U': env.print_uid = true; break;
		case 'e': env.args = true; break;
		case 'x': env.failed = true; break;
		case 'c': env.callers = true; break;
		case 'v': env.verbose = true; break;
		case 'n': env.name = optarg; break;
		case 'p':
		case 't':
		case 'u':
		case 's':
		case 'd':
			if (parse_number(optarg, option == 'u' ? UINT_MAX - 1 : INT_MAX, &value) ||
			    ((option == 'p' || option == 't' || option == 'd') && !value)) {
				fprintf(stderr, "Invalid value for -%c: %s\n", option, optarg);
				return -1;
			}
			if (option == 'p') env.pid = value;
			if (option == 't') env.tid = value;
			if (option == 'u') env.uid = value;
			if (option == 's') env.sys_id = value;
			if (option == 'd') env.duration = value;
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		return -1;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void handle_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static void print_user_stack(const struct event *event)
{
	struct blaze_symbolize_src_process src = {
		.type_size = sizeof(src),
		.pid = event->pid,
		.no_map_files = true,
	};
	const struct blaze_syms *syms;
	uint64_t addresses[STACK_DEPTH];
	size_t count, index;

	if (event->stack_size <= 0) {
		printf("  user stack unavailable (code=%d)\n", event->stack_size);
		return;
	}
	count = (size_t)event->stack_size / sizeof(event->callers[0]);
	if (count > STACK_DEPTH)
		count = STACK_DEPTH;
	memcpy(addresses, event->callers, count * sizeof(addresses[0]));
	syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, addresses, count);
	for (index = 0; index < count; index++) {
		const struct blaze_sym *sym = syms && index < syms->cnt ? &syms->syms[index] : NULL;

		if (sym && sym->name)
			printf("  %s+0x%zx (%s)\n", sym->name, sym->offset,
			       sym->module ? sym->module : "unknown module");
		else
			printf("  0x%llx <no symbol>\n", (unsigned long long)event->callers[index]);
	}
	if (syms)
		blaze_syms_free(syms);
}

static void print_openat_path(const struct event *event)
{
	size_t index;

	if (event->path_len <= 0) {
		printf(" path=<unavailable: %d>", event->path_len);
		return;
	}
	printf(" path=\"");
	for (index = 0; index < OPENAT_PATH_LEN - 1 && event->path[index]; index++) {
		unsigned char character = event->path[index];

		if (character == '\\' || character == '"')
			putchar('\\');
		if (character >= 32 && character != 127)
			putchar(character);
		else
			printf("\\x%02x", character);
	}
	printf("\"");
	if (event->path_len == OPENAT_PATH_LEN)
		printf(" (possibly truncated)");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
	struct event event;
	char syscall_buf[64];
	const char *syscall;
	int index;

	(void)ctx;
	(void)cpu;
	if (size < sizeof(event)) {
		fprintf(stderr, "short perf event: %u bytes\n", size);
		return;
	}
	memcpy(&event, data, sizeof(event));
	event.comm[TASK_COMM_LEN - 1] = '\0';
	if (env.name && !strstr(event.comm, env.name))
		return;
	syscall = event.sys_id >= 0 && event.sys_id <= UINT_MAX &&
		!syscall_name((unsigned)event.sys_id, syscall_buf, sizeof(syscall_buf)) ?
		syscall_buf : "unknown";
	if (env.timestamp) {
		time_t now = time(NULL);
		struct tm local;
		char timestamp[16];

		localtime_r(&now, &local);
		strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &local);
		printf("%s ", timestamp);
	}
	printf("pid=%u tid=%u ", event.pid, event.tid);
	if (env.print_uid)
		printf("uid=%u ", event.uid);
	printf("comm=%s syscall=%s(%lld) ret=%lld", event.comm, syscall,
	       (long long)event.sys_id, (long long)event.ret);
	if (env.args) {
		printf(" args=[");
		for (index = 0; index < 6; index++)
			printf("%s0x%llx", index ? ", " : "",
			       (unsigned long long)event.args[index]);
		printf("]");
	}
	if (event.sys_id == ESTRACE_NR_OPENAT)
		print_openat_path(&event);
	putchar('\n');
	if (env.callers)
		print_user_stack(&event);
}

static void handle_lost_events(void *ctx, int cpu, __u64 count)
{
	(void)ctx;
	fprintf(stderr, "lost %llu perf events on CPU #%d\n",
		(unsigned long long)count, cpu);
}

int main(int argc, char **argv)
{
	struct estrace_bpf *obj = NULL;
	struct perf_buffer *buffer = NULL;
	struct timespec start, now;
	__u32 key = 0, self_pid = getpid();
	int err, parsed;

	parsed = parse_args(argc, argv);
	if (parsed)
		return parsed < 0;
	libbpf_set_print(libbpf_print_fn);
	obj = estrace_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object: %s\n", strerror(errno));
		return 1;
	}
	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->targ_uid = env.uid;
	obj->rodata->targ_sys_id = env.sys_id;
	obj->rodata->targ_failed = env.failed;
	obj->rodata->targ_callers = env.callers;

	err = estrace_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %s\n", strerror(-err));
		goto cleanup;
	}
	if (bpf_map_update_elem(bpf_map__fd(obj->maps.ignored_pid), &key, &self_pid, BPF_ANY)) {
		err = -errno;
		fprintf(stderr, "failed to ignore own PID: %s\n", strerror(errno));
		goto cleanup;
	}
	if (env.callers) {
		symbolizer = blaze_symbolizer_new();
		if (!symbolizer) {
			fprintf(stderr, "failed to create symbolizer\n");
			err = -1;
			goto cleanup;
		}
	}
	buffer = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
				  handle_event, handle_lost_events, NULL, NULL);
	if (!buffer) {
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %s\n", strerror(errno));
		goto cleanup;
	}
	err = estrace_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}
	if (signal(SIGINT, handle_signal) == SIG_ERR ||
	    signal(SIGTERM, handle_signal) == SIG_ERR) {
		err = -errno;
		fprintf(stderr, "failed to install signal handler: %s\n", strerror(errno));
		goto cleanup;
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!exiting) {
		err = perf_buffer__poll(buffer, POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			fprintf(stderr, "failed to poll perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (env.duration) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec - start.tv_sec >= env.duration)
				break;
		}
	}
	err = 0;

cleanup:
	perf_buffer__free(buffer);
	estrace_bpf__destroy(obj);
	if (symbolizer)
		blaze_symbolizer_free(symbolizer);
	return err != 0;
}

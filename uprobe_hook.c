#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "uprobe_hook.h"
#include "uprobe_hook.skel.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int signal_number)
{
	(void)signal_number;
	exiting = 1;
}

static int handle_event(void *ctx, struct event *data,size_t data_sz){
    printf("pid:%d\n", data->pid);
    return 0;
}

static int my_libbpf_print(enum libbpf_print_level level,const char *format, va_list args){
    return vfprintf(stderr, format,args);
}


int main(void)
{   
    // 定义一个结构体
	struct uprobe_hook_bpf *obj;
    struct ring_buffer *rb =NULL;
	int err;
    
    libbpf_set_print(my_libbpf_print);//自定义输出

	obj = uprobe_hook_bpf__open();
	if (!obj) {
		fprintf(stderr, "[zhou] failed to open  BPF program\n");
		return 1;
	}

    err = uprobe_hook_bpf__load(obj);
    if (err)
    {
        fprintf(stderr,"[zhou] failed to load  BPF program");
        goto cleanup;
    }
    

    //附加 eBPF程序
	err = uprobe_hook_bpf__attach(obj);
	if (err) {
        //附加失败
		fprintf(stderr, "[zhou] failed to attach BPF program: %d\n", err);
		goto cleanup;
	}

    //获取内核态的数据
    rb = ring_buffer__new(bpf_map__fd(obj->maps.ringbuf),(void *)handle_event,NULL,NULL);
    if(!rb){
        err =1;
        fprintf(stderr,"Failed to create ring buffer \n");
        goto cleanup;
    }
    printf("[zhou] Successfylly started! Press Ctrl+C to Stop.\n");


	if (signal(SIGINT, sig_handler) == SIG_ERR ||
	    signal(SIGTERM, sig_handler) == SIG_ERR) {
		perror("[zhou] signal");
		err = 1;
		goto cleanup;
	}

    printf("[zhou] Tracing libc getpid; press Ctrl-C to stop.\n");
    //判断是否退出
	while (!exiting) {
		int poll_err = ring_buffer__poll(rb, 100);
		if (poll_err == -EINTR)
			continue;
		if (poll_err < 0) {
			err = poll_err;
			fprintf(stderr, "Failed to poll ring buffer: %d\n", poll_err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	uprobe_hook_bpf__destroy(obj);
	return err ? 1 : 0;
}

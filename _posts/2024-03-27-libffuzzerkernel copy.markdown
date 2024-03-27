---
layout: post
title:  "Using libFuzzer with linux kernel!"
date:   2024-03-27 22:27:59 +0100
categories: fuzzing
---


{% highlight shell %}
# Use a base image with Ubuntu
FROM ubuntu:latest

# Update package lists
RUN apt-get update

# Install necessary packages
RUN apt-get install -y \
        build-essential \
        qemu-system-x86 \
        libpython2.7-dev \
        gettext \
        libelf-dev \
        git \ 
        flex \
        bison \
        bc \
        libssl-dev \
        ncurses-dev \
        python3-pip \
        python-setuptools \
        busybox-static \
        qemu-kvm \ 
        clang \
        protobuf-compiler \
        libprotobuf-dev \
        binutils \
        cmake \
        ninja-build \
	liblzma-dev \
	libz-dev \
	pkg-config \
	autoconf \
	libtool

# Cleanup
RUN apt-get clean && rm -rf /var/lib/apt/lists/*
{% endhighlight %}




{% highlight cpp %}

#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <asm/siginfo.h>

void send_sigsegv_to_process(void*  access_addr );
void send_sigsegv_to_process(void*  access_addr ) {

        kernel_siginfo_t info;
        memset(&info, 0, sizeof(kernel_siginfo_t));
        info.si_signo = SIGSEGV;  // Signal type
        info.si_pid = current->pid;  // Process ID to send the signal to
        info.si_code = SEGV_MAPERR;   // Signal code for a memory access error
        info.si_addr = access_addr;          // Address that caused the fault
        send_sig_info(SIGSEGV, &info, current);
}



static void print_error_description(struct kasan_report_info *info)
{

        //debugfs_create_dir("panic_meysam", NULL);
        send_sigsegv_to_process((void*)info->access_addr);

        pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);

        if (info->type != KASAN_REPORT_ACCESS) {
                pr_err("Free of addr %px by task %s/%d\n",
                        info->access_addr, current->comm, task_pid_nr(current));
                return;
        }

        if (info->access_size)
                pr_err("%s of size %zu at addr %px by task %s/%d\n",
                        info->is_write ? "Write" : "Read", info->access_size,
                        info->access_addr, current->comm, task_pid_nr(current));
        else
                pr_err("%s at addr %px by task %s/%d\n",
                        info->is_write ? "Write" : "Read",
                        info->access_addr, current->comm, task_pid_nr(current));
}
{% endhighlight %}


{% highlight cpp %}


#include <cmath>
#include <iostream>


#include "examples/libfuzzer/libfuzzer_example.pb.h"
#include "port/protobuf.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <memory.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

void fail(const char* msg, ...);
void cover_start();
void cover_stop();


#define KCOV_COVER_SIZE (256 << 10)
#define KCOV_TRACE_PC 0
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64_t)
#define KCOV_ENABLE _IO('c', 100)

__attribute__((section("__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[32 << 10];
uint64_t* kcov_data;




extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
	
	int kcov = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcov == -1)
		fail("open of /sys/kernel/debug/kcov failed");
	if (ioctl(kcov, KCOV_INIT_TRACE64, KCOV_COVER_SIZE))
		fail("cover init trace write failed");
	kcov_data = (uint64_t*)mmap(NULL, KCOV_COVER_SIZE * sizeof(kcov_data[0]),
				    PROT_READ | PROT_WRITE, MAP_SHARED, kcov, 0);
	if (kcov_data == MAP_FAILED)
		fail("cover mmap failed");
	if (ioctl(kcov, KCOV_ENABLE, KCOV_TRACE_PC))
		fail("cover enable write trace failed");
	close(kcov);

 	return 0;
}




void cover_start()
{
	__atomic_store_n(&kcov_data[0], 0, __ATOMIC_RELAXED);
}

void cover_stop()
{
	uint64_t ncov = __atomic_load_n(&kcov_data[0], __ATOMIC_RELAXED);
	
	
	
	if (ncov >= KCOV_COVER_SIZE)
		fail("too much cover: %llu", ncov);
	for (uint64_t i = 0; i < ncov; i++) {
		uint64_t pc = __atomic_load_n(&kcov_data[i + 1], __ATOMIC_RELAXED);
//	        printf("0x%lx\n", kcov_data[i + 1]);
		libfuzzer_coverage[pc % sizeof(libfuzzer_coverage)]++;
	}
}



void fail(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	_exit(1);
}

DEFINE_PROTO_FUZZER(const libfuzzer_example::Msg& message) {
protobuf_mutator::protobuf::FileDescriptorProto file;

        cover_start();
         // std::cerr << message.DebugString() << "\n";	
        // Emulate a bug.
        int fd = syscall(SYS_open, "example.txt", 4, message.sample_int());
        syscall(SYS_close,fd);
        cover_stop();
}
{% endhighlight %}


[jekyll-docs]: https://jekyllrb.com/docs/home
[jekyll-gh]:   https://github.com/jekyll/jekyll
[jekyll-talk]: https://talk.jekyllrb.com/

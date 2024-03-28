---
layout: post
title:  "Using libFuzzer with linux kernel!"
date:   2024-03-27 22:27:59 +0100
categories: fuzzing
---

I just wanted to expreirnace with kcov and see how can I hook it into libfuzzer and boot the kernel without spending too much on building root file system.

after some googling I found a very interesting blog post by [cloudflare](https://blog.cloudflare.com/a-gentle-introduction-to-linux-kernel-fuzzing/ )

they have had answered my second question on how to boot newly built linux kernel with current root file system with 
[virtme](https://github.com/amluto/virtme)
so basicall Virtme is a set of simple tools to run a virtualized Linux kernel that uses the host Linux distribution or a simple rootfs instead of a whole disk image.
Virtme is tiny, easy to use, and makes testing kernel changes quite simple.

So let's get started:
clone virtme and linux kenel 
{% highlight shell %}
git clone --depth 1 https://github.com/torvalds/linux.git
git clone --depth 1 https://github.com/amluto/virtme.git
cd linux
{% endhighlight %}


you have to enable kcov for all targets with KCOV_INSTRUMENT_ALL or specific makefile.
Enable KCOV in all "fs" subdirectory:
{% highlight shell %}
find "fs" -name Makefile \
    | xargs -L1 -I {} bash -c 'echo "KCOV_INSTRUMENT := y" >> {}'
{% endhighlight %}

then build linux kernel with kcov and kasan and some other flags needed by virtme

{% highlight shell %}
../virtme/virtme-configkernel  --defconfig
 
 ./scripts/config \
    -e KCOV \
    -d KCOV_INSTRUMENT_ALL \
    -e KCOV_ENABLE_COMPARISONS
   
   
./scripts/config \
    -e DEBUG_FS -e DEBUG_INFO \
    -e KALLSYMS -e KALLSYMS_ALL \
    -e NAMESPACES -e UTS_NS -e IPC_NS -e PID_NS -e NET_NS -e USER_NS \
    -e CGROUP_PIDS -e MEMCG -e CONFIGFS_FS -e SECURITYFS \
    -e KASAN -e KASAN_INLINE -e WARNING \
    -e FAULT_INJECTION -e FAULT_INJECTION_DEBUG_FS \
    -e FAILSLAB -e FAIL_PAGE_ALLOC \
    -e FAIL_MAKE_REQUEST -e FAIL_IO_TIMEOUT -e FAIL_FUTEX \
    -e LOCKDEP -e PROVE_LOCKING \
    -e DEBUG_ATOMIC_SLEEP \
    -e PROVE_RCU -e DEBUG_VM \
    -e REFCOUNT_FULL -e FORTIFY_SOURCE \
    -e HARDENED_USERCOPY -e LOCKUP_DETECTOR \
    -e SOFTLOCKUP_DETECTOR -e HARDLOCKUP_DETECTOR \
    -e BOOTPARAM_HARDLOCKUP_PANIC \
    -e DETECT_HUNG_TASK -e WQ_WATCHDOG \
    --set-val DEFAULT_HUNG_TASK_TIMEOUT 140 \
    --set-val RCU_CPU_STALL_TIMEOUT 100 \
    -e UBSAN \
    -d RANDOMIZE_BASE
{% endhighlight %}
    

in order to provied kenrnel code coverage to libfuzzer we can use __libfuzzer_extra_counters, you can see a good example  in [syzkaller]
(https://github.com/google/syzkaller/blob/master/tools/kcovfuzzer/kcovfuzzer.c)
and its documentation in [kernel website](https://docs.kernel.org/dev-tools/kcov.html)


I used wanted to have Structure-Aware kernel Fuzzing with libFuzzer so I deciede to use libprotobuf-mutator.
which has show is very powerfull 
almost every kernel attack vector is Stateful APIs. you can't just feed raw buffer to it. 

* [poc2018](https://powerofcommunity.net/poc2018/ned.pdf)
* [project zero blog](https://googleprojectzero.blogspot.com/2019/12/sockpuppet-walkthrough-of-kernel.html)
* [chromium](https://chromium.googlesource.com/chromium/src/+/main/testing/libfuzzer/libprotobuf-mutator.md)
there are tons of resource out there about using libprotobuf-mutator
I can't explain better then original google fuzzing doc

> Protocol Buffers As Intermediate Format
Protobufs provide a convenient way to serialize structured data, and LPM provides an easy way to mutate protobufs for structure-aware fuzzing. Thus, it is tempting to use libFuzzer+LPM for APIs that consume structured data other than protobufs.

but simpply clone the repo and replace following code with [this file](https://github.com/google/libprotobuf-mutator/blob/master/examples/libfuzzer/libfuzzer_bin_example.cc

{% highlight cpp %}
git clone https://github.com/google/libprotobuf-mutator.git
{% endhighlight %}

you can commnent out other files in CMakeLists.txt because we want to modify .proto file.

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
void kcov_start();
void kcov_stop();
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
		fail("init trace write failed");
	kcov_data = (uint64_t*)mmap(NULL, KCOV_COVER_SIZE * sizeof(kcov_data[0]),
				    PROT_READ | PROT_WRITE, MAP_SHARED, kcov, 0);
	if (kcov_data == MAP_FAILED)
		fail("mmap failed");
	if (ioctl(kcov, KCOV_ENABLE, KCOV_TRACE_PC))
		fail("enable write trace failed");
	close(kcov);

 	return 0;
}
void kcov_start()
{
	__atomic_store_n(&kcov_data[0], 0, __ATOMIC_RELAXED);
}
void kcov_stop()
{
	uint64_t ncov = __atomic_load_n(&kcov_data[0], __ATOMIC_RELAXED);
	if (ncov >= KCOV_COVER_SIZE)
		fail("too much cover: %llu", ncov);
	for (uint64_t i = 0; i < ncov; i++) {
		uint64_t pc = __atomic_load_n(&kcov_data[i + 1], __ATOMIC_RELAXED);
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

        kcov_start();
        // your logic should be here:

        // std::cerr << message.DebugString() << "\n";	
        // Emulate a bug.
        //int fd = syscall(SYS_open, "example.txt", 4, message.sample_int());
        int fd = syscall(SYS_open, "example.txt", 4, 0x4141);
        syscall(SYS_close,fd);

        kcov_stop();
}
{% endhighlight %}


build the libprotobuf-mutator

the interesting parts begin, now if the kasan panics, libfuzzer dosen't have a way to know it and will discard the sample,so to save the sample that triggered the crash we have to tell to libfuzzer that kernel has paniced.

At first I used others ways to let the fuzzer know about panic but I decied to mimic SIGSEGV and send signal to libfuzzer when there is a kasan panic in kernel. when libfuzzer gets this signal it will save the sample and quit.

so add send_sigsegv_to_process function to print_error_description in /mm/kasan/report.c file.

make sure 
"kernel.panic_on_warn" and 
"kernel.panic_on_oops"
are set to "0"
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

copy libprotobuf example file to testfuzz. now you can boot the new kernel and run the fuzzer with
{% highlight shell %}
cd linux
 ../virtme/virtme-run --kimg arch/x86/boot/bzImage --rwdir ../testfuzz/ --qemu-opts  -m 2G -smp 2 -enable-kvm
{% endhighlight %}


[jekyll-docs]: https://jekyllrb.com/docs/home
[jekyll-gh]:   https://github.com/jekyll/jekyll
[jekyll-talk]: https://talk.jekyllrb.com/





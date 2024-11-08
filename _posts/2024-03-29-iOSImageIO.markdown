---
layout: post
title: "ImageIO, the infamous iOS Zero Click Attack Vector."
date: 2024-03-29 10:27:59 +0100
categories: fuzzing
---

ImageIO is Apple's Framework that handles image parsing, which exposes 0click attack surface

Months after reading [this blog post from Google Project Zero](https://googleprojectzero.blogspot.com/2020/04/fuzzing-imageio.html) about fuzzing ImageIO, I used LLDB to examine the testHeader functions, it turned out there are three new `testHeader` functions for different file formats.

such as `KTX2` and `WebP` and `ETC`, so because they were fairly new I thought maybe they have not been fuzzed by Project Zero.

{% highlight shell %}
1.30: where = ImageIO`IIO_Reader_KTX2::testHeader(unsigned char const*, unsigned long, __CFString const*), address = 0x00007ff8134cecc2, resolved, hit count = 5 
1.26: where = ImageIO`IIO_Reader_WebP::testHeader(unsigned char const*, unsigned long, __CFString const*), address = 0x00007ff81341f368, resolved, hit count = 0 
1.31: where = ImageIO`IIO_Reader_ETC::testHeader(unsigned char const*, unsigned long, __CFString const*), address = 0x00007ff8134dd1c6, resolved, hit count = 2
{% endhighlight %}



KTX2 is a relatively new specification introduced after the Project Zero fuzzing efforts. Arguably, its source code is also new. Further information about KTX2 can be found in its specification document here: [khronos.org](https://registry.khronos.org/KTX/specs/2.0/ktxspec_v2.html).

Although WebP has not been fuzzed by Project Zero, it is fuzzed with Google OSS-Fuzz. So I decided not to compete with Google's fuzzer in this regard.

Another important issue I noticed was that in the Project Zero's blog, ImageIO was using `OpenEXR`, but in my test, ImageIO was using Apple's closed-source new implementation of EXR in `libAppleEXR.dylib`. Therefore, I decided to fuzz these two file formats, EXR and KTX2.

the Samuel Groß has modifed Honggfuzz to have a binary Coverage-guided fuzzing. but I ported Project Zero's harness to [Jackalope fuzzer](https://github.com/googleprojectzero/Jackalope) (awesome project thanks to Ivan Fratric), also I used  `initWithData` method of NSImage and in-memory fuzzing option of Jackalope to make the fuzzing faster. 

I managed to find lots of KTX2 sample files in the following pages:
- [https://github.com/donmccurdy/KTX-Parse/tree/main/test/data/reference](https://github.com/donmccurdy/KTX-Parse/tree/main/test/data/reference)
- [https://github.com/KhronosGroup/KTX-Software](https://github.com/KhronosGroup/KTX-Software)


you can also use `DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib` to increase the change of finding more bugs.  

My fuzzing effort found several vulnerabilities, you can see them in my [CVEs page](https://r00tkitsmm.github.io/fuzzing/2024/03/27/CVEs.html)



{% highlight cpp %}
#include <Foundation/Foundation.h>
#include <Foundation/NSURL.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/shm.h>
#include <dirent.h>

#import <ImageIO/ImageIO.h>
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>


#define MAX_SAMPLE_SIZE 1000000
#define SHM_SIZE (4 + MAX_SAMPLE_SIZE)
unsigned char *shm_data;

int setup_shmem(const char *name)
{
  int fd;

  // get shared memory file descriptor (NOT a file)
  fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
  if (fd == -1)
  {
    printf("Error in shm_open\n");
    return 0;
  }

  // map shared memory to process address space
  shm_data = (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
  if (shm_data == MAP_FAILED)
  {
    printf("Error in mmap\n");
    return 0;
  }

  return 1;
}


extern bool CGRenderingStateGetAllowsAcceleration(void*);
extern bool CGRenderingStateSetAllowsAcceleration(void*, bool);
extern void* CGContextGetRenderingState(CGContextRef);

void dummyLogProc() { }

extern void HF_ITER(uint8_t** buf, size_t* len);
extern void ImageIOSetLoggingProc(void*);


void __attribute__ ((noinline)) fuzz_image() {

    char *sample_bytes = NULL;
    uint32_t sample_size = 0;
  
  // read the sample either from file or
  // shared memory
    sample_size = *(uint32_t *)(shm_data);
    if(sample_size > MAX_SAMPLE_SIZE) sample_size = MAX_SAMPLE_SIZE;
    sample_bytes = (char *)malloc(sample_size);
    memcpy(sample_bytes, shm_data + sizeof(uint32_t), sample_size);
    NSData* content = [NSData dataWithBytes:sample_bytes length:sample_size];
    free(sample_bytes)
    
    NSImage* img = [[NSImage alloc] initWithData:content];
    
   // NSImage *img = [[NSImage alloc]initWithContentsOfFile:objcstring];
    if (img == nil) {
        NSLog(@"image nil");
    }
    
    CGImageRef cgImg = [img CGImageForProposedRect:nil context:nil hints:nil];
    if (cgImg) {
        size_t width = CGImageGetWidth(cgImg);
        size_t height = CGImageGetHeight(cgImg);
        CGColorSpaceRef colorspace = CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx = CGBitmapContextCreate(0, width, height, 8, 0, colorspace, 1);
        void* renderingState = CGContextGetRenderingState(ctx);
        CGRenderingStateSetAllowsAcceleration(renderingState, false);
        CGRect rect = CGRectMake(0, 0, width, height);
        CGContextDrawImage(ctx, rect, cgImg);
        CGColorSpaceRelease(colorspace);
        CGContextRelease(ctx);
        CGImageRelease(cgImg);
    }
    [img release];
}
int main(int argc, const char* argv[]) {
    NSError* err = 0;
    if(argc < 2) {
        NSLog(@"need an image file");
        return 0;
    }
    if(!setup_shmem(argv[1])) {
      printf("Error mapping shared memory\n");
    }
    ImageIOSetLoggingProc(&dummyLogProc);
    fuzz_image();

    return 0;
}
{% endhighlight %}


[jekyll-docs]: https://jekyllrb.com/docs/home
[jekyll-gh]:   https://github.com/jekyll/jekyll
[jekyll-talk]: https://talk.jekyllrb.com/





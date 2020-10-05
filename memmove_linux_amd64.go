// Package pcap is a wrapper around the pcap library.
package pcap

/*
#cgo LDFLAGS: -Wl,-Bstatic -lpcap -Wl,-Bdynamic,--wrap=memcpy
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ifaddrs.h>

#ifdef  __GLIBC__
// See this for glibc 2.14 hack below
// https://www.win.tue.nl/~aeb/linux/misc/gcc-semibug.html
void *__memcpy_glibc_2_2_5(void *, const void *, size_t);

// We use memmove rather than memcpy here since it is safer
// for overlapping memory regions.
asm(".symver __memcpy_glibc_2_2_5, memmove@GLIBC_2.2.5");

void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
  	return __memcpy_glibc_2_2_5(dest, src, n);
}
#endif
*/
import "C"

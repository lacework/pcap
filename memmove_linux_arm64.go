// Package pcap is a wrapper around the pcap library.
package pcap

/*
#cgo LDFLAGS: -Wl,-Bstatic -lpcap -Wl,-Bdynamic,--wrap=memcpy
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ifaddrs.h>

#ifdef  __GLIBC__
// We use memmove rather than memcpy here since it is safer
// for overlapping memory regions.

void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}
#endif
*/
import "C"

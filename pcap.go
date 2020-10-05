// Package pcap is a wrapper around the pcap library.
package pcap

/*
#cgo LDFLAGS: -Wl,-Bstatic -lpcap -Wl,-Bdynamic,--wrap=memcpy
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ifaddrs.h>

#define MAX_PACKETS     10
#define PCAP_DISPATCH_OVERFLOW 5
#define MAX_PKT_CAPLEN  576
struct user {
	int	pkts;
	char	*hdrs;
	char	*data;
	int	hdrsize;
	pcap_t  *p;
};
extern int Sizeof_pcap_pkthdr(void)
{
	return sizeof(struct pcap_pkthdr);
}
void pcaphandler(u_char *u2, const struct pcap_pkthdr *h, const u_char *bytes)
{
	struct user *u = (struct user *)u2;
//	int breakout = 0;

//	if (u->pkts >= MAX_PACKETS-1) {
//		breakout = 1;
//	}
	if (u->pkts >= MAX_PACKETS*PCAP_DISPATCH_OVERFLOW) {
		return;
	}
	int len = h->caplen;
	if (len == 0) {
		return;
	}
	if (len > MAX_PKT_CAPLEN) {
		len=MAX_PKT_CAPLEN;
	}
	memmove(u->hdrs + u->pkts*u->hdrsize, h, u->hdrsize);

	memmove(u->data + u->pkts*MAX_PKT_CAPLEN, bytes, len);
	u->pkts++;
//	if (breakout == 1) {
//		pcap_breakloop(u->p);
//	}
}
// Workaround for not knowing how to cast to const u_char**
int hack_pcap_next_ex(pcap_t * p, char *hdrs, char *data)
{
	struct user u;
	int ret = 0;

	u.hdrs = hdrs;
	u.data = data;
	u.hdrsize = Sizeof_pcap_pkthdr();
	u.p = p;
	u.pkts = 0;

	ret = pcap_dispatch(p, MAX_PACKETS, pcaphandler,(u_char *)(&u));
	if (u.pkts !=0) {
		return u.pkts;
	}
//	if (ret == -2) {
//printf("Setting ret to 0 %d %d\n", ret, u.pkts);
//		return 0;
//	}
	return ret;
}
void hack_pcap_dump(pcap_dumper_t * dumper, struct pcap_pkthdr *pkt_header,
		      u_char * pkt_data)
{
    pcap_dump((u_char *)dumper, pkt_header, pkt_data);
}
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lacework/agent/datacollector/dlog"
	"io/ioutil"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type Pcap struct {
	cptr    *C.pcap_t
	hdrs    unsafe.Pointer
	data    unsafe.Pointer
	max     int
	used    int
	seq     uint32
	hdrsize int
	IsRaw   bool
}

type PcapDumper struct {
	cptr *C.pcap_dumper_t
}

type pcapError struct{ string }

type Stat struct {
	PacketsReceived  uint32
	PacketsDropped   uint32
	PacketsIfDropped uint32
}

type Interface struct {
	Name        string
	Description string
	Addresses   []IFAddress
	Flags       uint
	// TODO: add more elements
}

type IFAddress struct {
	IP      net.IP
	Netmask net.IPMask
	Family  uint16
	IfName  string
	Flags   uint
	// TODO: add broadcast + PtP dst ?
}

func Version() string               { return C.GoString(C.pcap_lib_version()) }
func (p *Pcap) Datalink() int       { return int(C.pcap_datalink(p.cptr)) }
func (e *pcapError) Error() string  { return e.string }
func (p *Pcap) Geterror() error     { return &pcapError{C.GoString(C.pcap_geterr(p.cptr))} }
func (p *Pcap) Next() (pkt *Packet) { rv, _ := p.NextEx(nil); return rv }

func (h *Pcap) initHdrsData() {
	h.hdrsize = int(C.Sizeof_pcap_pkthdr())

	// Allocate 5x the buffer since pcap_dispatch seems to overflow
	h.hdrs = (C.calloc(C.size_t(h.hdrsize*C.MAX_PACKETS*C.PCAP_DISPATCH_OVERFLOW), 1))
	h.data = (C.calloc(C.MAX_PKT_CAPLEN*C.MAX_PACKETS*C.PCAP_DISPATCH_OVERFLOW, 1))
	h.max = 0
	h.used = 0
	h.seq = 0
}
func Create(device string) (handle *Pcap, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	h.cptr = C.pcap_create(dev, buf)
	if nil == h.cptr {
		handle = nil
		err = &pcapError{C.GoString(buf)}
	} else {
		handle = h
		h.initHdrsData()
	}

	C.free(unsafe.Pointer(buf))
	return
}

// Set buffer size (units in bytes) on activated handle.
func (p *Pcap) SetBufferSize(sz int32) error {
	if C.pcap_set_buffer_size(p.cptr, C.int(sz)) != 0 {
		return p.Geterror()
	}
	return nil
}

//  If arg p is non-zero promiscuous mode will be set on capture handle when it is activated.
func (p *Pcap) SetPromisc(promisc bool) error {
	var pro int32
	if promisc {
		pro = 1
	}

	if C.pcap_set_promisc(p.cptr, C.int(pro)) != 0 {
		return p.Geterror()
	}
	return nil
}

func (p *Pcap) SetSnapLen(s int32) error {
	if C.pcap_set_snaplen(p.cptr, C.int(s)) != 0 {
		return p.Geterror()
	}
	return nil
}

// Set read timeout (milliseconds) that will be used on a capture handle when it is activated.
func (p *Pcap) SetReadTimeout(toMs int32) error {
	if C.pcap_set_timeout(p.cptr, C.int(toMs)) != 0 {
		return p.Geterror()
	}
	return nil
}

// Activate a packet capture handle to look at packets on the network, with the options that
// were set on the handle being in effect.
func (p *Pcap) Activate() error {
	if C.pcap_activate(p.cptr) != 0 {
		return p.Geterror()
	}
	return nil
}

// OpenLive opens a device and returns a handler.
func OpenLive(device string, snaplen int32, promisc bool, timeout_ms int32) (handle *Pcap, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)
	var pro int32
	if promisc {
		pro = 1
	}

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	h.cptr = C.pcap_open_live(dev, C.int(snaplen), C.int(pro), C.int(timeout_ms), buf)
	if nil == h.cptr {
		handle = nil
		err = &pcapError{C.GoString(buf)}
	} else {
		handle = h
		h.initHdrsData()
		h.FindRawDataLinks()
	}
	C.free(unsafe.Pointer(buf))
	return
}

// Openoffline
func OpenOffline(file string) (handle *Pcap, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	h := new(Pcap)

	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	h.cptr = C.pcap_open_offline(cf, buf)
	if nil == h.cptr {
		handle = nil
		err = &pcapError{C.GoString(buf)}
	} else {
		handle = h
		h.initHdrsData()
	}
	C.free(unsafe.Pointer(buf))
	return
}

func (p *Pcap) FindRawDataLinks() {
	var dltbuf *C.int

	p.IsRaw = false
	n := int(C.pcap_list_datalinks(p.cptr, &dltbuf))
	if -1 == n {
		dlog.Infof("list datalinks Read Error")
		return
	}

	defer C.pcap_free_datalinks(dltbuf)

	dltArray := (*[100]C.int)(unsafe.Pointer(dltbuf))

	for i := 0; i < n; i++ {
		expr1 := C.pcap_datalink_val_to_name((*dltArray)[i])
		expr2 := C.pcap_datalink_val_to_description((*dltArray)[i])
		if i == 0 && C.GoString(expr2) == "Raw IP" && C.GoString(expr1) == "RAW" {
			dlog.Debugf("datalinks type Raw IP found")
			p.IsRaw = true
			break
		}
	}
	return
}

// Pcap closes a handler.
func (p *Pcap) Close() {
	if p.cptr != nil {
		C.pcap_close(p.cptr)
		p.cptr = nil
	}
	if p.hdrs != nil {
		C.free(unsafe.Pointer(p.hdrs))
		p.hdrs = nil
	}
	if p.data != nil {
		C.free(unsafe.Pointer(p.data))
		p.data = nil
	}
	p.max = 0
	p.used = 0
	p.seq = 0
}

func (p *Pcap) IsBufferReleased() bool {
	return p.hdrs == nil && p.data == nil
}

func (p *Pcap) NextEx(pktin *Packet) (pkt *Packet, result int32) {
	if pktin == nil {
		pkt = new(Packet)
	} else {
		pkt = pktin
		pkt.Headers_cnt = 0
	}
	if pkt.data == nil {
		pkt.data = make([]byte, C.MAX_PKT_CAPLEN)
	}
	pkt.Data = nil

	if p.max-p.used > 0 {
		p.getNextPkt(pkt)
		return pkt, 1
	}
	p.used = 0
	p.max = 0
	max := int32(C.hack_pcap_next_ex(p.cptr, (*C.char)(p.hdrs), (*C.char)(p.data)))
	if max > 0 {
		p.seq++
		pkt.Seq = p.seq
		p.max = int(max)
		p.getNextPkt(pkt)

		return pkt, 1
	}
	return pkt, max
}

func (p *Pcap) getNextPkt(pkt *Packet) {

	pkthdr := *((*C.struct_pcap_pkthdr)(unsafe.Pointer(uintptr(p.hdrs) + uintptr(p.hdrsize*p.used))))
	buf := unsafe.Pointer(uintptr(p.data) + uintptr(C.MAX_PKT_CAPLEN*p.used))
	p.used++

	pkt.Time = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000) // pcap provides usec but time.Unix requires nsec
	pkt.Caplen = uint32(pkthdr.caplen)
	pkt.Len = uint32(pkthdr.len)

	pkt.LinkType = 1 //LINKTYPE_ETHERNET
	if p.IsRaw == true {
		pkt.LinkType = 101 //LINKTYPE_RAW
	}
	if pkt.Caplen > C.MAX_PKT_CAPLEN {
		pkt.Partial = pkt.Caplen - C.MAX_PKT_CAPLEN
		pkt.Caplen = C.MAX_PKT_CAPLEN
	}
	pkt.Data = (*[C.MAX_PKT_CAPLEN]byte)(buf)[0:pkt.Caplen]
	if int(binary.BigEndian.Uint16(pkt.Data[12:14])) == 0x0806 {
		if pkt.Data[14+4] == 0 && len(pkt.Data) >= int(8+2*pkt.Data[14+4]+2*pkt.Data[14+5]) {
			dlog.Infof("s:%d m:%d u:%d r:%d pktin [C:%d P:%d L:%d] Data %x", p.seq, p.max, p.used, pkt.Caplen, pkt.Partial, pkt.Len, bytes.Split(pkt.Data, []byte(",")))
		}
	}
}

func (p *Pcap) Getstats() (stat *Stat, err error) {
	var cstats C.struct_pcap_stat
	if -1 == C.pcap_stats(p.cptr, &cstats) {
		return nil, p.Geterror()
	}
	stats := new(Stat)
	stats.PacketsReceived = uint32(cstats.ps_recv)
	stats.PacketsDropped = uint32(cstats.ps_drop)
	stats.PacketsIfDropped = uint32(cstats.ps_ifdrop)

	return stats, nil
}

func (p *Pcap) SetFilter(expr string) (err error) {
	var bpf C.struct_bpf_program
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if -1 == C.pcap_compile(p.cptr, &bpf, cexpr, 1, 0) {
		return p.Geterror()
	}

	if -1 == C.pcap_setfilter(p.cptr, &bpf) {
		C.pcap_freecode(&bpf)
		return p.Geterror()
	}
	C.pcap_freecode(&bpf)
	return nil
}

func (p *Pcap) SetDirection(direction string) (err error) {
	var pcap_direction C.pcap_direction_t
	if direction == "in" {
		pcap_direction = C.PCAP_D_IN
	} else if direction == "out" {
		pcap_direction = C.PCAP_D_OUT
	} else {
		pcap_direction = C.PCAP_D_INOUT
	}
	if -1 == C.pcap_setdirection(p.cptr, pcap_direction) {
		return p.Geterror()
	}
	return nil
}

func (p *Pcap) SetDataLink(dlt int) error {
	if -1 == C.pcap_set_datalink(p.cptr, C.int(dlt)) {
		return p.Geterror()
	}
	return nil
}

func DatalinkValueToName(dlt int) string {
	if name := C.pcap_datalink_val_to_name(C.int(dlt)); name != nil {
		return C.GoString(name)
	}
	return ""
}

func DatalinkValueToDescription(dlt int) string {
	if desc := C.pcap_datalink_val_to_description(C.int(dlt)); desc != nil {
		return C.GoString(desc)
	}
	return ""
}

func getNetworkInterfaceInfo(ifaddrs *C.struct_ifaddrs, ipaddr IFAddress) (string, uint, net.IPMask) {
	for fi := ifaddrs; fi != nil; fi = fi.ifa_next {
		if (fi.ifa_addr == nil) || (C.int(fi.ifa_flags)&syscall.IFF_UP != syscall.IFF_UP) {
			continue
		}
		if (C.int(fi.ifa_addr.sa_family) == syscall.AF_INET) || (C.int(fi.ifa_addr.sa_family) == syscall.AF_INET6) {
			var ifaddr IFAddress
			var err error
			if ifaddr.IP, ifaddr.Family, err = sockaddrToIP((*syscall.RawSockaddr)(unsafe.Pointer(fi.ifa_addr))); err != nil {
				sa_in := (*C.struct_sockaddr_in)(unsafe.Pointer(fi.ifa_addr))
				dlog.Errf("sockadd to IP %v err %v", sa_in, err)
			}
			if ifaddr.IP.Equal(ipaddr.IP) == true {
				if ifaddr.Netmask, _, err = sockaddrToIP((*syscall.RawSockaddr)(unsafe.Pointer(fi.ifa_netmask))); err != nil {
					sa_in := (*C.struct_sockaddr_in)(unsafe.Pointer(fi.ifa_netmask))
					dlog.Errf("sockadd to IP %v err %v", sa_in, err)
				}
				//dlog.Debugf("IF info %v : %v : %v", C.GoString(fi.ifa_name), uint(fi.ifa_flags), ifaddr.Netmask)
				return C.GoString(fi.ifa_name), uint(fi.ifa_flags), ifaddr.Netmask
			}
		}
	}
	return "", 0, []byte{0xff, 0xff, 0xff, 0}
}

func FindAllDevs() (ifs []Interface, err error) {
	var buf *C.char
	buf = (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))
	var alldevsp *C.pcap_if_t

	if -1 == C.pcap_findalldevs((**C.pcap_if_t)(&alldevsp), buf) {
		return nil, errors.New(C.GoString(buf))
	}
	defer C.pcap_freealldevs((*C.pcap_if_t)(alldevsp))
	dev := alldevsp
	var i uint32
	for i = 0; dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		i++
	}
	ifs = make([]Interface, 0, 1) // i not possible to use since we may have network aliases
	dev = alldevsp
	var ifaddrs *C.struct_ifaddrs
	getrc, _ := C.getifaddrs(&ifaddrs)
	if getrc == 0 {
		defer C.freeifaddrs(ifaddrs)
	}
	for j := uint32(0); dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		var ipv4, ipv6 int
		var iface Interface
		iface.Addresses, ipv4, ipv6 = findAllAddresses(dev.addresses)
		if getrc == 0 {
			for k, ipaddr := range iface.Addresses {
				iface.Addresses[k].IfName, iface.Addresses[k].Flags, iface.Addresses[k].Netmask = getNetworkInterfaceInfo(ifaddrs, ipaddr)
			}
		} else {
			for k, ipaddr := range iface.Addresses {
				iface.Addresses[k].IfName = C.GoString(dev.name)
				iface.Addresses[k].Flags = uint(dev.flags)
				iface.Addresses[k].Netmask = ipaddr.Netmask
			}
		}
		dlog.Debugf("Found IF %v ipv4 %v ipv6 %v ifaddr %v", C.GoString(dev.name), ipv4, ipv6, iface.Addresses)
		iface.Description = C.GoString(dev.description)
		iface.Flags = uint(dev.flags)
		iface.Name = C.GoString(dev.name)
		ifs = append(ifs, iface)
		j++
		// TODO: add more elements
	}
	return
}

func findAllAddresses(addresses *C.struct_pcap_addr) (retval []IFAddress, ipv4, ipv6 int) {
	// TODO - make it support more than IPv4 and IPv6?
	retval = make([]IFAddress, 0, 1)
	for curaddr := addresses; curaddr != nil; curaddr = (*C.struct_pcap_addr)(curaddr.next) {
		if curaddr.addr == nil {
			continue
		}
		var a IFAddress
		var err error
		if a.IP, a.Family, err = sockaddrToIP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr))); err != nil {
			continue
		}
		if a.Netmask, _, err = sockaddrToIP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.netmask))); err != nil {
			continue
		}
		if a.Family == syscall.AF_INET {
			ipv4++
		} else if a.Family == syscall.AF_INET6 {
			ipv6++
		}
		retval = append(retval, a)
	}
	return
}

func sockaddrToIP(rsa *syscall.RawSockaddr) (IP []byte, Family uint16, err error) {
	switch rsa.Family {
	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		IP = make([]byte, 4)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		Family = syscall.AF_INET
		return
	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		IP = make([]byte, 16)
		for i := 0; i < len(IP); i++ {
			IP[i] = pp.Addr[i]
		}
		Family = syscall.AF_INET6
		return
	}
	err = errors.New("Unsupported address type")
	return
}

// Inject ...
func (p *Pcap) Inject(data []byte) (err error) {
	buf := (*C.char)(C.malloc((C.size_t)(len(data))))

	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = data[i]
	}

	if -1 == C.pcap_inject(p.cptr, unsafe.Pointer(buf), (C.size_t)(len(data))) {
		err = p.Geterror()
	}
	C.free(unsafe.Pointer(buf))
	return
}

func (p *Pcap) DumpOpen(ofile *string) (dumper *PcapDumper, err error) {
	d := new(PcapDumper)
	d.cptr = C.pcap_dump_open(p.cptr, C.CString(*ofile))
	if nil == d.cptr {
		return d, errors.New("Cannot open dumpfile")
	}
	dumper = d
	return
}

/*
func (p *Pcap) PcapLoop(pktnum int, dumper *PcapDumper) (result int32, err error) {
	var pkthdr_ptr *C.struct_pcap_pkthdr
	var buf_ptr *C.u_char

	for i := 0; true; {
		result = int32(C.hack_pcap_next_ex(p.cptr, &pkthdr_ptr, &buf_ptr))
		switch result {
		case 0:
			continue // timeout
		case 1:
			// success : capturing packet
		case -1:
			return result, errors.New("Error in pcap next ex")
		case -2:
			return // reach EOF in offline mode
		}
		if nil == buf_ptr {
			continue
		}
		if nil != dumper {
			p.PcapDump(dumper, pkthdr_ptr, buf_ptr)
			p.PcapDumpFlush(dumper)
		}
		if pktnum > 0 {
			i++
			if i >= pktnum {
				break
			}
		}
	}
	return
}
*/

func (p *Pcap) PcapDump(dumper *PcapDumper, pkthdr_ptr *C.struct_pcap_pkthdr, buf_ptr *C.u_char) {
	C.hack_pcap_dump(dumper.cptr, pkthdr_ptr, buf_ptr)
}

func (p *Pcap) PcapDumpFlush(dumper *PcapDumper) error {
	if -1 == C.pcap_dump_flush(dumper.cptr) {
		return p.Geterror()
	}
	return nil
}

func (p *Pcap) PcapDumpClose(dumper *PcapDumper) {
	C.pcap_dump_close(dumper.cptr)
}

type ifreq struct {
	ifr_name [16]byte
	ifr_data uintptr
}

func GetArp(if_name string) string {
	data, err := ioutil.ReadFile("/sys/class/net/" + if_name + "/address")
	if err != nil {
		sockfd, _, err := syscall.RawSyscall(syscall.SYS_SOCKET, syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
		if err != 0 {
			return ""
		}
		defer syscall.Close(int(sockfd))

		var name [16]byte
		copy(name[:], []byte(if_name))

		var hwaddr [16]byte
		ifr := ifreq{
			ifr_name: name,
			ifr_data: uintptr(unsafe.Pointer(&hwaddr)),
		}
		_, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(sockfd), syscall.SIOCGIFHWADDR, uintptr(unsafe.Pointer(&ifr)))
		if err != 0 {
			return ""
		}
		// magic to convert uintptr to byte array
		const sizeOfUintPtr = unsafe.Sizeof(uintptr(0))
		macddr := (*[sizeOfUintPtr]byte)(unsafe.Pointer(&ifr.ifr_data))[:]

		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", macddr[2], macddr[3], macddr[4], macddr[5], macddr[6], macddr[7])
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

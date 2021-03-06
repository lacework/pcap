package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/lacework/agent/datacollector/dlog"
	"reflect"
	"strings"
	"time"
)

type PacketTime struct {
	Sec  int32
	Usec int32
}

// Packet is a single packet parsed from a pcap file.
type Packet struct {
	// porting from 'pcap_pkthdr' struct
	Time    time.Time // packet send/receive time
	Caplen  uint32    // bytes stored in the file (caplen <= len)
	Len     uint32    // bytes sent/received
	Partial uint32    // partial bytes clipped
	Seq     uint32    // pkt capture sequence number

	Data []byte // packet data

	Type     int // protocol type, see LINKTYPE_*
	LinkType int // [enhnacement] handle LINKTYPE_ETHERNET or LINKTYPE_RAW
	DestMac  uint64
	SrcMac   uint64

	Headers     [4]interface{} // decoded headers, in order
	Headers_cnt int
	Payload     []byte // remaining non-header bytes

	// Pre-allocated memory to reduce allocation overhead
	data   []byte
	iphdr  *Iphdr
	ip6hdr *Ip6hdr
	tcphdr *Tcphdr
}

func (p *Packet) setHeader(header interface{}) error {

	if p.Headers_cnt >= len(p.Headers) {
		return fmt.Errorf("Too many headers")
	}
	p.Headers[p.Headers_cnt] = header
	p.Headers_cnt++

	return nil
}

// only handle LINKTYPE_ETHER AND LINKTYPE_RAW (IPv4 and IPv6)
func (p *Packet) IsRaw() bool {
	if p.LinkType == LINKTYPE_RAW {
		return true
	}
	return false
}

// Decode decodes the headers of a Packet.
func (p *Packet) Decode() {
	if p.IsRaw() == false {
		p.Type = int(binary.BigEndian.Uint16(p.Data[12:14]))
		p.DestMac = decodemac(p.Data[0:6])
		p.SrcMac = decodemac(p.Data[6:12])
		p.Payload = p.Data[14:]
		switch p.Type {
		case 0x8100:
			//VLAN tag skip 802.1Q tag
			p.Type = int(binary.BigEndian.Uint16(p.Data[16:18]))
			p.Payload = p.Data[18:]
		case 0x88A8:
			//VLAN tag skip 802.1ad double tag
			p.Type = int(binary.BigEndian.Uint16(p.Data[20:22]))
			p.Payload = p.Data[22:]
		}
	} else {
		p.Type = TYPE_IP
		if p.Data[0]&0xf0 == 6 {
			p.Type = TYPE_IP6
		}
		p.Payload = p.Data[0:]
	}

	switch p.Type {
	case TYPE_IP:
		p.decodeIp(0)
	case TYPE_IP6:
		p.decodeIp6(0)
	case TYPE_ARP:
		//p.decodeArp()
	}
}

func (p *Packet) headerString(headers []interface{}) string {
	// If there's just one header, return that.
	if len(headers) == 1 {
		if hdr, ok := headers[0].(fmt.Stringer); ok {
			return hdr.String()
		}
	}
	// If there are two headers (IPv4/IPv6 -> TCP/UDP/IP..)
	if len(headers) == 2 {
		// Commonly the first header is an address.
		if addr, ok := p.Headers[0].(addrHdr); ok {
			if hdr, ok := p.Headers[1].(addrStringer); ok {
				return fmt.Sprintf("%s %s", p.Time, hdr.String(addr))
			}
		}
	}
	// For IP in IP, we do a recursive call.
	if len(headers) >= 2 {
		if addr, ok := headers[0].(addrHdr); ok {
			if _, ok := headers[1].(addrHdr); ok {
				return fmt.Sprintf("%s > %s IP in IP: %v",
					addr.SrcAddr(), addr.DestAddr(), p.headerString(headers[1:]))
			}
		}
	}

	var typeNames []string
	for _, hdr := range headers {
		typeNames = append(typeNames, reflect.TypeOf(hdr).String())
	}

	return fmt.Sprintf("unknown [%s]", strings.Join(typeNames, ","))
}

// String prints a one-line representation of the packet header.
// The output is suitable for use in a tcpdump program.
func (p *Packet) String() string {
	// If there are no headers, print "unsupported protocol".
	if p.Headers_cnt == 0 {
		return fmt.Sprintf("%s unsupported protocol %d", p.Time, int(p.Type))
	}
	return fmt.Sprintf("%s %s", p.Time, p.headerString(p.Headers[0:p.Headers_cnt]))
}

func (p *Packet) decodeArp() {
	pkt := p.Payload
	arp := new(Arphdr)
	arp.Addrtype = binary.BigEndian.Uint16(pkt[0:2])
	arp.Protocol = binary.BigEndian.Uint16(pkt[2:4])
	arp.HwAddressSize = pkt[4]
	arp.ProtAddressSize = pkt[5]
	arp.Operation = binary.BigEndian.Uint16(pkt[6:8])
	if arp.HwAddressSize != 0 && len(pkt) >= int(8+2*arp.HwAddressSize+2*arp.ProtAddressSize) {
		arp.SourceHwAddress = pkt[8 : 8+arp.HwAddressSize]
		arp.SourceProtAddress = pkt[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
		arp.DestHwAddress = pkt[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
		arp.DestProtAddress = pkt[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]

		p.setHeader(arp)

		p.Payload = p.Payload[8+2*arp.HwAddressSize+2*arp.ProtAddressSize:]
	} else {
		dlog.Infof("s: %d L:%d(H:%d P:%d) -> T:%x D:%x S:%x A:%x P:%x %x", p.Seq, len(p.Payload), arp.HwAddressSize, arp.ProtAddressSize, p.Type, p.DestMac, p.SrcMac, arp.Addrtype, arp.Protocol, bytes.Split(p.Data, []byte(",")))
	}
}

func (p *Packet) decodeIp(recur int) {
	if len(p.Payload) < 20 {
		return
	}
	if recur > 3 {
		dlog.Infof("more than %v level of IPnIP encapsulation %+v", recur, p)
		return
	}
	pkt := p.Payload
	if p.iphdr == nil {
		p.iphdr = new(Iphdr)
	}
	ip := p.iphdr

	ip.Version = uint8(pkt[0]) >> 4
	ip.Ihl = uint8(pkt[0]) & 0x0F
	ip.Tos = pkt[1]
	ip.Length = binary.BigEndian.Uint16(pkt[2:4])
	ip.Id = binary.BigEndian.Uint16(pkt[4:6])
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])
	ip.Flags = uint8(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.Ttl = pkt[8]
	ip.Protocol = pkt[9]
	ip.Checksum = binary.BigEndian.Uint16(pkt[10:12])
	ip.SrcIp = pkt[12:16]
	ip.DestIp = pkt[16:20]
	pEnd := int(ip.Length)
	if pEnd > len(pkt) {
		pEnd = len(pkt)
	}
	pIhl := int(ip.Ihl) * 4
	if pIhl > pEnd {
		pIhl = pEnd
	}
	p.Payload = pkt[pIhl:pEnd]
	p.setHeader(ip)
	switch ip.Protocol {
	case IP_TCP:
		p.decodeTcp()
	case IP_UDP:
		p.decodeUdp()
	case IP_ICMP:
		p.decodeIcmp()
	case IP_INIP:
		p.decodeIp(recur + 1)
	}
}

func (p *Packet) decodeTcp() {
	pLenPayload := len(p.Payload)
	if pLenPayload < 20 {
		return
	}
	pkt := p.Payload
	if p.tcphdr == nil {
		p.tcphdr = new(Tcphdr)
	}
	tcp := p.tcphdr

	tcp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	tcp.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	tcp.Seq = binary.BigEndian.Uint32(pkt[4:8])
	tcp.Ack = binary.BigEndian.Uint32(pkt[8:12])
	tcp.DataOffset = (pkt[12] & 0xF0) >> 4
	tcp.Flags = binary.BigEndian.Uint16(pkt[12:14]) & 0x1FF
	tcp.Window = binary.BigEndian.Uint16(pkt[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(pkt[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(pkt[18:20])
	pDataOffset := int(tcp.DataOffset * 4)
	if pDataOffset > pLenPayload {
		pDataOffset = pLenPayload
	}
	p.Payload = pkt[pDataOffset:]
	p.setHeader(tcp)
}

func (p *Packet) decodeUdp() {
	if len(p.Payload) < 8 {
		return
	}
	pkt := p.Payload
	udp := new(Udphdr)
	udp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	udp.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	udp.Length = binary.BigEndian.Uint16(pkt[4:6])
	udp.Checksum = binary.BigEndian.Uint16(pkt[6:8])
	p.setHeader(udp)

	p.Payload = pkt[8:]
}

func (p *Packet) decodeIcmp() *Icmphdr {
	if len(p.Payload) < 8 {
		return nil
	}
	pkt := p.Payload
	icmp := new(Icmphdr)
	icmp.Type = pkt[0]
	icmp.Code = pkt[1]
	icmp.Checksum = binary.BigEndian.Uint16(pkt[2:4])
	icmp.Id = binary.BigEndian.Uint16(pkt[4:6])
	icmp.Seq = binary.BigEndian.Uint16(pkt[6:8])
	p.Payload = pkt[8:]
	p.setHeader(icmp)

	return icmp
}

func (p *Packet) decodeIp6(recur int) {
	if len(p.Payload) < 40 {
		return
	}
	if recur > 3 {
		dlog.Infof("more than %v level of IP6nIP encapsulation %+v", recur, p)
		return
	}
	pkt := p.Payload
	if p.ip6hdr == nil {
		p.ip6hdr = new(Ip6hdr)
	}
	ip6 := p.ip6hdr

	ip6.Version = uint8(pkt[0]) >> 4
	ip6.TrafficClass = uint8((binary.BigEndian.Uint16(pkt[0:2]) >> 4) & 0x00FF)
	ip6.FlowLabel = binary.BigEndian.Uint32(pkt[0:4]) & 0x000FFFFF
	ip6.Length = binary.BigEndian.Uint16(pkt[4:6])
	ip6.NextHeader = pkt[6]
	ip6.HopLimit = pkt[7]
	ip6.SrcIp = pkt[8:24]
	ip6.DestIp = pkt[24:40]
	p.Payload = pkt[40:]
	p.setHeader(ip6)

	switch ip6.NextHeader {
	case IP_TCP:
		p.decodeTcp()
	case IP_UDP:
		p.decodeUdp()
	case IP_ICMP:
		p.decodeIcmp()
	case IP_INIP:
		p.decodeIp6(recur + 1)
	}
}

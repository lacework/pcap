package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/lacework/pcap"
)

func min(x uint32, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

func main() {
	var device *string = flag.String("d", "", "device")
	var file *string = flag.String("r", "", "file")
	var expr *string = flag.String("e", "", "filter expression")

	flag.Parse()

	var h *pcap.Pcap

	devs, err := pcap.FindAllDevs()
	if len(devs) == 0 {
		fmt.Printf("Warning: no devices found : %s\n", err)
	} else {
		for idx := range devs {
			fmt.Printf("Monitoring Interface %v (%v) flags %v\n", devs[idx].Name, devs[idx].Description, devs[idx].Flags)
			for _, addr := range devs[idx].Addresses {
				if addr.IP.To4() != nil {
					fmt.Printf("IPV4 Interface addr: %+v\n", addr)
				} else if addr.IP.To16() != nil {
					fmt.Printf("IPV6 Interface addr: %+v\n", addr)
				} else {
					fmt.Printf("Unknown IP addr %v\n", addr)
					break
				}
			}
		}
	}

	if *device != "" {
		h, err = pcap.OpenLive(*device, 65535, true, 0)
		if h == nil {
			fmt.Printf("OpenLive(%s) failed: %s\n", *device, err)
			return
		}
		fmt.Printf("pcap device opened %s, properties %+v\n", *device, h)
	} else if *file != "" {
		h, err = pcap.OpenOffline(*file)
		if h == nil {
			fmt.Printf("Openoffline(%s) failed: %s\n", *file, err)
			return
		}
	} else {
		fmt.Printf("usage: pcaptest [-d <device> | -r <file>]\n")
		return
	}

	fmt.Printf("pcap version: %s\n", pcap.Version())

	if *expr != "" {
		fmt.Printf("Setting filter: %s\n", *expr)
		err := h.SetFilter(*expr)
		if err != nil {
			fmt.Printf("Warning: setting filter failed: %s\n", err)
		}
	}

	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		fmt.Printf("time: %d.%06d (%s) caplen: %d len: %d\nData:",
			int64(pkt.Time.Second()), int64(pkt.Time.Nanosecond()),
			time.Unix(int64(pkt.Time.Second()), 0).String(), int64(pkt.Caplen), int64(pkt.Len))
		for i := uint32(0); i < pkt.Caplen; i++ {
			if i%32 == 0 {
				fmt.Printf("\n")
			}
			if 32 <= pkt.Data[i] && pkt.Data[i] <= 126 {
				fmt.Printf("%x-%c ", pkt.Data[i], pkt.Data[i])
			} else {
				fmt.Printf("%x-. ", pkt.Data[i])
			}
		}
		fmt.Printf("\n\n")
	}

}

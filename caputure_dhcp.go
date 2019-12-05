// +build ignore

package main

import (
	"fmt"
	"os"
	"time"
	"log"
	"path/filepath"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

var (
	device string
	snapshotLen int32 = 1024
	promiscuous bool = false
	err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
)

func main(){
	if len(os.Args) != 2{
		fmt.Printf("Usage: %s <interface>\n", filepath.Base(os.Args[0]))
		return
	}
	
	device = os.Args[1]
	fmt.Printf("interface: %s\n", device)
	
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
		printDHCP(packet)
		// fmt.Println(packet)
    }
}

func printDHCP(packet gopacket.Packet){
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
		fmt.Println(time.Now())
		dhcpPacket, _ := dhcpLayer.(*layers.DHCPv4)
		fmt.Println("Operation: ", dhcpPacket.Operation)
		fmt.Println("Options: ", dhcpPacket.Options)
		fmt.Println("-------------------------------------------------")
	}
}
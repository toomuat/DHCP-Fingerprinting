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
	
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
		// fmt.Println(packet)
		// printPacketInfo(packet)
		printAllLayers(packet)
    }
}

func printPacketInfo(packet gopacket.Packet){
	fmt.Println(time.Now())
	
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil{
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Src MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Dst MAC: ", ethernetPacket.DstMAC)
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        ipPacket, _ := ipLayer.(*layers.IPv4)
        fmt.Println("Src IP: ", ipPacket.SrcIP)
        fmt.Println("Dst IP: ", ipPacket.DstIP)
    }

    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
		tcpPacket, _ := tcpLayer.(*layers.TCP)
		fmt.Println("Src Port: ", tcpPacket.SrcPort)
        fmt.Println("Dst Port: ", tcpPacket.DstPort)
    }

    // Iterate over all layers, printing out each layer type
    // fmt.Println("All packet layers:")
    // for _, layer := range packet.Layers() {
    //     fmt.Println("- ", layer.LayerType())
    // }

    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        fmt.Println("Application layer/Payload found.")
        fmt.Printf("%s\n", applicationLayer.Payload())

        // Search for a string inside the payload
        // if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
        //     fmt.Println("HTTP found!")
        // }
    }
	fmt.Println("-----------------------------")
}

func printAllLayers(packet gopacket.Packet){
	fmt.Println(time.Now())
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}
	fmt.Println("-----------------------------")
}
package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	// "strings"
	"io/ioutil"
)

var all = flag.Bool("a", false, "-a Print all Info")
var path = flag.String("p", "", "-p assign the pcap path")
var folder = flag.String("P", "", "-P assign the pcap folder path")
var help = flag.Bool("h", false, "-h Print the help usage")

func main() {
	flag.Parse()
	if *help {
		// fmt.Println(" ")
		fmt.Printf("-a Print all Info\n-p assign the pcap path\n-P assign the pcap folder path\n")
		os.Exit(1)
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in Parse ", r)
		}
	}()
	fmt.Println("Parsing...")
	if *path != "" {
		Parse_pcap(*path)
	} else {
		if *folder != "" {
			Foler_Parse(*folder)
		}
	}
}

func Foler_Parse(folder string) {
	files, err := ioutil.ReadDir(folder)
	if err != nil {
		log.Fatal(err)
	} else {
		for _, file := range files {
			if file.IsDir() {
				//linux 下运行
				Foler_Parse(folder + "/" + file.Name())
			} else {
				fmt.Println("Parsing ", folder+"/"+file.Name())
				Parse_pcap(folder + "/" + file.Name())
			}
		}
	}
}

func Parse_pcap(path string) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// fmt.Println(packet)
			Print_PacketInfio(packet)
		}
	}
}

func Print_PacketInfio(pcaket gopacket.Packet) {

	if *all {
		fmt.Println("All packet layers:")
		for _, layer := range pcaket.Layers() {
			fmt.Println("- ", layer.LayerType())
		}
		ethernetLayer := pcaket.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			fmt.Println("Ethernet layer detected.")
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			fmt.Printf("Source MAC: %s\tDestination MAC: %s\tEthernet type: %s\n", ethernetPacket.SrcMAC,
				ethernetPacket.DstMAC, ethernetPacket.EthernetType)
			fmt.Println()
		}

		ipLayer := pcaket.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			fmt.Println("IPv4 layer detected.")
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
			fmt.Println("Protocol: ", ip.Protocol)
			fmt.Println()
		}

		tcpLayer := pcaket.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			fmt.Println("TCP layer detected.")
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			fmt.Println("Sequence number: ", tcp.Seq)
			fmt.Println()
		}
	}

	applicationLayer := pcaket.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())
		// if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		// 	fmt.Println("HTTP found")
		// }
	}

	if err := pcaket.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some port of the packet:", err)
	}
}

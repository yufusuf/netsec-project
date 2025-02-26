package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nats-io/nats.go"
)

// Function to process the ethernet packet
func processEthernetPacket(nc *nats.Conn, iface string, data []byte) {
	// Add your ethernet packet processing logic here
	fmt.Printf("Processing ethernet packet: %s\n", iface)
	
	// Use gopacket to dissect the packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		fmt.Println("Error decoding some part of the packet:", packet.ErrorLayer().Error())
		return
	}
	// Iterate over all layers, printing out each layer type and its contents
	for _, layer := range packet.Layers() {
		fmt.Println("Layer type:", layer.LayerType())
		fmt.Println(gopacket.LayerDump(layer))
	}
	// Publish the processed packet to the appropriate subject
	var subject string
	if iface == "inpktsec" {
		subject = "outpktinsec"
	} else {
		subject = "outpktsec"
	}
	err := nc.Publish(subject, data)
	if err != nil {
		fmt.Println("Error publishing message:", err)
	}
}

func main() {
	fmt.Println("Hello, World!")
	url := os.Getenv("NATS_SURVEYOR_SERVERS")
	if url == "" {
		url = nats.DefaultURL
	}
	fmt.Println("NATS_SURVEYOR_SERVERS: ", url)


		// Connect to a server
	nc, _ := nats.Connect(url)
	defer nc.Drain()
	// Simple Publisher
	//nc.Publish("foo", []byte("Hello World"))

	// Simple Subscriber
	nc.Subscribe("inpktsec", func(m *nats.Msg) {
		//fmt.Printf("Received a message: %s\n", string(m.Data))
		// Process the incoming ethernet packet here
		processEthernetPacket(nc, m.Subject, m.Data)
	})

	// Simple Subscriber
	nc.Subscribe("inpktinsec", func( m *nats.Msg) {
		//fmt.Printf("Received a message: %s\n", string(m.Data))
		// Process the incoming ethernet packet here
		processEthernetPacket(nc, m.Subject, m.Data)
	})

	// Keep the connection alive
	select {}

	// Drain connection (Preferred for responders)
	// Close() not needed if this is called.


	// Close connection
	nc.Close()
}	


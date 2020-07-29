package main

import (
	"fmt"
	"math"
	"os"
	"net"
	"crypto/tls"
	"flag"
	"time"
	
	"github.com/scionproto/scion/go/flowtele/dbus"
	"github.com/lucas-clemente/quic-go"
)

var (
	remoteAddr = flag.String("ip", "127.0.0.1", "IP address to connect to")
	remotePort = flag.Int("port", 5500, "Port number to connect to")
	nConnections = flag.Int("num", 12, "Number of QUIC connections using increasing port numbers")
)

func main() {
	flag.Parse()
	// first run
	// python3.6 athena_m10.py 12
	// clear; go run go/flowtele/quic_listener.go --num 2
	// clear; go run go/flowtele/socket.go --num 2
	
	// var fdbus fshaperDbus
	fdbus := flowteledbus.NewFshaperDbus()
	// dbus setup
	fdbus.OpenSessionBus()
	defer fdbus.Close()

	// start QUIC instances
	// TODO(cyrill) read flow specs from config/user_X.json
	remoteIp := net.ParseIP(*remoteAddr)
	remoteAddresses := []net.UDPAddr{}
	startPort := *remotePort
	fmt.Println(*nConnections)
	for ui := 0; ui < *nConnections; ui++ {
		remoteAddresses = append(remoteAddresses, net.UDPAddr{IP: remoteIp, Port: startPort+ui})
	}

    errs := make(chan error)
	for di, addr := range remoteAddresses {
		go func(remoteAddress net.UDPAddr, flowId int32) {
			err := startQuicSender(addr, flowId)
			if err != nil {
				errs <- err
			}
		}(addr, int32(di))
	}

	// register method and listeners
	fdbus.Register()

	// listen for feedback from QUIC instances and forward to athena
	go func() {
		for v := range fdbus.SignalListener {
			if fdbus.Conn.Names()[0] == v.Sender {
				fdbus.Log("ignore signal %s generated by socket", v.Name)
			} else {
				fdbus.Log("forwarding signal...")
				fdbus.Send(flowteledbus.CreateFshaperDbusSignal(v))
			}
		}
	}()

	select {
	case err := <-errs:
		fmt.Printf("Error encountered (%s), stopping all QUIC senders and SCION socket\n", err)
		os.Exit(1)
	}
}

func startQuicSender(remoteAddress net.UDPAddr, flowId int32) error {
	// start dbus
	qdbus := flowteledbus.NewQuicDbus(flowId)
	qdbus.OpenSessionBus()
	defer qdbus.Close()
	qdbus.Register()

	// start QUIC session
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		fmt.Printf("Error starting UDP listener: %s\n", err)
		return err
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	newSrttMeasurement := func(t time.Time, srtt time.Duration) {
		qdbus.Log("New srtt measurement received (%v), %v", t, srtt)
		if srtt > math.MaxUint32 {
			panic("srtt does not fit in uint32")
		}
		qdbus.Send(flowteledbus.CreateQuicDbusSignalRtt(flowId, t, uint32(srtt.Microseconds())))
	}
	packetsLost := func(t time.Time, newSlowStartThreshold uint64) {
		// qdbus.Log("packets lost (%v), new ssthresh=%d", t, newSlowStartThreshold)
		if newSlowStartThreshold > math.MaxUint32 {
			panic("newSlotStartThreshold does not fit in uint32")
		}
		qdbus.Send(flowteledbus.CreateQuicDbusSignalLost(flowId, t, uint32(newSlowStartThreshold)))
	}
	packetsAcked := func(t time.Time, congestionWindow uint64, packetsInFlight uint64) {
		qdbus.Log("packets acked (%v), cwnd=%d, inflight=%d", t, congestionWindow, packetsInFlight)
		if congestionWindow > math.MaxUint32 {
			panic("congestionWindow does not fit in uint32")
		}
		if packetsInFlight > math.MaxInt32 {
			panic("packetsInFlight does not fit in int32")
		}
		qdbus.Send(flowteledbus.CreateQuicDbusSignalCwnd(flowId, t, uint32(congestionWindow), int32(packetsInFlight)))
	}

	// make QUIC idle timout long to allow a delay between starting the listeners and the senders
	flowteleSignalInterface := quic.CreateFlowteleSignalInterface(newSrttMeasurement, packetsLost, packetsAcked)
	quicConfig := &quic.Config{IdleTimeout: time.Hour,
		FlowteleSignalInterface: flowteleSignalInterface}
	session, err := quic.Dial(conn, &remoteAddress, "host:0", tlsConfig, quicConfig)
	if err != nil {
		fmt.Printf("Error starting QUIC connection to [%s]: %s\n", remoteAddress.String(), err)
		return err
	}
	rateInBitsPerSecond := uint64(3000000)
	qdbus.Log("set fixed rate %f...", float64(rateInBitsPerSecond)/1000000)
	session.SetFixedRate(rateInBitsPerSecond)
	qdbus.Log("session established. Opening stream...")
	stream, err := session.OpenStreamSync()
	if err != nil {
		fmt.Printf("Error opening QUIC stream to [%s]: %s\n", remoteAddress.String(), err)
		return err
	}
	qdbus.Log("stream opened %d", stream.StreamID())
	message := make([]byte, 1000000)
	for i := range message {
		message[i] = 42
	}
	for {
		// fmt.Printf("Sending message of length %d\n", len(message))
		// finished := make(chan error)
		// go func(m []byte) {
		// 	_, err = stream.Write(m)
		// 	finished <- err
		// }(message)
		// select {
		// case err := <-finished:
		// 	fmt.Printf("Finished writing (%s)\n", err)
		// }
		_, err = stream.Write(message)
		if err != nil {
			fmt.Printf("Error writing message to [%s]: %s\n", remoteAddress.String(), err)
			return err
		}
	}
	return nil
}

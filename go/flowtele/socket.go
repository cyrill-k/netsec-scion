package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"time"
	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/flowtele/dbus"
)

var (
	remoteAddr     = flag.String("ip", "127.0.0.1", "IP address to connect to")
	remotePort     = flag.Int("port", 5500, "Port number to connect to")
	quicSenderOnly = flag.Bool("quic-sender-only", false, "Only start the quic sender")
	fshaperOnly    = flag.Bool("fshaper-only", false, "Only start the fshaper")
	quicDbusIndex  = flag.Int("quic-dbus-index", 0, "index of the quic sender dbus name")
	nConnections   = flag.Int("num", 2, "Number of QUIC connections (only used in combination with --fshaper-only to restrict the number of quic flows to less than 10)")
	noApplyControl = flag.Bool("no-apply-control", false, "Do not forward apply-control calls from fshaper to this QUIC connection (useful to ensure the calibrator flow is not influenced by vAlloc)")
)

func main() {
	flag.Parse()
	// first run
	// python3.6 athena_m2.py 2
	// clear; go run go/flowtele/quic_listener.go --num 3
	// clear; go run go/flowtele/socket.go --fshaper-only
	// clear; go run go/flowtele/socket.go --quic-sender-only --ip 164.90.176.95 --port 5500 --quic-dbus-index 0
	// clear; go run go/flowtele/socket.go --quic-sender-only --ip 164.90.176.95 --port 5501 --quic-dbus-index 1
	// clear; go run go/flowtele/socket.go --quic-sender-only --ip 164.90.176.95 --port 5502 --quic-dbus-index 2
	// can add --no-apply-control to calibrator flow

	if *quicSenderOnly {
		// start QUIC instances
		// TODO(cyrill) read flow specs from config/user_X.json
		remoteIp := net.ParseIP(*remoteAddr)
		remoteAddress := net.UDPAddr{IP: remoteIp, Port: *remotePort}
		err := startQuicSender(remoteAddress, int32(*quicDbusIndex), !*noApplyControl)
		if err != nil {
			fmt.Printf("Error encountered (%s), stopping all QUIC senders and SCION socket\n", err)
			os.Exit(1)
		}
	} else if *fshaperOnly {
		fdbus := flowteledbus.NewFshaperDbus(*nConnections)

		// fdbus.SetMinIntervalForAllSignals(5 * time.Millisecond)

		// dbus setup
		fdbus.OpenSessionBus()
		defer fdbus.Close()

		// register method and listeners
		fdbus.Register()

		// listen for feedback from QUIC instances and forward to athena
		go func() {
			for v := range fdbus.SignalListener {
				if fdbus.Conn.Names()[0] == v.Sender {
					// fdbus.Log("ignore signal %s generated by socket", v.Name)
				} else {
					// fdbus.Log("forwarding signal...")
					signal := flowteledbus.CreateFshaperDbusSignal(v)
					if fdbus.ShouldSendSignal(signal) {
						fdbus.Send(signal)
					}
				}
			}
		}()

		select {}
	} else {
		fmt.Fprintf(os.Stderr, "Must provide either --quic-sender-only or --fshaper-only:\n")

		flag.PrintDefaults()
	}
}

func startQuicSender(remoteAddress net.UDPAddr, flowId int32, applyControl bool) error {
	// start dbus
	qdbus := flowteledbus.NewQuicDbus(flowId, applyControl)
	qdbus.SetMinIntervalForAllSignals(5 * time.Millisecond)
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
		if srtt > math.MaxUint32 {
			panic("srtt does not fit in uint32")
		}
		signal := flowteledbus.CreateQuicDbusSignalRtt(flowId, t, uint32(srtt.Microseconds()))
		if qdbus.ShouldSendSignal(signal) {
			// qdbus.LogRtt(t, srtt)
			qdbus.Send(signal)
		}
	}
	packetsLost := func(t time.Time, newSlowStartThreshold uint64) {
		if newSlowStartThreshold > math.MaxUint32 {
			panic("newSlotStartThreshold does not fit in uint32")
		}
		signal := flowteledbus.CreateQuicDbusSignalLost(flowId, t, uint32(newSlowStartThreshold))
		if qdbus.ShouldSendSignal(signal) {
			qdbus.LogLost(t, newSlowStartThreshold)
			qdbus.Send(signal)
		}
	}
	packetsAcked := func(t time.Time, congestionWindow uint64, packetsInFlight uint64, ackedBytes uint64) {
		if congestionWindow > math.MaxUint32 {
			panic("congestionWindow does not fit in uint32")
		}
		if packetsInFlight > math.MaxInt32 {
			panic("packetsInFlight does not fit in int32")
		}
		if ackedBytes > math.MaxUint32 {
			panic("ackedBytes does not fit in uint32")
		}
		signal := flowteledbus.CreateQuicDbusSignalCwnd(flowId, t, uint32(congestionWindow), int32(packetsInFlight), uint32(ackedBytes))
		if qdbus.ShouldSendSignal(signal) {
			qdbus.LogAcked(t, congestionWindow, packetsInFlight, ackedBytes)
			qdbus.Send(signal)
		}
	}

	// setup quic session
	flowteleSignalInterface := quic.CreateFlowteleSignalInterface(newSrttMeasurement, packetsLost, packetsAcked)
	// make QUIC idle timout long to allow a delay between starting the listeners and the senders
	quicConfig := &quic.Config{IdleTimeout: time.Hour,
		FlowteleSignalInterface: flowteleSignalInterface}
	session, err := quic.Dial(conn, &remoteAddress, "host:0", tlsConfig, quicConfig)
	if err != nil {
		fmt.Printf("Error starting QUIC connection to [%s]: %s\n", remoteAddress.String(), err)
		return err
	}
	qdbus.Session = session

	// open stream
	// rateInBitsPerSecond := uint64(20 * 1000 * 1000)
	// session.SetFixedRate(rateInBitsPerSecond)
	// qdbus.Log("set fixed rate %f...", float64(rateInBitsPerSecond)/1000000)
	qdbus.Log("session established. Opening stream...")
	stream, err := session.OpenStreamSync()
	if err != nil {
		fmt.Printf("Error opening QUIC stream to [%s]: %s\n", remoteAddress.String(), err)
		return err
	}
	qdbus.Log("stream opened %d", stream.StreamID())

	// continuously send 10MB messages to quic listener
	message := make([]byte, 10000000)
	for i := range message {
		message[i] = 42
	}
	for {
		_, err = stream.Write(message)
		if err != nil {
			fmt.Printf("Error writing message to [%s]: %s\n", remoteAddress.String(), err)
			return err
		}
	}
	return nil
}

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/flowtele/dbus"
	"github.com/scionproto/scion/go/lib/addr"
	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

var (
	localIAFlag, remoteIAFlag addr.IA
	scionPath                 scionPathDescription

	remoteIpFlag       = flag.String("ip", "127.0.0.1", "IP address to connect to")
	remotePortFlag     = flag.Int("port", 5500, "Port number to connect to")
	useRemotePortRange = flag.Bool("port-range", false, "Use increasing (remote) port numbers for additional QUIC senders")
	localIpFlag        = flag.String("local-ip", "", "IP address to listen on (required for SCION)")
	localPortFlag      = flag.Int("local-port", 0, "Port number to listen on (required for SCION)")
	useLocalPortRange  = flag.Bool("local-port-range", true, "Use increasing local port numbers for additional QUIC senders")
	quicSenderOnly     = flag.Bool("quic-sender-only", false, "Only start the quic sender")
	fshaperOnly        = flag.Bool("fshaper-only", false, "Only start the fshaper")
	quicDbusIndex      = flag.Int("quic-dbus-index", 0, "index of the quic sender dbus name")
	nConnections       = flag.Int("num", 2, "Number of QUIC connections")
	noApplyControl     = flag.Bool("no-apply-control", false, "Do not forward apply-control calls from fshaper to this QUIC connection (useful to ensure the calibrator flow is not influenced by vAlloc)")
	mode               = flag.String("mode", "fetch", "the sockets mode of operation: fetch, quic, fshaper")
	maxData            = flag.Int("max-data", 0, "the maximum amount of data that should be transmitted on each QUIC flow (0 means no limit)")

	useScion        = flag.Bool("scion", false, "Open scion quic sockets")
	dispatcherFlag  = flag.String("dispatcher", "", "Path to dispatcher socket")
	sciondAddrFlag  = flag.String("sciond", sd.DefaultSCIONDAddress, "SCIOND address")
	scionPathsFile  = flag.String("paths-file", "", "File containing a list of SCION paths to the destination")
	scionPathsIndex = flag.Int("paths-index", 0, "Index of the path to use in the --paths-file")
)

func init() {
	flag.Var(&localIAFlag, "local-ia", "ISD-AS address to listen on")
	flag.Var(&remoteIAFlag, "remote-ia", "ISD-AS address to connect to")
	flag.Var(&scionPath, "path", "SCION path to use")
}

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

	// ./scion.sh topology -c topology/Tiny.topo
	// ./scion.sh start
	// bazel build //... && bazel-bin/go/flowtele/listener/linux_amd64_stripped/flowtele_listener --scion --sciond 127.0.0.12:30255 --local-ia 1-ff00:0:110 --num 2
	// bazel build //... && bazel-bin/go/flowtele/linux_amd64_stripped/flowtele_socket --quic-sender-only --scion --sciond 127.0.0.19:30255 --local-ip 127.0.0.1 --local-port 6000 --ip 127.0.0.1 --port 5500 --local-ia 1-ff00:0:111 --remote-ia 1-ff00:0:110 --path 1-ff00:0:111,1-ff00:0:110
	// bazel build //... && bazel-bin/go/flowtele/linux_amd64_stripped/flowtele_socket --quic-sender-only --scion --sciond 127.0.0.19:30255 --local-ip 127.0.0.1 --local-port 6001 --ip 127.0.0.1 --port 5501 --local-ia 1-ff00:0:111 --remote-ia 1-ff00:0:110 --path 1-ff00:0:111,1-ff00:0:110
	errChannel := make(chan error)
	closeChannel := make(chan struct{})

	if *quicSenderOnly || *mode == "quic" {
		invokeQuicSenders(closeChannel, errChannel)
	} else if *fshaperOnly || *mode == "fshaper" {
		go invokeFshaper(closeChannel, errChannel)
	} else if *mode == "fetch" {
		go invokePathFetching(closeChannel, errChannel)
	} else {
		flag.PrintDefaults()
		errChannel <- fmt.Errorf("Must provide either --quic-sender-only or --fshaper-only")
	}

	select {
	case err := <-errChannel:
		fmt.Fprintf(os.Stderr, "Error encountered (%s), exiting socket\n", err)
		os.Exit(1)
	case <-closeChannel:
		fmt.Println("Exiting without errors")
	}
}

func invokePathFetching(closeChannel chan struct{}, errChannel chan error) {
	sciondAddr := *sciondAddrFlag
	localIA := localIAFlag
	remoteIA := remoteIAFlag
	paths, err := fetchPaths(sciondAddr, localIA, remoteIA)
	if err != nil {
		errChannel <- err
	} else {
		for _, path := range paths {
			fmt.Println(NewScionPathDescription(path).String())
		}
		close(closeChannel)
	}
}

func invokeQuicSenders(closeChannel chan struct{}, errChannel chan error) {
	// start QUIC instances
	// TODO(cyrill) read flow specs from config/user_X.json
	fmt.Printf("Starting %d QUIC senders:\n", *nConnections)
	remoteIp := net.ParseIP(*remoteIpFlag)
	localIp := net.ParseIP(*localIpFlag)
	var wg sync.WaitGroup
	for i := 0; i < *nConnections; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			localPort := *localPortFlag
			remotePort := *remotePortFlag

			if *useLocalPortRange {
				localPort += index
			}
			if *useRemotePortRange {
				remotePort += index
			}

			localAddr := net.UDPAddr{IP: localIp, Port: localPort}
			remoteAddr := net.UDPAddr{IP: remoteIp, Port: remotePort}
			err := startQuicSender(&localAddr, &remoteAddr, int32(*quicDbusIndex+index), !*noApplyControl, errChannel)
			if err != nil {
				errChannel <- err
			}
		}(i)
	}
	go func() {
		wg.Wait()
		close(closeChannel)
	}()
}

func invokeFshaper(closeChannel chan struct{}, errChannel chan error) {
	fdbus := flowteledbus.NewFshaperDbus(*nConnections)

	// if a min interval for the fshaper is specified, make sure to accumulate acked bytes that would otherwise not be registered by athena
	// fdbus.SetMinIntervalForAllSignals(5 * time.Millisecond)

	// dbus setup
	if err := fdbus.OpenSessionBus(); err != nil {
		errChannel <- err
		return
	}

	// register method and listeners
	if err := fdbus.Register(); err != nil {
		errChannel <- err
		return
	}

	// listen for feedback from QUIC instances and forward to athena
	go func() {
		for v := range fdbus.SignalListener {
			if fdbus.Conn.Names()[0] == v.Sender {
				// fdbus.Log("ignore signal %s generated by socket", v.Name)
			} else {
				// fdbus.Log("forwarding signal...")
				signal := flowteledbus.CreateFshaperDbusSignal(v)
				if fdbus.ShouldSendSignal(signal) {
					if err := fdbus.Send(signal); err != nil {
						errChannel <- err
						return
					}
				}
			}
		}
	}()

	// don't close the closeChannel to keep running forever
	// fdbus.Close()
	// close(closeChannel)
}

func fetchPaths(sciondAddr string, localIA addr.IA, remoteIA addr.IA) ([]snet.Path, error) {
	sdConn, err := sd.NewService(sciondAddr).Connect(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize SCION network: %s", err)
	}
	paths, err := sdConn.Paths(context.Background(), remoteIA, localIA, sd.PathReqFlags{})
	if err != nil {
		return nil, fmt.Errorf("Failed to lookup paths: %s", err)
	}
	return paths, nil
}

func fetchPath(pathDescription *scionPathDescription, sciondAddr string, localIA addr.IA, remoteIA addr.IA) (snet.Path, error) {
	paths, err := fetchPaths(sciondAddr, localIA, remoteIA)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		if pathDescription.IsEqual(NewScionPathDescription(path)) {
			return path, nil
		}
	}
	return nil, fmt.Errorf("No matching path (%v) was found in %v", pathDescription, paths)
}

func establishQuicSession(localAddr *net.UDPAddr, remoteAddr *net.UDPAddr, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.Session, error) {
	if *useScion {
		dispatcher := *dispatcherFlag
		sciondAddr := *sciondAddrFlag
		var pathDescription *scionPathDescription
		if !scionPath.IsEmpty() {
			pathDescription = &scionPath
		} else if *scionPathsFile != "" {
			pathDescriptions, err := readPaths(*scionPathsFile)
			if err != nil {
				return nil, fmt.Errorf("Couldn't read paths from file %s: %s", *scionPathsFile, err)
			}
			if *scionPathsIndex >= len(pathDescriptions) {
				return nil, fmt.Errorf("SCION path index out of range %d >= %d", *scionPathsIndex, len(pathDescriptions))
			}
			pathDescription = pathDescriptions[*scionPathsIndex]
		} else {
			return nil, fmt.Errorf("Must specify either --path or --paths-file and --paths-index")
		}
		localIA := localIAFlag
		remoteIA := remoteIAFlag

		// fetch path fitting to description
		var remoteScionAddr snet.UDPAddr
		remoteScionAddr.Host = remoteAddr
		remoteScionAddr.IA = remoteIA
		if !remoteIA.Equal(localIA) {
			path, err := fetchPath(pathDescription, sciondAddr, localIA, remoteIA)
			if err != nil {
				return nil, err
			}
			remoteScionAddr.Path = path.Path()
			remoteScionAddr.NextHop = path.OverlayNextHop()
		}

		// setup SCION connection
		ds := reliable.NewDispatcher(dispatcher)
		sciondConn, err := sd.NewService(sciondAddr).Connect(context.Background())
		if err != nil {
			return nil, fmt.Errorf("Unable to initialize SCION network: %s, err")
		}
		network := snet.NewNetworkWithPR(localIA, ds, sd.Querier{
			Connector: sciondConn,
			IA:        localIA,
		}, sd.RevHandler{Connector: sciondConn})

		// start QUIC session
		return squic.Dial(network, localAddr, &remoteScionAddr, addr.SvcNone, quicConfig)
	} else {
		// open UDP connection
		// localAddr := net.UDPAddr{IP: net.IPv4zero, Port: 0}
		conn, err := net.ListenUDP("udp", localAddr)
		if err != nil {
			fmt.Printf("Error starting UDP listener: %s\n", err)
			return nil, err
		}

		// start QUIC session
		return quic.Dial(conn, remoteAddr, "host:0", tlsConfig, quicConfig)
	}
}

func startQuicSender(localAddr *net.UDPAddr, remoteAddr *net.UDPAddr, flowId int32, applyControl bool, errChannel chan error) error {
	// start dbus
	qdbus := flowteledbus.NewQuicDbus(flowId, applyControl)
	qdbus.SetMinIntervalForAllSignals(5 * time.Millisecond)
	if err := qdbus.OpenSessionBus(); err != nil {
		return err
	}
	defer qdbus.Close()

	if err := qdbus.Register(); err != nil {
		return err
	}

	// signal forwarding functions
	newSrttMeasurement := func(t time.Time, srtt time.Duration) {
		if qdbus.Conn == nil {
			// ignore signals if the session bus is not connected
			return
		}

		if srtt > math.MaxUint32 {
			panic("srtt does not fit in uint32")
		}
		signal := flowteledbus.CreateQuicDbusSignalRtt(flowId, t, uint32(srtt.Microseconds()))
		if qdbus.ShouldSendSignal(signal) {
			if err := qdbus.Send(signal); err != nil {
				fmt.Printf("srtt -> %d\n", qdbus.FlowId)
				errChannel <- err
			}
		}
	}
	packetsLost := func(t time.Time, newSlowStartThreshold uint64) {
		if qdbus.Conn == nil {
			// ignore signals if the session bus is not connected
			return
		}

		if newSlowStartThreshold > math.MaxUint32 {
			panic("newSlotStartThreshold does not fit in uint32")
		}
		signal := flowteledbus.CreateQuicDbusSignalLost(flowId, t, uint32(newSlowStartThreshold))
		if qdbus.ShouldSendSignal(signal) {
			if err := qdbus.Send(signal); err != nil {
				fmt.Printf("lost -> %d\n", qdbus.FlowId)
				errChannel <- err
			}
		}
	}
	packetsAcked := func(t time.Time, congestionWindow uint64, packetsInFlight uint64, ackedBytes uint64) {
		if qdbus.Conn == nil {
			// ignore signals if the session bus is not connected
			return
		}

		if congestionWindow > math.MaxUint32 {
			panic("congestionWindow does not fit in uint32")
		}
		if packetsInFlight > math.MaxInt32 {
			panic("packetsInFlight does not fit in int32")
		}
		if ackedBytes > math.MaxUint32 {
			panic("ackedBytes does not fit in uint32")
		}
		ackedBytesSum := qdbus.Acked(uint32(ackedBytes))
		signal := flowteledbus.CreateQuicDbusSignalCwnd(flowId, t, uint32(congestionWindow), int32(packetsInFlight), ackedBytesSum)
		if qdbus.ShouldSendSignal(signal) {
			if err := qdbus.Send(signal); err != nil {
				fmt.Printf("ack -> %d\n", qdbus.FlowId)
				errChannel <- err
			}
			qdbus.ResetAcked()
		}
	}

	flowteleSignalInterface := quic.CreateFlowteleSignalInterface(newSrttMeasurement, packetsLost, packetsAcked)
	// make QUIC idle timout long to allow a delay between starting the listeners and the senders
	quicConfig := &quic.Config{MaxIdleTimeout: time.Hour,
		FlowteleSignalInterface: flowteleSignalInterface}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	// setup quic session
	session, err := establishQuicSession(localAddr, remoteAddr, tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("Error starting QUIC connection to [%s]: %s", remoteAddr.String(), err)
	}
	defer func() {
		fmt.Printf("closing session %d\n", flowId)
		// session.Close()
		qdbus.Session = nil
	}()
	qdbus.Session = session

	// open stream
	// rateInBitsPerSecond := uint64(20 * 1000 * 1000)
	// session.SetFixedRate(rateInBitsPerSecond)
	// qdbus.Log("set fixed rate %f...", float64(rateInBitsPerSecond)/1000000)
	qdbus.Log("session established. Opening stream...")
	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("Error opening QUIC stream to [%s]: %s", remoteAddr.String(), err)
	}
	defer func() {
		fmt.Println("closing stream")
		stream.Close()
	}()
	qdbus.Log("stream opened %d", stream.StreamID())

	// continuously send 10MB messages to quic listener
	message := make([]byte, 10000000)
	for i := range message {
		message[i] = 42
	}
	sentBytes := 0
	for {
		if *maxData == 0 {
			_, err = stream.Write(message)
		} else {
			if sentBytes < *maxData {
				var n int
				n, err = stream.Write(message[0:min(len(message), *maxData-sentBytes)])
				sentBytes += n
			} else {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("Error writing message to [%s]: %s", remoteAddr.String(), err)
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

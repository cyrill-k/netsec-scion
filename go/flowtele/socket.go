package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"time"
	"github.com/lucas-clemente/quic-go"
	"github.com/scionproto/scion/go/flowtele/dbus"
	"github.com/scionproto/scion/go/lib/addr"
	sd "github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/snet/squic"
	"github.com/scionproto/scion/go/lib/sock/reliable"
)

var (
	localIAFlag, remoteIAFlag addr.IA
	scionPath                 scionPathDescription

	remoteIpFlag   = flag.String("ip", "127.0.0.1", "IP address to connect to")
	remotePort     = flag.Int("port", 5500, "Port number to connect to")
	localIpFlag    = flag.String("local-ip", "", "IP address to listen on (required for SCION)")
	localPort      = flag.Int("local-port", 0, "Port number to listen on (required for SCION)")
	quicSenderOnly = flag.Bool("quic-sender-only", false, "Only start the quic sender")
	fshaperOnly    = flag.Bool("fshaper-only", false, "Only start the fshaper")
	quicDbusIndex  = flag.Int("quic-dbus-index", 0, "index of the quic sender dbus name")
	nConnections   = flag.Int("num", 2, "Number of QUIC connections (only used in combination with --fshaper-only to restrict the number of quic flows to less than 10)")
	noApplyControl = flag.Bool("no-apply-control", false, "Do not forward apply-control calls from fshaper to this QUIC connection (useful to ensure the calibrator flow is not influenced by vAlloc)")
	mode           = flag.String("mode", "fetch", "the sockets mode of operation: fetch, quic, fshaper")

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

	if *quicSenderOnly || *mode == "quic" {
		// start QUIC instances
		// TODO(cyrill) read flow specs from config/user_X.json
		remoteIp := net.ParseIP(*remoteIpFlag)
		remoteAddr := net.UDPAddr{IP: remoteIp, Port: *remotePort}
		err := startQuicSender(&remoteAddr, int32(*quicDbusIndex), !*noApplyControl)
		if err != nil {
			fmt.Printf("Error encountered (%s), stopping all QUIC senders and SCION socket\n", err)
			os.Exit(1)
		}
	} else if *fshaperOnly || *mode == "fshaper" {
		fdbus := flowteledbus.NewFshaperDbus(*nConnections)

		// if a min interval for the fshaper is specified, make sure to accumulate acked bytes that would otherwise not be registered by athena
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
	} else if *mode == "fetch" {
		sciondAddr := *sciondAddrFlag
		localIA := localIAFlag
		remoteIA := remoteIAFlag
		paths, err := fetchPaths(sciondAddr, localIA, remoteIA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		for _, path := range paths {
			fmt.Println(NewScionPathDescription(path).String())
		}
	} else {
		fmt.Fprintf(os.Stderr, "Must provide either --quic-sender-only or --fshaper-only:\n")

		flag.PrintDefaults()
	}
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

func establishQuicSession(remoteAddr *net.UDPAddr, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.Session, error) {
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
		localIp := net.ParseIP(*localIpFlag)
		localAddr := net.UDPAddr{IP: localIp, Port: *localPort}

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
		return squic.Dial(network, &localAddr, &remoteScionAddr, addr.SvcNone, quicConfig)
	} else {
		// open UDP connection
		localAddr := net.UDPAddr{IP: net.IPv4zero, Port: 0}
		conn, err := net.ListenUDP("udp", &localAddr)
		if err != nil {
			fmt.Printf("Error starting UDP listener: %s\n", err)
			return nil, err
		}

		// start QUIC session
		return quic.Dial(conn, remoteAddr, "host:0", tlsConfig, quicConfig)
	}
}

func startQuicSender(remoteAddr *net.UDPAddr, flowId int32, applyControl bool) error {
	// start dbus
	qdbus := flowteledbus.NewQuicDbus(flowId, applyControl)
	qdbus.SetMinIntervalForAllSignals(5 * time.Millisecond)
	qdbus.OpenSessionBus()
	defer qdbus.Close()
	qdbus.Register()

	// signal forwarding functions
	newSrttMeasurement := func(t time.Time, srtt time.Duration) {
		if srtt > math.MaxUint32 {
			panic("srtt does not fit in uint32")
		}
		signal := flowteledbus.CreateQuicDbusSignalRtt(flowId, t, uint32(srtt.Microseconds()))
		if qdbus.ShouldSendSignal(signal) {
			qdbus.Send(signal)
		}
	}
	packetsLost := func(t time.Time, newSlowStartThreshold uint64) {
		if newSlowStartThreshold > math.MaxUint32 {
			panic("newSlotStartThreshold does not fit in uint32")
		}
		signal := flowteledbus.CreateQuicDbusSignalLost(flowId, t, uint32(newSlowStartThreshold))
		if qdbus.ShouldSendSignal(signal) {
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
		ackedBytesSum := qdbus.Acked(uint32(ackedBytes))
		signal := flowteledbus.CreateQuicDbusSignalCwnd(flowId, t, uint32(congestionWindow), int32(packetsInFlight), ackedBytesSum)
		if qdbus.ShouldSendSignal(signal) {
			qdbus.Send(signal)
			qdbus.ResetAcked()
		}
	}

	flowteleSignalInterface := quic.CreateFlowteleSignalInterface(newSrttMeasurement, packetsLost, packetsAcked)
	// make QUIC idle timout long to allow a delay between starting the listeners and the senders
	quicConfig := &quic.Config{IdleTimeout: time.Hour,
		FlowteleSignalInterface: flowteleSignalInterface}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	// setup quic session
	session, err := establishQuicSession(remoteAddr, tlsConfig, quicConfig)
	if err != nil {
		fmt.Printf("Error starting QUIC connection to [%s]: %s\n", remoteAddr.String(), err)
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
		fmt.Printf("Error opening QUIC stream to [%s]: %s\n", remoteAddr.String(), err)
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
			fmt.Printf("Error writing message to [%s]: %s\n", remoteAddr.String(), err)
			return err
		}
	}
	return nil
}

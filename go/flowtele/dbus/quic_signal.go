package flowteledbus

import (
	"time"
	
	"github.com/godbus/dbus/introspect"
)


func CreateQuicDbusSignalRtt(flow int32, t time.Time, srtt_us uint32) DbusSignal {
	return createReportDbusSignalUint32(Rtt, flow, t, srtt_us)
}

func CreateQuicDbusSignalLost(flow int32, t time.Time, newSsthresh uint32) DbusSignal {
	return createReportDbusSignalUint32(Lost, flow, t, newSsthresh)
}

func CreateQuicDbusSignalCwnd(flow int32, t time.Time, cwnd uint32, pktsInFlight int32) DbusSignal {
	return createReportDbusSignalUint32Int32(Cwnd, flow, t, cwnd, pktsInFlight)
}

func allQuicDbusSignals() []introspect.Signal {
	return []introspect.Signal{
		CreateQuicDbusSignalRtt(0, time.Now(), 0).IntrospectSignal(),
		CreateQuicDbusSignalLost(0, time.Now(), 0).IntrospectSignal(),
		CreateQuicDbusSignalCwnd(0, time.Now(), 0, 0).IntrospectSignal(),
	}
}

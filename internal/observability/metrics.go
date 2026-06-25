package observability

import (
	"fmt"
	"strings"
	"sync/atomic"
)

var (
	clientsConnected atomic.Int64
	adminsConnected  atomic.Int64
	framesRelayed    atomic.Uint64
	bytesRelayed     atomic.Uint64
	clientReconnects atomic.Uint64
	adminReconnects  atomic.Uint64
)

func SetClientsConnected(n int64)  { clientsConnected.Store(n) }
func SetAdminsConnected(n int64)   { adminsConnected.Store(n) }
func IncFramesRelayed(n uint64)     { framesRelayed.Add(n) }
func IncBytesRelayed(n uint64)      { bytesRelayed.Add(n) }
func IncClientReconnects()          { clientReconnects.Add(1) }
func IncAdminReconnects()           { adminReconnects.Add(1) }

// PrometheusText renders counters/gauges in Prometheus exposition format.
func PrometheusText() string {
	var b strings.Builder
	writeGauge := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
	}
	writeCounter := func(name, help string, v uint64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}

	writeGauge("stremo_clients_connected", "Live client WebSocket connections", clientsConnected.Load())
	writeGauge("stremo_admins_connected", "Live admin WebSocket connections", adminsConnected.Load())
	writeCounter("stremo_frames_relayed_total", "Video frames relayed to admins", framesRelayed.Load())
	writeCounter("stremo_bytes_relayed_total", "JPEG bytes relayed to admins", bytesRelayed.Load())
	fmt.Fprintf(&b, "# HELP stremo_reconnects_total Reconnect events by connection type\n# TYPE stremo_reconnects_total counter\n")
	fmt.Fprintf(&b, "stremo_reconnects_total{type=\"client\"} %d\n", clientReconnects.Load())
	fmt.Fprintf(&b, "stremo_reconnects_total{type=\"admin\"} %d\n", adminReconnects.Load())
	return b.String()
}

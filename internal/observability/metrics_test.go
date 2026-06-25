package observability

import (
	"strings"
	"testing"
)

func TestPrometheusTextContainsMetrics(t *testing.T) {
	SetClientsConnected(2)
	SetAdminsConnected(1)
	IncFramesRelayed(10)
	text := PrometheusText()
	for _, want := range []string{
		"stremo_clients_connected",
		"stremo_admins_connected",
		"stremo_frames_relayed_total",
		"stremo_bytes_relayed_total",
		"stremo_reconnects_total{type=\"client\"}",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in metrics output", want)
		}
	}
}

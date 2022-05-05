package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSNI(t *testing.T) {
	defer resetMetrics()
	sni := "test.sni"
	inc := &Inc{
		ActiveSeconds:               1,
		FailedSeconds:               1,
		ActiveFailedSeconds:         1,
		SuccessfulConnections:       2,
		RejectedConnections:         5,
		RejectedConnectionsByClient: 1,
		SNI:                         sni,
	}

	inc.apply()

	const secondsMetadata = `
		# HELP connectivity_exporter_seconds_total Total number of seconds.
		# TYPE connectivity_exporter_seconds_total counter
	`

	secondsExpected := `
		connectivity_exporter_seconds_total{kind="active",sni="test.sni"} 1
		connectivity_exporter_seconds_total{kind="active_failed",sni="test.sni"} 1
		connectivity_exporter_seconds_total{kind="failed",sni="test.sni"} 1
	`

	if err := testutil.CollectAndCompare(seconds, strings.NewReader(secondsMetadata+secondsExpected)); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}

	const connectionsMetadata = `
		# HELP connectivity_exporter_connections_total Total number of new connections.
		# TYPE connectivity_exporter_connections_total counter
	`

	connectionsExpected := `
		connectivity_exporter_connections_total{kind="rejected",sni="test.sni"} 5
		connectivity_exporter_connections_total{kind="rejected_by_client",sni="test.sni"} 1
		connectivity_exporter_connections_total{kind="successful",sni="test.sni"} 2
	`

	if err := testutil.CollectAndCompare(connections, strings.NewReader(connectionsMetadata+connectionsExpected)); err != nil {
		t.Errorf("unexpected collecting result:\n%s", err)
	}
}

func resetMetrics() {
	seconds.Reset()
	connections.Reset()
}

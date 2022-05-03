package metrics

import (
	"strings"
	"sync"
	"testing"
	"time"

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
		SNI:                         NewSNI(sni),
	}
	inc.SNI.StartTTL(&RealTimer{
		Timer: time.NewTimer(TTL),
	})
	applyInc(inc)

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

type mockTimer struct {
	c     chan time.Time
	reset bool
	wg    *sync.WaitGroup
}

func (t *mockTimer) resetTimer() {
	t.reset = true
}

func (t *mockTimer) getChannel() <-chan time.Time {
	return t.c
}

func (t *mockTimer) cleanup() {
	t.wg.Done()
}

func TestTTL(t *testing.T) {
	defer resetMetrics()
	sni := "testsni"
	inc := &Inc{
		ActiveSeconds:               1,
		FailedSeconds:               1,
		ActiveFailedSeconds:         1,
		SuccessfulConnections:       2,
		RejectedConnections:         5,
		RejectedConnectionsByClient: 1,
		SNI:                         NewSNI(sni),
	}

	ch := make(chan time.Time)
	wg := &sync.WaitGroup{}

	inc.SNI.StartTTL(&mockTimer{
		c:  ch,
		wg: wg,
	})

	wg.Add(1)

	// Apply the increment and verify that the metrics got created
	applyInc(inc)
	if testutil.CollectAndCount(seconds) != 3 {
		t.Errorf("Expected 2 metrics got: %d", testutil.CollectAndCount(seconds))
	}

	// expire metrics
	ch <- time.Now()
	wg.Wait()

	// verify metrics are gone
	if testutil.CollectAndCount(seconds) != 0 {
		t.Errorf("Expected 0 metrics got: %d", testutil.CollectAndCount(seconds))
	}

	// SNI appears again after it has been expired
	inc = &Inc{
		ActiveSeconds:               1,
		FailedSeconds:               1,
		ActiveFailedSeconds:         1,
		SuccessfulConnections:       2,
		RejectedConnections:         5,
		RejectedConnectionsByClient: 1,
		SNI:                         NewSNI(sni),
	}
	inc.SNI.StartTTL(&mockTimer{
		c:  ch,
		wg: wg,
	})

	applyInc(inc)
	if testutil.CollectAndCount(seconds) != 3 {
		t.Errorf("Expected 3 metrics got: %d", testutil.CollectAndCount(seconds))
	}

	// RefreshTTL should not affect the metrics
	inc.SNI.refreshTTL <- nil
	if testutil.CollectAndCount(seconds) != 3 {
		t.Errorf("Expected 3 metrics got: %d", testutil.CollectAndCount(seconds))
	}
}

func resetMetrics() {
	seconds.Reset()
	connections.Reset()
}

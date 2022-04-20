// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/klog/v2"

	"m/promextra"
)

// ListenAndServe starts the http server to expose the prometheus metrics
func ListenAndServe(ctx context.Context, addr string, wg *sync.WaitGroup) {
	defer wg.Done()
	defer klog.Infoln("Bye.")

	http.Handle("/metrics", promhttp.Handler())
	klog.Info("Starting connectivity-exporter")
	server := &http.Server{Addr: addr, Handler: nil}

	go func() {
		<-ctx.Done()
		// ignoring the error, we are shutting down anyway
		_ = server.Shutdown(context.TODO())
	}()

	err := server.ListenAndServe()
	if err != http.ErrServerClosed {
		klog.Fatal("unexpected error", err)
	}
	klog.Info(err)
}

// Apply the increments to the prometheus metrics
func Apply(ctx context.Context, wg *sync.WaitGroup, incs <-chan *Inc, snapshots <-chan promextra.Snapshot) {
	defer wg.Done()
	defer klog.Infoln("Bye.")
	done := ctx.Done()

	for {
		select {
		case <-done:
			return
		case inc := <-incs:
			applyInc(inc)
		case snapshot := <-snapshots:
			applySnapshot(snapshot)
		}
	}
}

func applyInc(inc *Inc) {
	inc.SNI.refreshTTL <- nil
	seconds.WithLabelValues("clock", inc.SNI.name).Add(inc.AllSeconds)
	seconds.WithLabelValues("active", inc.SNI.name).Add(inc.ActiveSeconds)
	seconds.WithLabelValues("failed", inc.SNI.name).Add(inc.FailedSeconds)
	seconds.WithLabelValues("active_failed", inc.SNI.name).Add(inc.ActiveFailedSeconds)
	connections.WithLabelValues("successful", inc.SNI.name).Add(inc.SuccessfulConnections)
	connections.WithLabelValues("unacknowledged", inc.SNI.name).Add(inc.UnacknowledgedConnections)
	connections.WithLabelValues("rejected", inc.SNI.name).Add(inc.RejectedConnections)
	connections.WithLabelValues("rejected_by_client", inc.SNI.name).Add(inc.RejectedConnectionsByClient)
	packets.WithLabelValues("orphan", inc.SNI.name).Add(inc.OrphanPackets)
}

func applySnapshot(snapshot promextra.Snapshot) {
	if err := execution.ApplySnapshot(snapshot); err != nil {
		klog.Error("failed to apply snapshot", err)
	}
}

func NewSNI(sni string) *SNI {
	s := &SNI{
		refreshTTL: make(chan interface{}),
		name:       sni,
	}
	return s
}

type TTLTimer interface {
	getChannel() <-chan time.Time
	resetTimer()
	cleanup()
}

type RealTimer struct {
	Timer *time.Timer
}

func (t *RealTimer) getChannel() <-chan time.Time {
	return t.Timer.C
}

func (t *RealTimer) resetTimer() {
	t.Timer.Stop()
	t.Timer.Reset(TTL)
}

func (t *RealTimer) cleanup() {
	t.Timer.Stop()
}

func (sni *SNI) StartTTL(t TTLTimer) {
	go waitForTTL(t, sni)
}

func waitForTTL(t TTLTimer, sni *SNI) {
	defer t.cleanup()
	for {
		select {
		case <-sni.refreshTTL:
			t.resetTimer()
		case <-t.getChannel():
			// The SNI is expired and should be removed from the SNIs map.
			sni.Expired = true
			// The metrics for this SNI have existed longer than
			// TTL and should no longer be exposed.
			deleteMetrics(sni.name)
			return
		}
	}
}

func deleteMetrics(sni string) {
	seconds.DeleteLabelValues("clock", sni)
	seconds.DeleteLabelValues("active", sni)
	seconds.DeleteLabelValues("failed", sni)
	seconds.DeleteLabelValues("active_failed", sni)
	connections.DeleteLabelValues("successful", sni)
	connections.DeleteLabelValues("unacknowledged", sni)
	connections.DeleteLabelValues("rejected", sni)
	connections.DeleteLabelValues("rejected_by_client", sni)
	packets.DeleteLabelValues("orphan", sni)
}

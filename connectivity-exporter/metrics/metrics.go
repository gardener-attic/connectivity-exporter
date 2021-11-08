// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net/http"
	"sync"

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
	seconds.WithLabelValues("clock", inc.SNI).Add(inc.AllSeconds)
	seconds.WithLabelValues("active", inc.SNI).Add(inc.ActiveSeconds)
	seconds.WithLabelValues("failed", inc.SNI).Add(inc.FailedSeconds)
	seconds.WithLabelValues("active_failed", inc.SNI).Add(inc.ActiveFailedSeconds)
	connections.WithLabelValues("successful", inc.SNI).Add(inc.SuccessfulConnections)
	connections.WithLabelValues("unacknowledged", inc.SNI).Add(inc.UnacknowledgedConnections)
	connections.WithLabelValues("rejected", inc.SNI).Add(inc.RejectedConnections)
	packets.WithLabelValues("orphan", inc.SNI).Add(inc.OrphanPackets)
}

func applySnapshot(snapshot promextra.Snapshot) {
	if err := execution.ApplySnapshot(snapshot); err != nil {
		klog.Error("failed to apply snapshot", err)
	}
}

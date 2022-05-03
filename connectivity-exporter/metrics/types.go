// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"m/promextra"
)

// Inc is the increment of the counter metrics
type Inc struct {
	ActiveSeconds,
	FailedSeconds,
	ActiveFailedSeconds,
	SuccessfulConnections,
	RejectedConnections,
	RejectedConnectionsByClient float64
	SNI *SNI
}

type SNI struct {
	refreshTTL chan interface{}
	name       string
	Expired    bool
}

const (
	TTL       time.Duration = time.Minute * 15
	namespace               = "connectivity_exporter"
)

var (
	SNIMutex = sync.Mutex{}

	seconds = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "seconds_total",
			Help:      "Total number of seconds.",
		}, []string{"kind", "sni"},
	)

	connections = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "connections_total",
			Help:      "Total number of new connections.",
		}, []string{"kind", "sni"},
	)

	execution = promextra.NewPrecomputedHistogramAuto(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "bpf_execution",
			Help:      "eBPF program execution time.",
			Buckets: prometheus.ExponentialBuckets(
				2,
				2,
				// The bucket count here should not
				// take the +Inf bucket, hence the -1.
				31,
			),
		},
		nil,
	)
)

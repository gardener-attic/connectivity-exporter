// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"m/promextra"
)

// Inc is the increment of the counter metrics
type Inc struct {
	AllSeconds,
	ActiveSeconds,
	FailedSeconds,
	ActiveFailedSeconds,
	SuccessfulConnections,
	UnacknowledgedConnections,
	RejectedConnections,
	RejectedConnectionsByClient,
	OrphanPackets float64
	SNI string
}

const (
	namespace = "connectivity_exporter"
)

var (
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

	packets = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_total",
			Help:      "Total number of new packets.",
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

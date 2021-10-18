// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package promextra

import (
	"fmt"
	"math"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type Snapshot struct {
	// Total execution time in nanoseconds.
	Total uint64
	// This field does contain the +Inf bucket.
	Buckets []uint64
}

type PrecomputedHistogram struct {
	desc *prometheus.Desc
	// This field does not contain the +Inf bucket.
	buckets []float64
	labels  []*dto.LabelPair

	mutex           sync.Mutex
	currentSnapshot Snapshot
}

var _ prometheus.Collector = (*PrecomputedHistogram)(nil)
var _ prometheus.Metric = (*PrecomputedHistogram)(nil)

// NewSnapshot creates a new snapshot filled with zeroes. The bucket
// count should should include the +Inf bucket too.
func NewSnapshot(bucketCount int) Snapshot {
	return Snapshot{
		Total:   0,
		Buckets: make([]uint64, bucketCount),
	}
}

func NewPrecomputedHistogram(opts prometheus.HistogramOpts) *PrecomputedHistogram {
	buckets := opts.Buckets
	if len(buckets) == 0 {
		buckets = prometheus.DefBuckets
	}
	lastIdx := len(buckets) - 1
	// Drop last bucket if its bound is +Inf.
	if math.IsInf(buckets[lastIdx], 1) {
		buckets = buckets[:lastIdx]
	}
	// For snapshots, we explicitly have a separate bucket for +Inf.
	snapshot := NewSnapshot(len(buckets) + 1)
	desc := prometheus.NewDesc(
		prometheus.BuildFQName(opts.Namespace, opts.Subsystem, opts.Name),
		opts.Help,
		nil,
		opts.ConstLabels,
	)
	return &PrecomputedHistogram{
		desc:            desc,
		buckets:         buckets,
		labels:          prometheus.MakeLabelPairs(desc, nil),
		currentSnapshot: snapshot,
	}
}

func NewPrecomputedHistogramAuto(opts prometheus.HistogramOpts, registerer prometheus.Registerer) *PrecomputedHistogram {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	h := NewPrecomputedHistogram(opts)
	registerer.MustRegister(h)
	return h
}

// Describe is a part of an implementation of the prometheus.Collector
// interface.
func (s *PrecomputedHistogram) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.desc
}

// Collect is a part of an implementation of the prometheus.Collector
// interface.
func (s *PrecomputedHistogram) Collect(ch chan<- prometheus.Metric) {
	ch <- s
}

// Desc is a part of an implementation of the prometheus.Metric
// interface.
func (s *PrecomputedHistogram) Desc() *prometheus.Desc {
	return s.desc
}

// Write is a part of an implementation of the prometheus.Metric
// interface.
func (s *PrecomputedHistogram) Write(out *dto.Metric) error {
	snapshot := s.getCurrentSnapshot()
	// Snapshot buckets include the +Inf, and protobuckets usually
	// should not include it (+Inf bucket should be included in
	// protobuckets if we are dealing with exemplars, which we
	// don't have). Thus we take the bucket count from
	// PrecomputedHistogram's bucket field, not from Snapshot's
	// Buckets.
	protoBuckets := make([]*dto.Bucket, len(s.buckets))
	var cumulativeCount uint64
	for idx := range protoBuckets {
		cumulativeCount += snapshot.Buckets[idx]
		// new variables for a new addresses
		newCount := cumulativeCount
		// UpperBound should be in seconds, while buckets are
		// in nanoseconds. Convert accordingly. One second is
		// 10^9 nanoseconds.
		newUpperBound := s.buckets[idx] / (1000 * 1000 * 1000)
		protoBuckets[idx] = &dto.Bucket{
			CumulativeCount: &newCount,
			UpperBound:      &newUpperBound,
		}
	}
	// Add a count from snapshot's +Inf bucket to get the sum.
	cumulativeCount += snapshot.Buckets[len(snapshot.Buckets)-1]
	// SampleSum should be in seconds, while Total is in
	// nanoseconds. Convert accordingly. One second is 10^9
	// nanoseconds.
	sum := (float64)(snapshot.Total) / (1000 * 1000 * 1000)
	out.Histogram = &dto.Histogram{
		Bucket:      protoBuckets,
		SampleCount: &cumulativeCount,
		SampleSum:   &sum,
	}
	out.Label = s.labels
	return nil
}

func (s *PrecomputedHistogram) getCurrentSnapshot() Snapshot {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.currentSnapshot
}

func (s *PrecomputedHistogram) ApplySnapshot(snapshot Snapshot) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.checkSnapshot(snapshot); err != nil {
		return err
	}
	s.currentSnapshot = snapshot
	return nil
}

func (s *PrecomputedHistogram) checkSnapshot(snapshot Snapshot) error {
	if len(snapshot.Buckets) != len(s.currentSnapshot.Buckets) {
		return fmt.Errorf("snapshot bucket count is not equal to current bucket count, %d vs %d", len(snapshot.Buckets), len(s.currentSnapshot.Buckets))
	}
	return nil
}

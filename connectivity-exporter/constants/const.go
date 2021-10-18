// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// ExecutionBucketCount is a number of buckets in execution
	// time tracking histogram, the last one is +Inf. Make sure it
	// matches the BUCKET_COUNT macro in packet/c/types.h.
	ExecutionBucketCount int = 32
	// BucketWindow is a width of each bucket in execution time
	// tracking histogram in nanoseconds. Make sure it matches the
	// BUCKET_WINDOW macro in packet/c/types.h.
	BucketWindow int = 200
	// PacketBucketCount is a number of buckets for collected
	// packets.
	PacketBucketCount int = 20
)

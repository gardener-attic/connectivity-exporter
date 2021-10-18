// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package packet

// Packet represents a TCP packet
type Packet struct {
	Connection Connection
	Dir        Dir
	Flag       Flag
}

// Connection is the string representation of a TCP connection
// Format: local IP.port _ peer IP.port
type Connection string

// Flag is a combination of TCP flags
type Flag string

// Dir is the direction
type Dir string

const (
	// Syn is the SYN flag
	Syn Flag = "[S]"
	// SynAck is the SYN and ACK flag
	SynAck Flag = "[S.]"
	// RstAck is the RST and ACK flag
	RstAck Flag = "[R.]"
	// From is the direction from the remote peer
	From Dir = "<"
	// To is the direction to the remote peer
	To Dir = ">"
)

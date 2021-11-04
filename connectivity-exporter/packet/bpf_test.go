// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package packet

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

var kernelRelease string

func init() {
	uname := unix.Utsname{}
	_ = unix.Uname(&uname)
	end := bytes.IndexByte(uname.Release[:], 0)
	kernelRelease = string(uname.Release[:end])
}

func TestConnectionTracking(t *testing.T) {
	tests := []struct {
		desc  string
		cidrs string
		ports string
		// The state of the connection map before the test packet is processed.
		// Use this field when testing scenarios which assume a certain state
		// from a previous execution of the BPF program (example: a SYN/ACK
		// packet which continues an already-existing connection).
		initialState map[*tuple]*tupleData
		srcAddr      net.IP
		destAddr     net.IP
		srcPort      uint16
		destPort     uint16
		// Used for swapping source/destination IP and ports for server->client
		// packets (e.g. SYN/ACK).
		serverToClient          bool
		FIN, SYN, RST, PSH, ACK bool
		// When true, we don't expect to find a connection for that test case.
		shouldFail bool
		wantState  connState
	}{
		{
			desc:      "SYN packet",
			cidrs:     "127.0.0.1/32",
			ports:     "443",
			srcAddr:   net.ParseIP("127.0.0.2"),
			destAddr:  net.ParseIP("127.0.0.1"),
			srcPort:   10000,
			destPort:  443,
			SYN:       true,
			wantState: SYN_RECEIVED,
		},
		{
			desc:  "SYN/ACK packet",
			cidrs: "127.0.0.1/32",
			ports: "443",
			initialState: map[*tuple]*tupleData{
				{
					srcIP:   net.ParseIP("127.0.0.1"),
					dstIP:   net.ParseIP("127.0.0.2"),
					srcPort: 10000,
					dstPort: 443,
				}: {state: SYN_RECEIVED},
			},
			srcAddr:        net.ParseIP("127.0.0.2"),
			destAddr:       net.ParseIP("127.0.0.1"),
			srcPort:        443,
			destPort:       10000,
			serverToClient: true,
			SYN:            true,
			ACK:            true,
			wantState:      SYNACK_RECEIVED,
		},
		{
			desc:           "SYN/ACK packet, no matching connection",
			cidrs:          "127.0.0.1/32",
			ports:          "443",
			srcAddr:        net.ParseIP("127.0.0.1"),
			destAddr:       net.ParseIP("127.0.0.2"),
			srcPort:        443,
			destPort:       10000,
			serverToClient: true,
			SYN:            true,
			ACK:            true,
			shouldFail:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ec, err := newEBPFConfig()
			if err != nil {
				t.Fatalf("Creating eBPF config: %v", err)
			}
			defer ec.Close()

			if err := initCIDRMap(ec.cidrMap, AsSet(tc.cidrs)); err != nil {
				t.Fatalf("Initializing CIDR map: %v", err)
			}
			if err := initPortMap(ec.portMap, AsSet(tc.ports)); err != nil {
				t.Fatalf("Initializing port map: %v", err)
			}

			// Initialize connection map to match test scenario.
			for k, v := range tc.initialState {
				if err := setConnection(ec.connectionMap, k, v); err != nil {
					t.Fatalf("Setting connection: %v", err)
				}
			}

			// Construct test packet.
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			err = gopacket.SerializeLayers(
				buf,
				opts,
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
					DstMAC:       net.HardwareAddr{2, 2, 2, 2, 2, 2},
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					SrcIP:    tc.srcAddr,
					DstIP:    tc.destAddr,
					Protocol: layers.IPProtocolTCP,
				},
				&layers.TCP{
					FIN:     tc.FIN,
					SYN:     tc.SYN,
					RST:     tc.RST,
					PSH:     tc.PSH,
					ACK:     tc.ACK,
					SrcPort: layers.TCPPort(tc.srcPort),
					DstPort: layers.TCPPort(tc.destPort),
				},
			)
			if err != nil {
				t.Fatalf("Serializing layers: %v", err)
			}

			// TODO: The first 14 bytes are ignored by the kernel (why?).
			packet := append(make([]byte, 14), buf.Bytes()...)

			ret, _, err := ec.prog.Benchmark(packet, 1, nil)
			if err != nil {
				t.Fatalf("Executing program: %v", err)
			}

			if ret != 0 {
				t.Fatalf("Got non-zero return code %d", ret)
			}

			var key tuple
			if tc.serverToClient {
				key = tuple{
					srcIP:   tc.destAddr,
					dstIP:   tc.srcAddr,
					srcPort: tc.destPort,
					dstPort: tc.srcPort,
				}
			} else {
				key = tuple{
					srcIP:   tc.srcAddr,
					dstIP:   tc.destAddr,
					srcPort: tc.srcPort,
					dstPort: tc.destPort,
				}
			}

			td, err := getConnection(ec.connectionMap, &key)
			if !tc.shouldFail && err != nil {
				t.Fatalf("Getting connection from map: %v", err)
			}
			if tc.shouldFail {
				if err != nil {
					return
				}
				t.Fatal("Test case should have failed")
			}

			if td.state != tc.wantState {
				t.Fatalf("Wrong state: got %d, want %d", td.state, tc.wantState)
			}
		})
	}
}

func TestSNI(t *testing.T) {
	tests := []struct {
		desc string
		// The state of the connection map before the test packet is processed.
		// Use this field when testing scenarios which assume a certain state
		// from a previous execution of the BPF program (example: a SYN/ACK
		// packet which continues an already-existing connection).
		initialState map[*tuple]*tupleData
		srcAddr      net.IP
		destAddr     net.IP
		srcPort      uint16
		destPort     uint16
		wantState    connState
		wantSNI      string
	}{
		{
			desc: "Basic SNI parsing",
			initialState: map[*tuple]*tupleData{
				{
					srcIP:   net.ParseIP("127.0.0.2"),
					dstIP:   net.ParseIP("127.0.0.1"),
					srcPort: 10000,
					dstPort: 443,
				}: {state: SYNACK_RECEIVED},
			},
			srcAddr:   net.ParseIP("127.0.0.2"),
			destAddr:  net.ParseIP("127.0.0.1"),
			srcPort:   10000,
			destPort:  443,
			wantState: SNI_RECEIVED,
			wantSNI:   "google.com",
		},
		{
			desc: "SNI already parsed",
			initialState: map[*tuple]*tupleData{
				{
					srcIP:   net.ParseIP("127.0.0.2"),
					dstIP:   net.ParseIP("127.0.0.1"),
					srcPort: 10000,
					dstPort: 443,
				}: {state: SNI_RECEIVED, sni: "google.com"},
			},
			srcAddr:   net.ParseIP("127.0.0.2"),
			destAddr:  net.ParseIP("127.0.0.1"),
			srcPort:   10000,
			destPort:  443,
			wantState: SNI_RECEIVED,
			wantSNI:   "google.com",
		},
	}

	// TLS payload of a client hello message.
	clientHello := []byte{
		0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x5c,
		0x7f, 0x06, 0x46, 0x23, 0xb0, 0x20, 0x51, 0xa6, 0x5e, 0x4b, 0x81, 0x7e,
		0xcf, 0x8b, 0x5e, 0xb1, 0xe6, 0xa9, 0x5f, 0xca, 0x22, 0xb8, 0x7c, 0xaa,
		0x77, 0x93, 0x6b, 0xc1, 0x37, 0x1d, 0x01, 0x20, 0x0a, 0x21, 0x6f, 0x29,
		0xbd, 0x83, 0x75, 0x2a, 0x7f, 0x9e, 0x01, 0x21, 0x21, 0xbb, 0xeb, 0x59,
		0x7d, 0x54, 0xb7, 0x79, 0x93, 0x8d, 0x0b, 0x34, 0x2d, 0x79, 0x20, 0xe7,
		0x5d, 0x62, 0xe7, 0xfe, 0x00, 0x3e, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01,
		0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
		0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b,
		0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
		0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
		0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x01, 0x75,
		0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x67, 0x6f, 0x6f,
		0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03,
		0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00,
		0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x33, 0x74, 0x00, 0x00, 0x00,
		0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
		0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00,
		0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e, 0x04,
		0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08,
		0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
		0x01, 0x06, 0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03,
		0x02, 0x02, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b, 0x00,
		0x09, 0x08, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x2d,
		0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
		0x00, 0x20, 0x36, 0x45, 0x7b, 0x01, 0xc9, 0x24, 0x4a, 0x9c, 0xd9, 0x6e,
		0x59, 0x05, 0x71, 0xc4, 0x31, 0x2c, 0x7c, 0xa7, 0x42, 0xe2, 0x09, 0xbd,
		0x11, 0xcd, 0x47, 0x6e, 0x52, 0x18, 0xd4, 0x41, 0xf3, 0x56, 0x00, 0x15,
		0x00, 0xb3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ec, err := newEBPFConfig()
			if err != nil {
				t.Fatalf("Creating eBPF config: %v", err)
			}
			defer ec.Close()

			if err := initCIDRMap(ec.cidrMap, AsSet(tc.destAddr.String()+"/32")); err != nil {
				t.Fatalf("Initializing CIDR map: %v", err)
			}
			if err := initPortMap(ec.portMap, AsSet(fmt.Sprint(tc.destPort))); err != nil {
				t.Fatalf("Initializing port map: %v", err)
			}

			// Initialize connection map to match test scenario.
			for k, v := range tc.initialState {
				if err := setConnection(ec.connectionMap, k, v); err != nil {
					t.Fatalf("Setting connection: %v", err)
				}
			}

			// Construct test packet.
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{FixLengths: true}
			err = gopacket.SerializeLayers(
				buf,
				opts,
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
					DstMAC:       net.HardwareAddr{2, 2, 2, 2, 2, 2},
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					SrcIP:    tc.srcAddr,
					DstIP:    tc.destAddr,
					Protocol: layers.IPProtocolTCP,
				},
				&layers.TCP{
					PSH:     true,
					ACK:     true,
					SrcPort: layers.TCPPort(tc.srcPort),
					DstPort: layers.TCPPort(tc.destPort),
				},
				gopacket.Payload(clientHello),
			)
			if err != nil {
				t.Fatalf("Serializing layers: %v", err)
			}

			// TODO: The first 14 bytes are ignored by the kernel (why?).
			packet := append(make([]byte, 14), buf.Bytes()...)

			ret, _, err := ec.prog.Benchmark(packet, 1, nil)
			if err != nil {
				t.Fatalf("Executing program: %v", err)
			}

			if ret != 0 {
				t.Fatalf("Got non-zero return code %d", ret)
			}

			key := tuple{
				tc.srcAddr, tc.destAddr, tc.srcPort, tc.destPort,
			}

			td, err := getConnection(ec.connectionMap, &key)
			if err != nil {
				t.Fatalf("Getting connection from map: %v", err)
			}

			if td.state != tc.wantState {
				t.Fatalf("Wrong state: got %d, want %d", td.state, tc.wantState)
			}
			if td.sni != tc.wantSNI {
				t.Fatalf("Wrong SNI: got %q, want %q", td.sni, tc.wantSNI)
			}
		})
	}
}

func TestBPFExecutionTracking(t *testing.T) {
	t.Skip("Performance tests skipped: see note about bpf_ktime_get_ns() in connectivity-exporter/packet/c/cap.c")

	ec, err := newEBPFConfig()
	if err != nil {
		t.Fatalf("Creating eBPF config: %v", err)
	}
	defer ec.Close()

	// Construct test packet.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(
		buf,
		opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{2, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.ParseIP("127.0.0.1"),
			DstIP:    net.ParseIP("127.0.0.2"),
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SYN:       true,
			SrcPort:   layers.TCPPort(1234),
			DstPort:   layers.TCPPort(443),
			BaseLayer: layers.BaseLayer{Payload: []byte{}},
		},
	)
	if err != nil {
		t.Fatalf("Serializing layers: %v", err)
	}
	// TODO: The first 14 bytes are ignored by the kernel (why?).
	packet := append(make([]byte, 14), buf.Bytes()...)

	ret, _, err := ec.prog.Benchmark(packet, 1, nil)
	if err != nil {
		t.Fatalf("Executing program: %v", err)
	}

	if ret != 0 {
		t.Fatalf("Got non-zero return code %d", ret)
	}

	snapshot, err := readSnapshotFromMap(ec.histogramMap)
	if err != nil {
		t.Fatalf("Failed to read histogram from BPF map: %v", err)
	}
	if snapshot.Total == 0 {
		t.Fatalf("Total duration after first run is zero")
	}
	cumulativeCount := uint64(0)
	for _, count := range snapshot.Buckets {
		cumulativeCount += count
	}
	if cumulativeCount == 0 {
		t.Fatalf("Nothing was added to the bucket")
	}
}

func TestBPFExecutionTrackingManyRuns(t *testing.T) {
	t.Skip("Performance tests skipped: see note about bpf_ktime_get_ns() in connectivity-exporter/packet/c/cap.c")

	ec, err := newEBPFConfig()
	if err != nil {
		t.Fatalf("Creating eBPF config: %v", err)
	}
	defer ec.Close()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(
		buf,
		opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{2, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.ParseIP("127.0.0.1"),
			DstIP:    net.ParseIP("127.0.0.2"),
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SYN:       true,
			SrcPort:   layers.TCPPort(1234),
			DstPort:   layers.TCPPort(443),
			BaseLayer: layers.BaseLayer{Payload: []byte{}},
		},
	)
	if err != nil {
		t.Fatalf("Serializing layers: %v", err)
	}
	// TODO: The first 14 bytes are ignored by the kernel (why?).
	packet := append(make([]byte, 14), buf.Bytes()...)
	runCount := 15

	ret, _, err := ec.prog.Benchmark(packet, runCount, nil)
	if err != nil {
		t.Fatalf("Executing program: %v", err)
	}

	if ret != 0 {
		t.Fatalf("Got non-zero return code %d", ret)
	}

	snapshot, err := readSnapshotFromMap(ec.histogramMap)
	if err != nil {
		t.Fatalf("Failed to read histogram from BPF map: %v", err)
	}
	cumulativeCount := uint64(0)
	for _, count := range snapshot.Buckets {
		cumulativeCount += count
	}
	if cumulativeCount != (uint64)(runCount) {
		t.Fatalf("Expected the cumulative count to be exactly %d, got %d", runCount, cumulativeCount)
	}
}

func TestStatMaps(t *testing.T) {
	t.Logf("Kernel release: %s", kernelRelease)
	ec, err := newEBPFConfig()
	if err != nil {
		t.Fatalf("Creating eBPF config: %v", err)
	}
	defer ec.Close()

	if err := initCIDRMap(ec.cidrMap, AsSet("127.0.0.1/32")); err != nil {
		t.Fatalf("Initializing CIDR map: %v", err)
	}
	if err := initPortMap(ec.portMap, AsSet("443")); err != nil {
		t.Fatalf("Initializing port map: %v", err)
	}
	if err := initStatsMap(ec.statsMap); err != nil {
		t.Fatalf("Initializing stats map: %v", err)
	}
	if err := initTestHookMap(ec.testHookMap, 1); err != nil {
		t.Fatalf("Initializing port map: %v", err)
	}

	// Construct test packet.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(
		buf,
		opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{2, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.ParseIP("127.0.0.1"),
			DstIP:    net.ParseIP("127.0.0.2"),
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			FIN:     false,
			SYN:     false,
			RST:     false,
			PSH:     false,
			ACK:     false,
			SrcPort: layers.TCPPort(12345),
			DstPort: layers.TCPPort(443),
		},
	)
	if err != nil {
		t.Fatalf("Serializing layers: %v", err)
	}

	// TODO: The first 14 bytes are ignored by the kernel (why?).
	packet := append(make([]byte, 14), buf.Bytes()...)

	ret, _, err := ec.prog.Benchmark(packet, 1, nil)
	if err != nil {
		t.Fatalf("Executing program: %v", err)
	}

	if ret != 0 {
		t.Fatalf("Got non-zero return code %d", ret)
	}

	stats, err := getStats(ec.statsMap)
	if err != nil {
		t.Fatalf("Getting stats: %v", err)
	}
	if len(stats) != 20 {
		t.Fatalf("Stats: wrong size: %d", len(stats))
	}
	if len(stats[0]) != 1 {
		t.Fatalf("Stats: wrong amount of items: %+v", stats)
	}
	if s, ok := stats[0]["my-sni-server"]; ok {
		succeededSeconds := s[0]
		failedSeconds := s[1]

		if succeededSeconds != 42 {
			t.Fatalf("Stats: wrong succeededSeconds value for my-sni-server: %v", succeededSeconds)
		}
		if failedSeconds != 43 {
			t.Fatalf("Stats: wrong failedSeconds value for my-sni-server: %v", failedSeconds)
		}
	} else {
		t.Fatalf("Stats: cannot find SNI my-sni-server")
	}
}

func BenchmarkBPF(b *testing.B) {
	ec, err := newEBPFConfig()
	if err != nil {
		b.Fatalf("Creating eBPF config: %v", err)
	}
	defer ec.Close()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(
		buf,
		opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 1, 1, 1, 1, 1},
			DstMAC:       net.HardwareAddr{2, 2, 2, 2, 2, 2},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			SrcIP:    net.ParseIP("127.0.0.1"),
			DstIP:    net.ParseIP("127.0.0.2"),
			Protocol: layers.IPProtocolTCP,
		},
		&layers.TCP{
			SYN:       true,
			SrcPort:   layers.TCPPort(1234),
			DstPort:   layers.TCPPort(443),
			BaseLayer: layers.BaseLayer{Payload: []byte{}},
		},
	)
	if err != nil {
		b.Fatalf("Serializing layers: %v", err)
	}

	// TODO: The first 14 bytes are ignored by the kernel (why?).
	packet := append(make([]byte, 14), buf.Bytes()...)

	var totalDuration time.Duration
	for i := 0; i < b.N; i++ {
		_, duration, err := ec.prog.Benchmark(packet, 1, nil)
		if err != nil {
			b.Fatalf("Benchmarking program: %v", err)
		}
		totalDuration += duration
	}
	b.ReportMetric(float64(totalDuration.Nanoseconds())/float64(b.N), "ns/op")
}

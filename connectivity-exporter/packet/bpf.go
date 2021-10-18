// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package packet

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"k8s.io/klog/v2"

	"m/constants"
	"m/promextra"
)

// #include "./c/types.h"
import "C"

const (
	SO_ATTACH_BPF           = 50
	BPF_PROGRAM_NAME        = "capture_packets"
	BPF_CIDR_MAP_NAME       = "config_cidrs"
	BPF_PORT_MAP_NAME       = "config_ports"
	BPF_CONNECTION_MAP_NAME = "connections"
	BPF_HISTOGRAM_MAP_NAME  = "histogram"

	BPF_TEST_HOOK_MAP_NAME    = "test_hook"
	BPF_TICKER_CLOCK_MAP_NAME = "ticker_clock"
	BPF_STATS_MAP_NAME        = "stats"
	BPF_SNI_STATS_MAP_NAME    = "sni_stats"
)

func init() {
	verifyConstants()
}

// ebpfConfig contains the eBPF programs and maps used for tracking
// connections.
type ebpfConfig struct {
	spec           *ebpf.CollectionSpec
	coll           *ebpf.Collection
	cidrMap        *ebpf.Map
	portMap        *ebpf.Map
	connectionMap  *ebpf.Map
	histogramMap   *ebpf.Map
	testHookMap    *ebpf.Map
	tickerClockMap *ebpf.Map
	statsMap       *ebpf.Map
	prog           *ebpf.Program
}

// newEBPFConfig loads the connection tracking program into the
// kernel, but it does not attach it anywhere.
func newEBPFConfig() (*ebpfConfig, error) {
	config := &ebpfConfig{}

	var err error
	defer func() {
		if err != nil {
			config.Close()
		}
	}()

	config.spec, err = ebpf.LoadCollectionSpecFromReader(bytes.NewReader(capProg))
	if err != nil {
		return nil, fmt.Errorf("loading asset: %w", err)
	}

	// Configure inner map
	config.spec.Maps[BPF_STATS_MAP_NAME].InnerMap = config.spec.Maps[BPF_SNI_STATS_MAP_NAME]

	config.coll, err = ebpf.NewCollection(config.spec)
	if err != nil {
		return nil, fmt.Errorf("creating eBPF collection: %w", err)
	}

	if err = setupMaps(config); err != nil {
		return nil, err
	}

	var ok bool
	config.prog, ok = config.coll.Programs[BPF_PROGRAM_NAME]
	if !ok {
		return nil, fmt.Errorf("bpf program %q not found", BPF_PROGRAM_NAME)
	}

	return config, nil
}

// Close drops a reference to the loaded program. Whether the loaded
// program will actually be unloaded from the kernel depends on
// whether this was a last reference to the program.
func (config *ebpfConfig) Close() {
	if config.coll != nil {
		config.coll.Close()
		config.coll = nil
	}
}

// setupMaps initializes the map fields of ebpfConfig, so accessing
// the maps is more convenient.
func setupMaps(config *ebpfConfig) error {
	var ok bool
	config.cidrMap, ok = config.coll.Maps[BPF_CIDR_MAP_NAME]
	if !ok {
		return fmt.Errorf("no map named %q found", BPF_CIDR_MAP_NAME)
	}
	config.portMap, ok = config.coll.Maps[BPF_PORT_MAP_NAME]
	if !ok {
		return fmt.Errorf("no map named %q found", BPF_PORT_MAP_NAME)
	}
	config.connectionMap, ok = config.coll.Maps[BPF_CONNECTION_MAP_NAME]
	if !ok {
		return fmt.Errorf("no map named %q found", BPF_CONNECTION_MAP_NAME)
	}
	config.histogramMap, ok = config.coll.Maps[BPF_HISTOGRAM_MAP_NAME]
	if !ok {
		return fmt.Errorf("no map named %q found", BPF_HISTOGRAM_MAP_NAME)
	}
	config.testHookMap, ok = config.coll.Maps[BPF_TEST_HOOK_MAP_NAME]
	if !ok {
		return fmt.Errorf("no map named %q found", BPF_TEST_HOOK_MAP_NAME)
	}
	config.tickerClockMap, ok = config.coll.Maps[BPF_TICKER_CLOCK_MAP_NAME]
	if !ok {
		return fmt.Errorf("no map named %q found", BPF_TICKER_CLOCK_MAP_NAME)
	}
	config.statsMap, ok = config.coll.Maps[BPF_STATS_MAP_NAME]
	if !ok {
		return fmt.Errorf("no map named %q found", BPF_STATS_MAP_NAME)
	}

	return nil
}

// ebpfAttachment represents a eBPF program reference that the network
// sockets holds.
//
// Internally it contains a file descriptor to the socket associated
// with some network interface. The socket contains the reference to
// the eBPF program. Closing the socket should unload the program and
// decrease the reference count on the program.
type ebpfAttachment struct {
	socketFD int
}

// attachProgramToNetworkInterface returns an ebpfAttachment object
func attachProgramToNetworkInterface(prog *ebpf.Program, networkInterface string) (*ebpfAttachment, error) {
	iface, err := net.InterfaceByName(networkInterface)
	if err != nil {
		return nil, err
	}
	fd, err := openRawSock(iface.Index)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			syscall.Close(fd)
		}
	}()
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD())
	if err != nil {
		return nil, err
	}
	attachment := &ebpfAttachment{
		socketFD: fd,
	}
	return attachment, nil
}

// Close closes the underlying socket.
func (a *ebpfAttachment) Close() {
	if a.socketFD != -1 {
		syscall.Close(a.socketFD)
		a.socketFD = -1
	}
}

func readSnapshotFromMap(histogramMap *ebpf.Map) (promextra.Snapshot, error) {
	var values []C.struct_execution_histogram
	var index uint32
	if err := histogramMap.Lookup(unsafe.Pointer(&index), &values); err != nil {
		return promextra.Snapshot{}, fmt.Errorf("failed to get values from map: %w", err)
	}
	snapshot := promextra.NewSnapshot(len(values[0].Buckets))
	for _, value := range values {
		snapshot.Total += (uint64)(value.Total)
		for idx, bucketValue := range value.Buckets {
			snapshot.Buckets[idx] += (uint64)(bucketValue)
		}
	}
	return snapshot, nil
}

func verifyConstants() {
	var zero C.struct_execution_histogram
	if len(zero.Buckets) != constants.ExecutionBucketCount {
		klog.Fatalf("bug: mismatched bucket count, %d in ebpf, %d in constants", len(zero.Buckets), constants.ExecutionBucketCount)
	}
}

func parseIPSizeCIDR(h string) (net.IP, int, error) {
	var (
		size int
		ip   net.IP
	)

	_, ipv4Net, err := net.ParseCIDR(h)
	// User might just pass simple IP instead in
	// CIDR format, so checking for that too
	if err != nil {
		ip = net.ParseIP(h).To4()
		if ip == nil {
			return nil, 0, fmt.Errorf("invalid CIDR or IP address: %s", h)
		}
		size = 32
	} else {
		size, _ = ipv4Net.Mask.Size()
		ip = ipv4Net.IP.To4() // this is byte slice of form [127 0 0 1]
		if ip == nil {
			return nil, 0, fmt.Errorf("only IPv4 address supported: %s", h)
		}
	}

	return ip, size, nil
}

func initCIDRMap(m *ebpf.Map, cidrs map[string]struct{}) error {
	for h := range cidrs {
		var (
			value [1]byte
			size  int
			ip    net.IP
		)
		ip, size, err := parseIPSizeCIDR(h)
		if err != nil {
			return err
		}

		IPBigEndian := unsafe.Pointer(&ip[0]) // stored in the form of big endian

		key := C.struct_cidr_key{
			prefixlen: C.uint(size),
			ip:        *(*C.uint)(IPBigEndian),
		}

		if err := m.Put(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			return err
		}
	}

	return nil
}

func initPortMap(m *ebpf.Map, ports map[string]struct{}) error {
	for p := range ports {
		parsed, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port %s", p)
		}
		port := uint16(parsed)

		v := byte(1)
		if err := m.Put(unsafe.Pointer(&port), unsafe.Pointer(&v)); err != nil {
			return err
		}
	}

	return nil
}

func initTestHookMap(m *ebpf.Map, i uint64) error {
	var zero uint32 = 0
	if err := m.Put(unsafe.Pointer(&zero), unsafe.Pointer(&i)); err != nil {
		return err
	}
	return nil
}

func initStatsMap(m *ebpf.Map) error {
	var clock uint32
	for clock = 0; clock < C.STATS_SECONDS_COUNT; clock++ {
		innerMap, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       "sni_stats",
			Type:       ebpf.Hash,
			KeySize:    C.TLS_MAX_SERVER_NAME_LEN,
			ValueSize:  16,
			MaxEntries: C.MAX_SERVER_COUNT,
		})
		if err != nil {
			return err
		}
		innerMapFdUint32 := uint32(innerMap.FD())

		if err := m.Put(unsafe.Pointer(&clock), innerMapFdUint32); err != nil {
			return err
		}
	}
	return nil
}

// Both openRawSock and htons are from github.com/cilium/ebpf
// https://github.com/cilium/ebpf/blob/eaa1fe7482d837490c22d9d96a788f669b9e3843/example_sock_elf_test.go#L146-L166
// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-FileCopyrightText: Copyright (c) 2017 Nathan Sweet
// SPDX-FileCopyrightText: Copyright (c) 2018, 2019 Cloudflare
// SPDX-FileCopyrightText: Copyright (c) 2019 Authors of Cilium
//
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

func openRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

// htons converts the unsigned short integer hostshort from host byte order to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

type tuple struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
}

// Convert the tuple to an array of network-ordered bytes which can be used as
// a key when interacting with BPF maps.
// TODO: When adding support for IPv6, this function needs to be adapted.
func (t tuple) toBytes() [12]byte {
	var res [12]byte

	copy(res[0:4], t.srcIP[12:16])
	copy(res[4:8], t.dstIP[12:16])
	binary.BigEndian.PutUint16(res[8:10], t.srcPort)
	binary.BigEndian.PutUint16(res[10:12], t.dstPort)

	return res
}

// Connection state. Mirrors the tuple_data_t.state enum in C code.
// TODO: Can we read the enum using CGO rather than duplicate it?
type connState uint32

const (
	SYN_RECEIVED connState = iota
	SYNACK_RECEIVED
	SNI_RECEIVED
	RST_RECEIVED
	FIN_RECEIVED
)

// Mirrors the tuple_data_t C struct.
type tupleData struct {
	state                  connState
	sni                    string
	tickerClockFirstPacket uint64
}

// Creates a tupleData from a C.struct_tuple_data_t and returns a pointer to
// it.
func tupleDataFromC(td C.struct_tuple_data_t) *tupleData {
	// TODO: Maybe we can avoid copying here.
	sni := make([]byte, len(td.sni))
	for i, c := range td.sni {
		sni[i] = byte(c)
	}

	res := tupleData{
		state: connState(td.state),
		// Cut the SNI at the first zero byte. This removes any zero bytes we
		// get from the null-terminated C string and also ensures we don't have
		// zero bytes in the middle of the SNI.
		sni:                    string(bytes.SplitN(sni, []byte{0}, 2)[0]),
		tickerClockFirstPacket: uint64(td.ticker_clock_first_packet),
	}

	return &res
}

// Query the BPF stats map.
func getStats(outerMap *ebpf.Map) (out []map[string][2]uint64, err error) {
	var outerKey uint32
	var innerMap *ebpf.Map

	out = make([]map[string][2]uint64, C.STATS_SECONDS_COUNT)
	outerEntries := outerMap.Iterate()
	for outerEntries.Next(&outerKey, &innerMap) {
		if outerKey >= uint32(len(out)) {
			return nil, errors.New("More than 20 entries in the stats map")
		}
		out[outerKey] = make(map[string][2]uint64)

		var innerKey string
		var innerValue [2]uint64
		innerEntries := innerMap.Iterate()
		for innerEntries.Next(&innerKey, &innerValue) {
			sniString := strings.SplitN(innerKey, "\000", 2)[0]

			// succeeded_seconds := innerValue[0]
			// failed_seconds := innerValue[1]
			out[outerKey][sniString] = innerValue
		}
		if err := innerEntries.Err(); err != nil {
			return nil, err
		}
	}

	if err := outerEntries.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// Query the BPF map m for a connection identified by the tuple t.
func getConnection(m *ebpf.Map, t *tuple) (*tupleData, error) {
	key := t.toBytes()
	var v C.struct_tuple_data_t

	err := m.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&v))
	if err != nil {
		return nil, err
	}

	return tupleDataFromC(v), nil
}

// Set an entry in the BPF map m for a connection identified by the tuple t
// with the specified state.
func setConnection(m *ebpf.Map, t *tuple, td *tupleData) error {
	key := t.toBytes()

	if len(td.sni) > C.TLS_MAX_SERVER_NAME_LEN {
		return fmt.Errorf("SNI field is too long: got %d, allowed %d",
			len(td.sni), C.TLS_MAX_SERVER_NAME_LEN)
	}

	// TODO: Maybe we can avoid copying here.
	var sni [C.TLS_MAX_SERVER_NAME_LEN]C.char
	for i, v := range td.sni {
		sni[i] = C.char(v)
	}

	v := C.struct_tuple_data_t{
		state: uint32(td.state),
		sni:   sni,
	}

	return m.Put(unsafe.Pointer(&key), unsafe.Pointer(&v))
}

type tcpFlag struct {
	mask  byte
	short string
}

var tcpFlags = []tcpFlag{
	{0x01, "F"}, // FIN
	{0x02, "S"}, // SYN
	{0x04, "R"}, // RST
	{0x08, "P"}, // PSH
	{0x10, "."}, // ACK
	{0x20, "U"}, // URG
	{0x40, "E"}, // ECE
	{0x80, "W"}, // CWR
}

func flagsString(flags byte) string {
	r := make([]string, 0, 2)
	for _, flag := range tcpFlags {
		if flags&flag.mask != 0 {
			r = append(r, flag.short)
		}
	}
	return fmt.Sprintf("[%s]", strings.Join(r, ""))
}

// Converts a big endian representation of an IP address to a net.IP.
func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

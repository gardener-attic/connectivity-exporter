// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <linux/bpf.h>

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x1
#define TLS_EXTENSION_SERVER_NAME 0x0
// TODO: Figure out real max number according to RFC.
#define TLS_MAX_EXTENSION_COUNT 20
// TODO: figure out the right value.
#define TLS_MAX_SERVER_NAME_LEN 128

// The stats eBPF map can hold statistics for as many different SNI
#define MAX_SERVER_COUNT 100
// The stats eBPF map can hold up to 20 seconds of data
#define STATS_SECONDS_COUNT 20

// The length of the session ID length field.
#define TLS_SESSION_ID_LENGTH_LEN 1
// The length of the cipher suites length field.
#define TLS_CIPHER_SUITES_LENGTH_LEN 2
// The length of the compression methods length field.
#define TLS_COMPRESSION_METHODS_LENGTH_LEN 1
// The length of the extensions length field.
#define TLS_EXTENSIONS_LENGTH_LEN 2
// The length of the extension type field.
#define TLS_EXTENSION_TYPE_LEN 2
// The length of the extension length field (a single extension).
#define TLS_EXTENSION_LENGTH_LEN 2

// The offset of the server name length field from the start of the server_name
// TLS extension.
#define TLS_SERVER_NAME_LENGTH_OFF 7
// The offset of the server name field from the start of the server_name TLS
// extension.
#define TLS_SERVER_NAME_OFF 9

// The offset of the handshake type field from the start of the TLS payload.
#define TLS_HANDSHAKE_TYPE_OFF 5
// The offset of the session ID length field from the start of the TLS payload.
#define TLS_SESSION_ID_LENGTH_OFF 43

// The minimum number of packets that should be sent/received for a connection
// in order to treat the connection as successful.
#define CONN_MIN_NUM_OF_PACKETS 30
// The minimum number of data bytes that should be sent/received on a
// connection in order to treat the connection as successful.
#define CONN_MIN_DATA_BYTES 1024

#define ALL_TCP_FLAGS(func) \
  func(fin, (1 << 0))       \
  func(syn, (1 << 1))       \
  func(rst, (1 << 2))       \
  func(psh, (1 << 3))       \
  func(ack, (1 << 4))       \
  func(urg, (1 << 5))       \
  func(ece, (1 << 6))       \
  func(cwr, (1 << 7))


#define MAKE_TCP_ENUM(name, value) tcp_flags_ ## name = value,
enum tcp_flags {
  ALL_TCP_FLAGS(MAKE_TCP_ENUM)
};
#undef MAKE_TCP_ENUM

struct tcp4_packet {
  __u32 src_addr;
  __u32 dst_addr;
  __u16 src_port;
  __u16 dst_port;
  __u8 flags;
};

struct cidr_key {
	__u32	prefixlen;
	__u32	ip;
};

struct tuple_key_t {
  __u32 source_ip;
  __u32 dest_ip;
  __u16 source_port;
  __u16 dest_port;
};

struct tuple_data_t {
  enum {
    SYN_RECEIVED,
    SYNACK_RECEIVED,
    SNI_RECEIVED,
    RST_RECEIVED,
    FIN_RECEIVED,
  } state;
  char sni[TLS_MAX_SERVER_NAME_LEN];
  // The following two fields cause clang to crash when set to __u16.
  // More info: https://github.tools.sap/kubernetes/connectivity-monitor/pull/109#discussion_r453913
  __u64 num_packets;
  __u64 total_data_bytes;
  __u64 ticker_clock_first_packet;
};

struct sni_stats_t {
    __u64 succeeded_seconds; // TODO: Should be succeeded_connections instead of seconds
    __u64 failed_seconds;    // TODO: Should be failed_connections instead of seconds
};

// A number of linear buckets in histogram.
#define BUCKET_COUNT (32)
// A width of a bucket in nanoseconds.
#define BUCKET_WINDOW (200)

struct execution_histogram {
  __u64 Total;
  __u64 Buckets[BUCKET_COUNT];
};

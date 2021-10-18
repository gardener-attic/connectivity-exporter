// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stdbool.h>

#include "types.h"

#ifndef printt
#define printt(fmt, ...)                                                \
  ({                                                                    \
    char ____fmt[] = fmt;                                               \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);          \
  })
#endif

// Used to pass CIDRs from userspace to BPF program.
struct bpf_map_def SEC("maps") config_cidrs = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct cidr_key),
  .value_size = 1, // not used
  .max_entries = 32, // TODO: hopefully that's enough
  .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") config_ports = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u16), // 0-65535 (native endian)
  .value_size = 1, // not used
  .max_entries = 32,
};

// Used for keeping track of TCP connection state across eBPF program
// invocations.
struct bpf_map_def SEC("maps") connections = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct tuple_key_t),
  .value_size = sizeof(struct tuple_data_t),
  .max_entries = 1024, // TODO: hopefully that's enough
};

struct bpf_map_def SEC("maps") histogram = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32), // indices need to be 4 bytes in size
  .value_size = sizeof(struct execution_histogram),
  .max_entries = 1,
};

// Use to keep a variable whose value alters the program behaviour
// - 0: program works as normal
// - 1: skip normal processing and add some data in the stats map
struct bpf_map_def SEC("maps") test_hook = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u64),
  .max_entries = 1,
};

// Used to keep a variable whose modulo is used as offset for the stats map.
struct bpf_map_def SEC("maps") ticker_clock = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u64),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") stats = {
  .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
  .key_size = sizeof(__u32),
  .max_entries = STATS_SECONDS_COUNT,
};

struct bpf_map_def SEC("maps") sni_stats = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(char[TLS_MAX_SERVER_NAME_LEN]),
  .value_size = sizeof(struct sni_stats_t),
  .max_entries = MAX_SERVER_COUNT,
};

static inline void run_test_hook(__u64 i)
{
  // ok, we add some data in the stats map
  __u64 clock_key = 0;
  __u32 zero = 0;
  __u64 *clock_key_ptr = bpf_map_lookup_elem(&ticker_clock, &zero);
  if (clock_key_ptr)
    clock_key = *clock_key_ptr % STATS_SECONDS_COUNT;

  void *inner_map = bpf_map_lookup_elem(&stats, &clock_key);
  if (inner_map) {

    struct sni_stats_t *s;
    char sni_string[TLS_MAX_SERVER_NAME_LEN] = "my-sni-server";
    s = bpf_map_lookup_elem(inner_map, sni_string);
    if (s) {
      s->failed_seconds++;
      s->succeeded_seconds++;
    } else {
      struct sni_stats_t new_stats = {42, 43};
      bpf_map_update_elem(inner_map, sni_string, &new_stats, BPF_ANY);
    }
  }
}

static inline void add_connection_to_stats(struct tuple_key_t *key, char *sni_string, bool successful_connection)
{
  __u64 clock_key = 0;
  __u32 zero = 0;
  __u64 *clock_key_ptr = bpf_map_lookup_elem(&ticker_clock, &zero);
  if (clock_key_ptr)
    clock_key = *clock_key_ptr % STATS_SECONDS_COUNT;

  void *inner_map = bpf_map_lookup_elem(&stats, &clock_key);
  if (!inner_map)
    return;

  struct sni_stats_t *s;
  s = bpf_map_lookup_elem(inner_map, sni_string);
  if (s) {
    if (successful_connection)
      __sync_fetch_and_add(&s->succeeded_seconds, 1); // TODO: Use core specific datastructures to avoid synchronization
    else
      __sync_fetch_and_add(&s->failed_seconds, 1);
  } else {
    struct sni_stats_t new_stats = {
      successful_connection ? 1 : 0,
      successful_connection ? 0 : 1
    };
    bpf_map_update_elem(inner_map, sni_string, &new_stats, BPF_ANY);

    // Only delete the connection if it was accounted for in the stats
    bpf_map_delete_elem(&connections, key);
  }
}

// Parses the provided SKB at the given offset for SNI information. If parsing
// succeeds, the SNI information is written to the out array. Returns the
// number of characters in the SNI field or 0 if SNI couldn't be parsed.
static inline int parse_sni(struct __sk_buff *skb, __u8 data_offset, char *out)
{
  // Verify TLS content type.
  __u8 content_type;
  bpf_skb_load_bytes(skb, data_offset, &content_type, 1);
  if (content_type != TLS_CONTENT_TYPE_HANDSHAKE)
    return 0;

  // Verify TLS handshake type.
  __u8 handshake_type;
  bpf_skb_load_bytes(skb, data_offset + TLS_HANDSHAKE_TYPE_OFF, &handshake_type, 1);
  if (handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    return 0;

  __u8 session_id_len_off = data_offset + TLS_SESSION_ID_LENGTH_OFF;
  __u8 session_id_len;
  bpf_skb_load_bytes(skb, session_id_len_off, &session_id_len, 1);

  __u8 cipher_suites_len_off =
      session_id_len_off + TLS_SESSION_ID_LENGTH_LEN + session_id_len;
  __u16 cipher_suites_len_be;
  bpf_skb_load_bytes(skb, cipher_suites_len_off, &cipher_suites_len_be, 2);

  __u8 compression_methods_len_off =
      cipher_suites_len_off + TLS_CIPHER_SUITES_LENGTH_LEN +
      bpf_ntohs(cipher_suites_len_be);
  __u8 compression_methods_len;
  bpf_skb_load_bytes(skb, compression_methods_len_off,
      &compression_methods_len, 1);

  __u8 extensions_len_off =
      compression_methods_len_off + TLS_COMPRESSION_METHODS_LENGTH_LEN +
        compression_methods_len;

  __u8 extensions_off = extensions_len_off + TLS_EXTENSIONS_LENGTH_LEN;

  // TODO: Ensure the cursor doesn't surpass the extensions length value?
  __u16 cur = 0;
  __u16 server_name_ext_off = 0;
  for (int i = 0; i < TLS_MAX_EXTENSION_COUNT; i++) {
    __u16 curr_ext_type_be;
    bpf_skb_load_bytes(skb, extensions_off + cur, &curr_ext_type_be, 2);
    if (bpf_ntohs(curr_ext_type_be) == TLS_EXTENSION_SERVER_NAME)
    {
      server_name_ext_off = extensions_off + cur;
      break;
    }
    // Skip the extension type field to get to the extension length field.
    cur += TLS_EXTENSION_TYPE_LEN;

    // Read the extension length and skip the extension length field as well as
    // the rest of the extension to get to the next extension.
    __u16 len_be;
    bpf_skb_load_bytes(skb, extensions_off + cur, &len_be, 2);
    cur += TLS_EXTENSION_LENGTH_LEN + bpf_ntohs(len_be);
  }

  if (server_name_ext_off == 0) // Couldn't find server name extension.
    return 0;

  __u16 server_name_len_be;
  bpf_skb_load_bytes(skb, server_name_ext_off + TLS_SERVER_NAME_LENGTH_OFF,
      &server_name_len_be, 2);
  __u16 server_name_len = bpf_ntohs(server_name_len_be);
  if (server_name_len == 0 || server_name_len > TLS_MAX_SERVER_NAME_LEN)
    return 0;

  // The server name field under the server name extension.
  __u16 server_name_off = server_name_ext_off + TLS_SERVER_NAME_OFF;

  // Read the server name field.
  int counter = 0;
  for (int i = 0; i < server_name_len; i++) {
    if (!out)
      break;
    if (i >= TLS_MAX_SERVER_NAME_LEN)
      break;
    char b;
    bpf_skb_load_bytes(skb, server_name_off + i, &b, 1);
    if (b == '\0')
      break;
    out[i] = b;
    counter++;
  }
  return counter;
}

static
void* get_from_array(struct bpf_map_def* map, __u32 index)
{
  return bpf_map_lookup_elem(map, &index);
}

static
int capture_packets_internal(struct __sk_buff *skb)
{
  // Skip frames with non-IP Ethernet protocol.
  struct ethhdr ethh;
  if (bpf_skb_load_bytes(skb, 0, &ethh, sizeof ethh)) {
    return 0;
  }
  if (bpf_ntohs(ethh.h_proto) != ETH_P_IP) {
    return 0;
  }

  __u8 ip_off = ETH_HLEN;

  // Read the IP header.
  struct iphdr iph;
  if (bpf_skb_load_bytes(skb, ip_off, &iph, sizeof iph)) {
    return 0;
  }

  // Skip packets with IP protocol other than TCP.
  if (iph.protocol != IPPROTO_TCP) {
    return 0;
  }

  struct cidr_key lpm_key;
  lpm_key.prefixlen = 32;

  // We can't check the two boolean expressions using '&&' or '||' as doing so
  // causes clang to optimize to a '|=' bitwise operator on a pointer, which
  // gets rejected by the verifier.
  lpm_key.ip = iph.saddr;
  void* src_addr_found = bpf_map_lookup_elem(&config_cidrs, &lpm_key);
  if (!src_addr_found) {
    lpm_key.ip = iph.daddr;
    void* dst_addr_found = bpf_map_lookup_elem(&config_cidrs, &lpm_key);
    if (!dst_addr_found)
      return 0;
  }

  // An IPv4 header doesn't have a fixed size. The IHL field of a packet
  // represents the size of the IP header in 32-bit words, so we need to
  // multiply this value by 4 to get the header size in bytes.
  __u8 ip_header_len = iph.ihl * 4;
  __u8 tcp_off = ip_off + ip_header_len;

  // Read the TCP header.
  struct tcphdr tcph;
  if (bpf_skb_load_bytes(skb, tcp_off, &tcph, sizeof tcph)) {
    return 0;
  }

  // Should be enabled from command-line explicitly for testing purposes.
  #ifndef TEST_ENABLED
  #define TEST_ENABLED 0
  #endif
  if (TEST_ENABLED) {
    __u32 zero = 0;
    __u64 *test_value = bpf_map_lookup_elem(&test_hook, &zero);
    if (test_value && *test_value != 0) {
      run_test_hook(*test_value);
      return 0;
    }
  }

  __u16 src_port = bpf_ntohs(tcph.source);
  __u16 dst_port = bpf_ntohs(tcph.dest);
  void *src_port_found = bpf_map_lookup_elem(&config_ports, &src_port);
  if (!src_port_found) {
    void *dst_port_found = bpf_map_lookup_elem(&config_ports, &dst_port);
    if (!dst_port_found)
      return 0;
  }

  // We need to be able to determine whether the packet is from the client to
  // the server or the other way around. This is important because for
  // server->client packets the source/dest IP and port need to be reversed so
  // that we can identify the right connection in the connections map.
  bool server_to_client = src_port_found;

  struct tuple_key_t key;
  if (server_to_client) {
    key.source_ip = iph.daddr;
    key.dest_ip = iph.saddr;
    key.source_port = tcph.dest;
    key.dest_port = tcph.source;
  } else {
    key.source_ip = iph.saddr;
    key.dest_ip = iph.daddr;
    key.source_port = tcph.source;
    key.dest_port = tcph.dest;
  }

  __u64 clock_key = 0;
  __u32 zero = 0;
  __u64 *clock_key_ptr = bpf_map_lookup_elem(&ticker_clock, &zero);
  if (!clock_key_ptr) {
    return 0;
  }

  if (tcph.syn && !tcph.ack) { // New connection
    struct tuple_data_t value = {
      .state = SYN_RECEIVED,
      .ticker_clock_first_packet = *clock_key_ptr,
      // TODO: Add more fields.
    };
    bpf_map_update_elem(&connections, &key, &value, BPF_ANY);
    // TODO: We aren't returning here because we still want to push the packet
    // to the queue as long as we don't have complete business logic in eBPF.
  }

  // Existing connection - look it up in the connections map.
  struct tuple_data_t *conn = bpf_map_lookup_elem(&connections, &key);
  if (!conn)
    return 0;

  if (tcph.syn && tcph.ack)
    conn->state = SYNACK_RECEIVED; // TODO: Is this operation safe?

  if (tcph.psh) {
    // The data offset field in the header is specified in 32-bit words. We
    // have to multiply this value by 4 to get the TCP header length in bytes.
    __u8 tcp_header_len = tcph.doff * 4;
    // TLS data starts at this offset.
    __u8 payload_off = tcp_off + tcp_header_len;

    if (conn->state == SNI_RECEIVED) {
      if (conn->num_packets > CONN_MIN_NUM_OF_PACKETS
          || conn->total_data_bytes > CONN_MIN_DATA_BYTES) {
        add_connection_to_stats(&key, conn->sni, true);
      }
    } else {
      // Parse SNI.
      char sni[TLS_MAX_SERVER_NAME_LEN] = {};
      int read = parse_sni(skb, payload_off, sni);
      // Update SNI in connection data.
      if (read > 0) {
        for (int i = 0; i < TLS_MAX_SERVER_NAME_LEN; i++) {
          if (sni[i] == '\0')
            break;
          conn->sni[i] = sni[i];
        }
        conn->state = SNI_RECEIVED;
      }
    }
    __u16 data_bytes = skb->len - payload_off;
    __sync_fetch_and_add(&conn->num_packets, 1);
    __sync_fetch_and_add(&conn->total_data_bytes, data_bytes);
  }

  if (tcph.rst) {
    if (server_to_client) { // Server RST
      conn->state = RST_RECEIVED;
      // Server RST could indicate server unavailability. Therefore, treat
      // the connection as failed.
      add_connection_to_stats(&key, conn->sni, false);
    } else { // Client RST
      conn->state = RST_RECEIVED;
      // Client RST does not indicate server unavailability. Therefore, treat
      // the connection as successful.
      add_connection_to_stats(&key, conn->sni, true);
    }
  }

  if (tcph.fin) {
    if (conn) {
      conn->state = FIN_RECEIVED;
      add_connection_to_stats(&key, conn->sni, true);
    }
  }

  return 0;
}

// https://github.com/iovisor/bcc/blob/722cf83941879c52ebea5e5a1692b2976de6ad62/src/cc/export/helpers.h#L977-L989
// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
// SPDX-FileCopyrightText: Copyright (c) 2015 PLUMgrid, Inc.
//
// SPDX-License-Identifier: Apache-2.0

static inline __attribute__((always_inline)) unsigned int bpf_log2(unsigned int v)
{
  unsigned int r;
  unsigned int shift;
  r = (v > 0xFFFF) << 4;
  v >>= r;

  shift = (v > 0xFF) << 3;
  v >>= shift;
  r |= shift;

  shift = (v > 0xF) << 2;
  v >>= shift;
  r |= shift;

  shift = (v > 0x3) << 1;
  v >>= shift;
  r |= shift;

  r |= (v >> 1);

  return r;
}

static
void update_histogram(__u64 duration_ns)
{
  struct execution_histogram* hist = get_from_array(&histogram, 0);
  if (!hist) {
    return;
  }
  hist->Total += duration_ns;
  __u64 bucket_index = bpf_log2(duration_ns);
  if (bucket_index >= BUCKET_COUNT) {
    bucket_index = BUCKET_COUNT - 1;
  }
  hist->Buckets[bucket_index]++;
}

SEC("socket1")
int capture_packets(struct __sk_buff *skb)
{
  // The performance measurement feature requires calling bpf_ktime_get_ns which requires a GPL v2 license
  // before Linux Kernel version 5.8. So we can activate this feature after the OS has been updated to 5.8+.
  // https://github.com/torvalds/linux/commit/082b57e3eb09810d357083cca5ee2df02c16aec9
  // __u64 start = bpf_ktime_get_ns();
  int ret_val = capture_packets_internal(skb);
  // __u64 end = bpf_ktime_get_ns();
  // update_histogram(end - start);
  return ret_val;
}

char _license[] SEC("license") = "Apache-2.0";

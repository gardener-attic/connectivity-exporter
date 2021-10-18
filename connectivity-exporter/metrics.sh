#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set +x

cd /sys/fs/cgroup || exit 1

while true; do
  sleep 2 &
  awk 'FILENAME == "cpuacct/cpuacct.usage"                {printf "cpu_usage_seconds_total{} %s\n", $1/1e9}
       FILENAME == "cpuacct/cpuacct.usage_percpu"         {for(i=1; i<=NF; i++)
                                                             printf "cpu_usage_seconds_total{cpu=\"%s\"} %s\n", i-1, $i/1e9}
       FILENAME == "cpu/cpu.cfs_period_us"                {printf "cpu_cfs_period_seconds{} %s\n",  $1/1e6}
       FILENAME == "cpu/cpu.cfs_quota_us"                 {printf "cpu_cfs_quota_seconds{} %s\n",   $1/1e6}
       FILENAME == "cpu/cpu.shares"                       {printf "cpu_shares{} %s\n",  $1}
       FILENAME == "cpu/cpu.stat"                         {printf "cpu_stat_%s{} %s\n", $1, $2}
       FILENAME == "memory/memory.max_usage_in_bytes"     {printf "memory_max_usage_in_bytes{} %s\n", $1}
       FILENAME == "memory/memory.usage_in_bytes"         {printf "memory_usage_in_bytes{} %s\n",     $1}
       FILENAME == "memory/memory.stat" && $1 !~ /^total/ {printf "memory_stat_%s{} %s\n", $1, $2}' \
    cpuacct/cpuacct.usage            \
    cpuacct/cpuacct.usage_percpu     \
    cpu/cpu.cfs_period_us            \
    cpu/cpu.cfs_quota_us             \
    cpu/cpu.shares                   \
    cpu/cpu.stat                     \
    memory/memory.max_usage_in_bytes \
    memory/memory.usage_in_bytes     \
    memory/memory.stat               \
  | sed 's/{/{container="connectivity-exporter",/' > /metrics/connectivity-exporter.prom.$$
  mv /metrics/connectivity-exporter.prom.$$ /metrics/connectivity-exporter.prom.part
  wait
done

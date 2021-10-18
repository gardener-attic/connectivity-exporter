#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -x

trap 'date
      echo "Received SIGTERM, propagating the signal to the background jobs."
      kill %1
      wait %1
      kill %2' TERM INT

cd "$(dirname "$(realpath "$0")")" || exit 1

date

apk add tmux curl tcpdump sed less gcc libc-dev libpcap-dev bind-tools util-linux make

./metrics.sh &


time make

default_iface="$(ip route | awk '$1=="default" {print $5}')"

taskset 0x1 \
bin/connectivity-exporter -i "${default_iface}" "$@" \
| tee tracker.log &

set +e
wait %2 # Wait will abort to yield execution to the trap function to handle the SIGTERM signal

echo "Waiting for the background jobs to finish..."
wait %2
date
echo "See you next time!"

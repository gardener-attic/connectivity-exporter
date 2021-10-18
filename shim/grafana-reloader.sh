#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -x
trap 'date
      echo "Received SIGTERM, killing inotifywait."
      killall inotifywait' TERM

apk add inotify-tools

echo "Initializing the grafana dashboards"
base64 -d /var/lib/grafana/dashboards-tbz2/*.tbz2 \
| tar -xjv -C /var/lib/grafana

while inotifywait -e moved_to /var/lib/grafana/dashboards-tbz2; do
  echo
  echo "Reloading the grafana dashboards"
  date
  rm /var/lib/grafana/dashboards/*
  base64 -d /var/lib/grafana/dashboards-tbz2/*.tbz2 \
  | tar -xjv -C /var/lib/grafana
  touch /var/lib/grafana/dashboards/*
done &

wait # Will be aborted by the TERM signal to execute the trap function

echo "Waiting for the background jobs to finish..."
wait
date
echo "See you next time!"

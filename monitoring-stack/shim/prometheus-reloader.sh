#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -x
trap 'date
      echo "Received SIGTERM, killing inotifywait."
      killall inotifywait' TERM

apk add curl inotify-tools jq

heredoc() {
  eval "
cat <<EOF
$(sed '/^# SPDX/d
       s/^#//
       s/#\$/$/' "$@")
EOF"
}

init() {
  echo
  echo "Initializing the prometheus config"
  cp -rL /etc/prometheus-config/* /etc/prometheus
  heredoc /etc/prometheus/prometheus.heredoc.yml > /etc/prometheus/prometheus.yml.$$
  mv /etc/prometheus/prometheus.yml.$$ /etc/prometheus/prometheus.yml
  heredoc /etc/prometheus/rules/error_budget.heredoc.yml > /etc/prometheus/rules/error_budget.yml.$$
  mv /etc/prometheus/rules/error_budget.yml.$$ /etc/prometheus/rules/error_budget.yml
}

init

while inotifywait -e moved_to /etc/prometheus-config; do
  init
  curl -s -XPOST localhost:9090/-/reload
  date
done &

wait # Will be aborted by the TERM signal to execute the trap function

echo "Waiting for the background jobs to finish..."
wait
date
echo "See you next time!"

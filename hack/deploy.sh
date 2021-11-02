#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

toShoot() {
  API_SERVER=$(bin/server.sh | sed -E 's|https?://||')
  API_SERVER_IP=$(dig +short "$API_SERVER" | grep -v -E '^;;|^$')

  FILTERED_IPS=$API_SERVER_IP
  FILTERED_PORTS=443

  export FILTERED_IPS FILTERED_PORTS
}

toSeed() {
  # Deploy in a seed cluster to track the connectivity of all shoot clusters
  # hosted on the seed.
  FILTERED_IPS=0.0.0.0/0
  FILTERED_PORTS=$(bin/node-port.sh)

  export FILTERED_IPS FILTERED_PORTS
}

cd "$(dirname "$(realpath "$0")")/.." || exit 1

if [ "$*" != "toShoot" ] && [ "$*" != "toSeed" ]; then
  echo "Usage: please run this script with the parameter toShoot or toSeed"
  exit 1
fi

eval "$@"

if [ -z "$FILTERED_IPS" ] || [ -z "$FILTERED_PORTS" ]; then
  echo "Usage: please export the FILTERED_IPS and FILTERED_PORTS variables" >&2
  echo "Only matching IP packets will be processed in the k8s cluster." >&2
  exit 1
fi

bin/check-tgz.sh

bin/heredoc.sh k8s/* > k8s/.all-in-one.yml

printf "\nApplying the k8s artifacts:\n"
kubectl apply -f k8s/.all-in-one.yml 2>&1 | tee k8s/.k8s.log

printf "\nConfigured or created artifacts:\n"
# See https://github.com/kubernetes/kubernetes/issues/66450
grep -E "configured|created" k8s/.k8s.log || true

# shellcheck disable=SC2012
cat <<EOF

See k8s/.all-in-one.yml
SHA1: $(sha1sum < k8s/.all-in-one.yml | awk '{print $1}')
$(ls -lh k8s/.all-in-one.yml | awk '{print $5}')

kubectl port-forward --address 127.0.0.1 statefulset/connectivity-monitor-prometheus 9090 9091 29100
kubectl port-forward --address 127.0.0.1 deployment/connectivity-monitor-grafana 3000 29100
kubectl port-forward --address 127.0.0.1 daemonset/connectivity-exporter 19100 29100
kubectl logs daemonset/connectivity-exporter -c connectivity-exporter

kubectl delete --selector 'app in (connectivity-monitor-grafana, connectivity-monitor-prometheus, connectivity-exporter)' \\
  $(awk '/^ {0,4}kind:/ {print $2}' k8s/.all-in-one.yml | sort | uniq | tr '\n' , | sed 's/,$//')
EOF

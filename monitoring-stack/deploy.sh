#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

cd "$(dirname "$(realpath "$0")")" || exit 1

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

kubectl delete --selector 'app in (connectivity-monitor-grafana, connectivity-monitor-prometheus)' \\
  $(awk '/^ {0,4}kind:/ {print $2}' k8s/.all-in-one.yml | sort | uniq | tr '\n' , | sed 's/,$//')
EOF

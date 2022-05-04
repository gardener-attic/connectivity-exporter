#!/bin/sh

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

cd "$(dirname "$(realpath "$0")")" || exit 1

helm upgrade --install \
  connectivity-exporter ../../charts/connectivity-exporter \
  --create-namespace \
  --namespace connectivity-exporter \
  --values ../../charts/connectivity-exporter/values.yaml \
  --values gardener-values.yaml \
  --set-string filteredPorts="$(./node-port.sh)"

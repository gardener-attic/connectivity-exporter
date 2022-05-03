#!/bin/sh

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

cd "$(dirname "$(realpath "$0")")" || exit 1

helm upgrade --install \
  connectivity-monitor ../../charts/connectivity-monitor \
  --create-namespace \
  --namespace connectivity-monitor \
  --values ../../charts/connectivity-monitor/values.yaml

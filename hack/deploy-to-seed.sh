#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

cd "$(dirname "$(realpath "$0")")/.." || exit 1

# Deploy in a seed cluster to track the connectivity of all shoot clusters
# hosted on the seed.
FILTERED_IPS=0.0.0.0/0
FILTERED_PORTS=$(bin/node-port.sh)

export FILTERED_IPS FILTERED_PORTS

hack/deploy.sh

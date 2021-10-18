#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

cd "$(dirname "$(realpath "$0")")/.." || exit 1

# Deploy in a shoot cluster (or a normal kubernetes cluster) to track the
# connectivity to the api server.

API_SERVER=$(bin/server.sh | sed -E 's|https?://||')
API_SERVER_IP=$(dig +short "$API_SERVER" | grep -v -E '^;;|^$')

FILTERED_IPS=$API_SERVER_IP
FILTERED_PORTS=443

export FILTERED_IPS FILTERED_PORTS

hack/deploy.sh

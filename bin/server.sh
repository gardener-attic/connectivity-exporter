#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

CONFIG=$(kubectl config view -o json)

CLUSTER=$(
  echo "$CONFIG" \
  | jq -r ".contexts[]
          | select(.name == \"$(kubectl config current-context)\")
          | .context.cluster")

echo "$CONFIG" \
| jq -r ".clusters[]
        | select(.name == \"$CLUSTER\")
        | .cluster.server"

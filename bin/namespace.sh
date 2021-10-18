#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

kubectl config view -o json \
| jq -r ".contexts[]
         | select(.name == \"$(kubectl config current-context)\")
         | .context.namespace // \"default\""

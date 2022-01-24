#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

cd "$(dirname "$(realpath "$0")")" || exit 1

helm uninstall kube-prometheus-stack

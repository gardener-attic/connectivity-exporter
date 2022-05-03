#!/bin/sh

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

helm uninstall \
  connectivity-monitor \
  --namespace connectivity-monitor

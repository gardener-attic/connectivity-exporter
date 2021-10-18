#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

kubectl -n istio-ingress get svc \
        -o=jsonpath='{.items[0].spec.ports[?(@.name == "tcp")].nodePort}'

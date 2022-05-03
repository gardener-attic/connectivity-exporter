#!/bin/sh

# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

cd "$(dirname "$(realpath "$0")")" || exit 1

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm upgrade --install \
             --values values.yaml \
             --version 35.0.3 \
             --create-namespace \
             --namespace monitoring \
             kube-prometheus-stack \
             prometheus-community/kube-prometheus-stack

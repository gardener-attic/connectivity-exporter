# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.16-alpine3.13
RUN apk add tmux curl tcpdump sed less gcc libc-dev libpcap-dev bind-tools util-linux make clang linux-headers libbpf-dev
COPY . /dependencies
RUN /dependencies/init.sh

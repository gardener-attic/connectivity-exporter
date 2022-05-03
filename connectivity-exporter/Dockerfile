# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.18.1-alpine3.15 as builder
RUN apk add tmux curl tcpdump sed less gcc libc-dev libpcap-dev bind-tools util-linux make clang linux-headers libbpf-dev

COPY ./ /build
RUN cd /build && make

FROM golang:1.18.1-alpine3.15
COPY --from=builder /build/bin/connectivity-exporter /bin/connectivity-exporter

CMD printf 'Example of command:\ndocker run --privileged --net=host -ti --rm ghcr.io/gardener/connectivity-monitor:test /bin/connectivity-exporter -r 0.0.0.0/0 -p 443,6443 -i wlp4s0\n'

ENTRYPOINT [ "/bin/connectivity-exporter" ]

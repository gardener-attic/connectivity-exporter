# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

REGISTRY ?= ghcr.io
IMAGE_NAME ?= gardener/connectivity-exporter
IMAGE_TAG ?= main

all: build

.PHONY: docker/build
docker/build:
	docker build -t $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) -f Dockerfile .

.PHONY: docker/push
docker/push:
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

CLANG_OS_FLAGS = ""

ifeq ($(shell lsb_release -si 2>/dev/null), Ubuntu)
	CLANG_OS_FLAGS="-I/usr/include/$(shell uname -m)-linux-gnu"
endif

.PHONY: build
build: bpf
	go build -o bin/connectivity-exporter main.go

.PHONY: bpf
bpf:
	clang $(CLANG_OS_FLAGS) -target bpf -O2 -g -c -x c packet/c/cap.c -o packet/c/cap.o
	clang $(CLANG_OS_FLAGS) -target bpf -O2 -g -c -x c packet/c/cap.c -o packet/c/cap-testing.o -DTEST_ENABLED=1

.PHONY: test
test: bpf
ifneq ($(shell id -u),0)
	$(warning ***Root privileges are required for executing BPF-related tests***)
	sudo $(shell which go) test -tags testing -timeout 30s -v ./... -count=1
else
	go test -tags testing -timeout 30s -v ./... -count=1
endif

.PHONY: benchmark
benchmark: bpf
ifneq ($(shell id -u),0)
	$(warning ***Root privileges are required for executing BPF-related tests***)
	sudo $(shell which go) test -run=$^ -bench=. ./...
else
	go test -run=$^ -bench=. ./...
endif

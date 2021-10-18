// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// By building this program, go can cache the build artifacts of the package dependencies.
package main

import (
	_ "bytes"
	_ "context"
	_ "embed"
	_ "encoding/binary"
	_ "errors"
	_ "flag"
	_ "fmt"
	_ "math"
	_ "net"
	_ "net/http"
	_ "os"
	_ "os/signal"
	_ "reflect"
	_ "strconv"
	_ "strings"
	_ "sync"
	_ "syscall"
	_ "testing"
	_ "time"
	_ "unsafe"

	_ "github.com/cilium/ebpf"
	_ "github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/prometheus/client_golang/prometheus/promauto"
	_ "github.com/prometheus/client_golang/prometheus/promhttp"
	_ "github.com/prometheus/client_model/go"
	_ "go.uber.org/automaxprocs"
	_ "golang.org/x/sys/unix"
	_ "k8s.io/klog/v2"
)

func main() {}

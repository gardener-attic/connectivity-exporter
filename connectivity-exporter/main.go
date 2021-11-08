// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"m/metrics"
	"m/packet"
	"m/promextra"

	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	_ "go.uber.org/automaxprocs"
)

var (
	networkInterface = flag.String("i", "", "Network interface to listen on")
	cidrs            = flag.String("r", "", "Network CIDRs, comma separated")
	ports            = flag.String("p", "", "Ports, comma separated")
	addr             = flag.String("metrics-addr", ":19100", "Bind and listen address for the metrics")

	incs      = make(chan *metrics.Inc)
	snapshots = make(chan promextra.Snapshot)

	signals = make(chan os.Signal, 1)
	wg      = &sync.WaitGroup{}
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()
	if len(flag.Args()) != 0 {
		klog.Fatalf("Expecting only flag / value pairs, got additional arguments: '%s'. Please check the quoting of the command line arguments.", flag.Args())
	}

	// Using eBPF maps requires locking memory, which in turn requires setting
	// the rlimit for the process.
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
	if err != nil {
		klog.Fatalf("Failed to set rlimit: %v", err)
	}

	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	dataSource, err := packet.NewNetworkDataSource(*networkInterface, packet.AsSet(*cidrs), packet.AsSet(*ports))
	if err != nil {
		klog.Fatalf("Failed to create an eBPF setup: %v", err)
	}
	defer dataSource.Close()
	wg.Add(4)
	go dataSource.TrackExecutionTime(ctx, wg, time.NewTicker(time.Second).C, snapshots)
	go dataSource.TrackConnections(ctx, wg, time.NewTicker(time.Second).C, incs)
	go metrics.Apply(ctx, wg, incs, snapshots)
	go metrics.ListenAndServe(ctx, *addr, wg)

	sig := <-signals
	klog.Infof("Received signal '%s'. Initiating a graceful shutdown.\n", sig)
	cancel()
	wg.Wait()
	klog.Infoln("See you next time!")
}

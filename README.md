Connectivity Monitor
====================

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

Tracks the connectivity of a kubernetes cluster to its api server and exposes
_meaningful_ connectivity metrics.

Uses [ebpf][] to observe all the TCP connection establishments from the shoot
cluster to the kubernetes api server.
Derives _meaningful_ connectivity metrics (upper bound for meaningful
availability) for the kubernetes api server that is running in the seed cluster.

Can be deployed in two different modes:

- Deployed in a shoot cluster (or a normal kubernetes cluster) to track the
  connectivity to the api server.
- Deployed in a seed cluster to track the connectivity of all shoot clusters
  hosted on the seed.

To deploy: run `hack/deploy.sh toShoot` or `hack/deploy.sh toSeed`.

The network path
----------------

The network path from the shoot cluster to the api server.

The shoot cluster's api server is hosted in the seed cluster and the network
path involves several hops:

- the NAT gateway in the shoot cluster,
- the load balancer in the seed cluster,
- a k8s service hop and
- the envoy reverse proxy.

The reverse proxy terminates the TCP connection, starts the TLS negotiation and
chooses the api server of the shoot cluster based on the server name extension
in the TLS ClientHello message ([SNI][]).
The TLS negotiation is relayed to the chosen api server so that the client
actually establishes a TLS session directly with the api server.
(See [SNI GEP][] for details.)

Possible failure types
----------------------

We can distinguish multiple failure types:

- There is no network connectivity to the api server.

  The focus of this connectivity-monitor component.

  New TCP connections to the kubernetes api server are observed to confirm that
  all the components along the network path to the kubernetes api server, and
  the kubernetes api server itself, are working as expected.
  Many things can break along the network path: the DNS resolution of the domain
  name of the load balancer, packets can be dropped due to misconfiguration of
  connection tracking tables, or the reverse proxy might be overloaded to accept
  any new connections.
  The mundane failure case that there are no running api server processes is
  also covered by the connectivity monitor.

- The api server reports an internal server error.

  Detecting this failure type is not feasible for the connectivity-monitor
  component; it can be achieved by processing the access logs of the api server.

  The failure cases when the connection is successfully established, but the api
  server detects and returns a internal server failure (4xx - user error, 5xx -
  internal error) are considered as successful connection attempts, hence the
  connectivity monitor yields an upper bound for meaningful availability.
  This situations can be detected on the server side, by parsing the access
  logs, knowing that due to the successful connections we can expect to find
  matching access logs.

- The api server doesn't comply with the specification.

  Detecting this failure type requires test cases with a known expected outcome.

  The most tricky failure case is when the api server can not itself detect the
  error and returns an incorrect answer as a success (2xx - ok).
  This failure case can only be detected by running test cases against the api
  server, where the result is known ahead of time and it can be asserted that
  the expected and actual results are equivalent.

Observe all the connections from the shoot cluster to the api server
--------------------------------------------------------------------

To capture all connection attempts by:

- system components managed by [Gardener][]: kubelet, kube-proxy, calico, ...
  and
- any user workload that is talking to the api server

the connectivity-exporter must be deployed as a daemonset in the host network of
the node, in the shoot cluster.

Deploying the connectivity-exporter directly in the shoot cluster is motivated
by:

- the connectivity-exporter is closer to the clients that initiate the
  connection and hence it can even capture failed attempts that don't reach the
  seed cluster at all (e.g. due to DNS misconfiguration),

- by deploying the connectivity-exporter in the shoot cluster, the load is
  considerably smaller:
  it is tracking all the connections from a single shoot cluster (1-1k/s), and
  not all the connections from all the shoot clusters of a single seed cluster
  (300x).

Later, we plan to deploy the connectivity exporter in the seed cluster as well
to monitor all the connections from all the shoot clusters centrally, that could
at least reach the reverse proxy (envoy).

Annotate time based on state of connections
-------------------------------------------

The connectivity-exporter assesses each connection attempt based on the packet
sequence it observes in a certain time window:

- rejected connection:
  `SYN` packet sent, `SYN+ACK` packet received, but e.g. during the TLS
  negotiation the server responds with an `RST+ACK` packet to abort the
  connection

- successful connection:
  `SYN` (packet sent to the api server), `SYN+ACK` (packet received from the api
  server)

The connectivity exporter annotates `1s` long time buckets after a certain
offset, to tolerate late arrivals and avoid issues at second boundaries:

- active (/inactive) second:
  active if there were some new connection attempts,
  inactive if there were no new connection attempts,

- failed (/successful) second:
  failed if there was at least one failed connection attempt (rejected), or
  if there were no connection attempts and the preceding bucket was assessed as
  failed;
  successful otherwise.

Prometheus metrics
------------------

The state of the connectivity exporter is exposed with prometheus counter
metrics, which can be comfortably scraped without losing the 1s granularity.

```prometheus
# HELP connectivity_exporter_connections_total Total number of new connections.
# TYPE connectivity_exporter_connections_total counter
connectivity_exporter_connections_total{kind="rejected"} 0
connectivity_exporter_connections_total{kind="successful"} 544

# HELP connectivity_exporter_seconds_total Total number of seconds.
# TYPE connectivity_exporter_seconds_total counter
connectivity_exporter_seconds_total{kind="active"} 337
connectivity_exporter_seconds_total{kind="active_failed"} 0
connectivity_exporter_seconds_total{kind="failed"} 0
```

When the connectivity exporter is deployed in the seed, an SNI label is added to
the metrics above to differentiate the connections to the different api servers.

Inspiration
-----------

This work is motivated by the [meaningful availability][] paper and the
[SRE books][] by Google.

The failed seconds counter metric is _meaningful_ according to the definition of
the paper: _it captures what users experience_.
In every counted failed second, there was at least one failed connection attempt
by a user or there weren't any successful connection attempts since the last
failure.
During the uptime of the monitoring stack itself, any failed connection attempt
by a user (running in the shoot cluster) will be reported as a failed second.

Overview
--------

The following sketch shows where the TCP connections are captured and how time
is annotated based on the assessed connection states.

![overview](docs/overview.png)

The big picture of meaningful availability also includes application level
access logs on the server side.
Connectivity monitoring is a first step on the path to meaningful availability
that yields an upper bound: availability requires connectivity.

Note that this is a low level and hence very generic approach with potential for
widespread adoption.
As long as the service is delivered via TCP/IP (i.e. all the services of our
concern), service instances can be differentiated by the SNI TLS extension, we
can measure the connectivity with `1s` resolution with this approach.
The connectivity exporter can be deployed anywhere along the path between the
clients and the servers.
This choice is a tradeoff: if deployed close to the clients, it can cover more
failure cases and needs to handle less load;
if it is deployed closer to the server, it might cover all the clients but miss
certain failure cases.

In the Gardener architecture, we have the unique situation that all the relevant
clients of the api server are running in the shoot cluster and we can deploy the
connectivity exporter next to some other Gardener managed system components in
the shoot cluster as well.

[ebpf]: https://ebpf.io/
[libpcap]: https://www.tcpdump.org/
[SNI]: https://en.wikipedia.org/wiki/Server_Name_Indication
[SNI GEP]: https://github.com/gardener/gardener/blob/master/docs/proposals/08-shoot-apiserver-via-sni.md
[Gardener]: https://gardener.cloud/
[meaningful availability]: https://www.usenix.org/conference/nsdi20/presentation/hauer
[SRE books]: https://sre.google/books/

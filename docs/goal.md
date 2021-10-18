Meaningful availability
=======================

Goal description
----------------

The availability of a service is its most important indicator:
if a service is not available (i.e. not usable for its clients due to a network
connectivity issue, crashloop backoff of the underlying container or other
internal errors),
all other otherwise critical qualities (e.g. cost efficiency, performance)
recede into the background.

The concept of availability is well-known on all management levels and the
industry standard high availability of 99.95% is explicitly requested.
High availability provides a data driven motivation for full automation (in a
daily maintenance window of 43s, human interaction is obviously not feasible),
self-healing, replication and spreading the deployment to multiple failure
domains (e.g. availability zones).

It turns out that measuring availability in a [meaningful][] way (related to
user experience) with sufficient precision (to be able to confirm the 99.95%
target) is a challenging engineering task on its own.

This business goal is about adopting Google SRE best practices to the Gardener
project and measuring the shoot cluster's k8s api server's availability in a
meaningful way.

This business goal shall be considered as successful if the availability of the
k8s api servers of all the Gardener shoot clusters is continuously (*) measured
in a meaningful way and that data is used regularly to drive business decisions.

*: obviously, with at least 99.95% availability :)

[meaningful]: https://www.usenix.org/conference/nsdi20/presentation/hauer

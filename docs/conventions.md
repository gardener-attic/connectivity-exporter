Conventions
===========

This document lists some of the conventions of this project.

- The configuration files are in versioned their idiomatic, POSIX path (e.g.
  `etc/prometheus/prometheus.yml`).

- The configuration files are kept separate from the kubernetes artifacts.
  They are merged with a very lightweight, bash here document based templating
  "engine" (`bin/heredoc.sh`) to produce a single yaml document
  (`k8s/.all-in-one.yml`) that can be directly applied with `kubectl apply`.

- Markdown

  - Tidy with [markdown lint][]

  - Semantic line feeds (inspired by [golang-design-documents][],
    [one-sentence-per-line][], with [reflow-markdown][])

Templating
----------

Many programming languages offer some form of templating.

A template is a source code file where the default context is uninterpreted
plain text.
When the template is processed by a templating engine, the program outputs the
plain text verbatim.

The value proposition of a templating engine is that it defines an escape
sequence that allows to leave the default context of uninterpreted plain text
and enter a context of a (general purpose or limited) programming language.
The output of those code snippets is merged with the verbatim output of the
surrounding plain text.

The templating engine of Ruby is ERB (Embedded Ruby).
Bosh (the release engineering component of Cloud Foundry) is implemented in
Ruby, the templates of a bosh release are based on ERB.

The templating engine of Golang is the text/template package.
K8s is implemented in Golang, and the features of the text/template package are
accessible e.g. via the `kubectl` output options.

K8s does not provide a standard way to generate Yaml files.
A popular choice is Helm but this projects is exploring something else for even
more simplicity.

The POSIX shell does not define a templating language, but the Here Document
feature of Bash (see `man bash`) can be turned into a simple and powerful
templating engine.

Here Documents allow to change the default context to uninterpreted plain text.
They support an escape sequence (`$`) to change the context back to the shell
script.

Example here document:

```shell
echo "The default context is source code."
cat <<EOF
This is a here document.
This is interpreted as plain text, verbatim.
The escape sequence \$ can be used to merge in
the output of code snippets.

The google.com domain name resolves to $(dig +short google.com).
EOF
```

produces the following output:

```text
The default context is source code.
This is a here document.
This is interpreted as plain text, verbatim.
The escape sequence $ can be used to merge in
the output of code snippets.

The google.com domain name resolves to 142.250.185.110.
```

The idea is to change the default context of a source file to a heredoc
template.
The following `heredoc.sh` program takes paths as arguments, and interprets them
as a heredoc template.

This is a templating engine in 4 lines of POSIX shell.

```shell
#!/bin/sh

eval "
cat <<EOF
$(cat "$@")
EOF"
```

Given a heredoc template, `hello.heredoc.txt`:

```heredoc
This is a here document.
This is interpreted as plain text, verbatim.
The escape sequence \$ can be used to merge in
the output of code snippets.

The google.com domain name resolves to $(dig +short google.com).
```

The command `bin/heredoc.sh hello.heredoc.txt` resolves the template as
expected.

```text
This is a here document.
This is interpreted as plain text, verbatim.
The escape sequence $ can be used to merge in
the output of code snippets.

The google.com domain name resolves to 142.250.185.110.
```

In yaml, the `#` character starts a comment which is shown in a different color
in an editor that supports syntax highlighting.
The idea is to prefix the code snippets in a heredoc template with `#` to show
them in the color of yaml comments in the editor.

```yaml
## k8s/cm-prometheus.yml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus
  labels: {app: connectivity-monitor}
data:
  prometheus.yml: |
#$(sed 's/^/    /' etc/prometheus/prometheus.yml)
```

We can remove the `#` prefix before the `$` sign and from the beginning of a line with:

```shell
sed 's/^#//
     s/#\$/$/'
```

With 5 lines of POSIX shell:

```shell
#!/bin/sh

eval "
cat <<EOF
$(sed 's/^#//
       s/#\$/$/' "$@")
EOF"
```

we can resolve the file `k8s/cm-prometheus.yml`

```yaml
## k8s/cm-prometheus.yml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus
  labels: {app: connectivity-monitor}
data:
  prometheus.yml: |
#$(sed 's/^/    /' etc/prometheus/prometheus.yml)
```

with `bin/heredoc.sh k8s/cm-prometheus.yml` to

```yaml
# k8s/cm-prometheus.yml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus
  labels: {app: connectivity-monitor}
data:
  prometheus.yml: |
    The indented content of etc/prometheus/prometheus.yml
```

The content of `etc/prometheus/prometheus.yml` is indented with 4 spaces and
merged into the template, to produce a valid yaml document.

This technique allows to strictly separate configuration files (`etc/...`) from
the k8s artifacts (`k8s/...`).

It also provides an idiomatic and simple way to compress Grafana dashboards
before including them in a config map, to avoid hitting the size limit of config
maps early on.

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboards-tbz2
  labels: {app: connectivity-monitor}
data:
  grafana-dashboards.tbz2: |
#$(printf "\nCreating a .tbz2 of the grafana dashboards:\n" >&2
#  cd var/lib/grafana
#  tar -cjv dashboards | base64 | tr -d '\n' | sed 's/^/    /')
```

is resolved with
`bin/heredoc.sh k8s/cm-grafana-dashboards-tgz.yml 2>/dev/null | cut -c 1-100`
to:

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboards-tbz2
  labels: {app: connectivity-monitor}
data:
  grafana-dashboards.tbz2: |
    QlpoOTFBWSZTWXArMNcDfXx/6v//+vJ/////v+//v/////8AAgGEQgARgGQI4M2/VfD4jeLDgesoPHsDhAegUDhYhSnZx23r
```

Calculating the content hash of configuration files that can not be reloaded at
runtime allows to automatically recreate the pod when those configuration files
change, with the help of the annotation feature of k8s.

```yaml
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: connectivity-monitor
  labels: {app: connectivity-monitor}
spec:
  selector: {matchLabels: {app: connectivity-monitor}}
  serviceName: connectivity-monitor
  template:
    metadata:
      labels: {app: connectivity-monitor}
      annotations:
        checksum/etc: #$(cat $(find etc/grafana -type f) | sha1sum | awk '{print $1}')
```

is resolved with `bin/heredoc.sh k8s/sts-connectivity-monitor.yml 2>/dev/null | head -14` to

```yaml
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: connectivity-monitor
  labels: {app: connectivity-monitor}
spec:
  selector: {matchLabels: {app: connectivity-monitor}}
  serviceName: connectivity-monitor
  template:
    metadata:
      labels: {app: connectivity-monitor}
      annotations:
        checksum/etc-grafana: 5b25c14b61a22b05b049d6716dbb60fa85a90627
```

Yaml
----

The yaml specification allows for concise, human readable or very verbose
representations of the same document.

A neatly formatted (e.g. vertically aligned), concise, human readable
representation is preferred.

Examples:

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: connectivity-monitor
  labels: {app: connectivity-monitor}
rules:
- apiGroups: [""]
  resources: [pods]
  verbs: [get, list, watch]
```

```yaml
- name: prometheus-reloader
  resources:
    requests: {cpu: 50m, memory: 100Mi}
    limits:   {cpu: 50m, memory: 100Mi}
  volumeMounts:
  - {name: prometheus-config,    mountPath: /etc/prometheus-config}
  - {name: prometheus,           mountPath: /etc/prometheus}
  - {name: connectivity-monitor, mountPath: /var/lib/prometheus, subPath: prometheus}
```

Shims and resource usage monitoring
-----------------------------------

Shim is the term for a lightweight wrapper.
It is used to replace the default entry point of a container with a shell script
that calls the original entry point and does something else as well.

This technique allows for customization in a container without creating a new
image or without using a sidecar.
Some customizations need to run in the same PID namespace and hence can't run in
a sidecar.
Customizations that need only a tiny amount of CPU can be run in the main
container to avoid wasting CPU requests.

Resource usage information can be collected in the main container (same PID
namespace) directly from the `/sys/fs/cgroup` file system.
This approach avoids the overhead and additional abstraction of a middle man
(e.g. `cadvisor`), gives us control over the sampling rate and adds the
flexibility to transport the output of any shell command to Prometheus/Grafana.

The following snippet produces samples about the disk usage of a specific
partition in the prometheus exposition format:

```shell
df /var/lib/prometheus | awk '/prometheus/ {
  printf "disk_usage_bytes{} %s\n", $3 * 1024
  printf "disk_available_bytes{} %s\n", $4 * 1024}' \
| sed 's/{/{container="prometheus",/'
```

```prometheus
disk_usage_bytes{container="prometheus",} 230608896
disk_available_bytes{container="prometheus",} 775917568
```

The `node-exporter`'s text collector can pick up these samples in a generic way,
so this is all it takes to transfer the output of `df` (disk free) as metric to
Prometheus and plot it in Grafana.

Scraping the `cadvisor` metrics is avoided on purpose to reduce wasteful work.
The cadvisor yields too many (for the current use case mostly irrelevant)
metrics for all the containers in the cluster.

The shim based approach to expose only select metrics and collect them with the
text collector of the `node-exporter` yields only relevant metrics and only for
the containers of this deployment.

The shim technique can be used to execute a shell script in an alpine container,
e.g. to reload the prometheus rules or Grafana dashboards when a new configmap
is detected with `inotifywait`.

Monorepo
--------

The mainstream way that is suggested by the Github model is to create a new Git
repository for every new idea.
However, if a project is composed of several Git repositories, the ceremony that
is needed to connect them is not justified if those projects don't have an
independent life cycle.
The other end of the spectrum is the Monorepo approach by Google, where all the
source code of a corporation is kept in a single repository - a model that is
not supported by Git.

In this project, naming and versioning components is avoided if they don't have
an independent lifecycle and are not consumed outside of the project.

The connectivity-exporter go application is developed in the scope of this
connectivity-monitor project.
It doesn't have an independent lifecycle (yet), and it is not to be consumed
outside of this project.
So, instead of devoting a dedicated git repository for the connectivity-exporter
golang application, the source code is simply kept in a subfolder of this
repository.

To facilitate the collaboration in the Go community, Go encourages to develop go
applications as libraries right from the start, so that they can be consumed in
other applications easily.

The approach of unnamed go modules is also supported if the component is
not to be consumed by other applications.

This way we can avoid the ceremony and hassle of working with multiple git
repositories, with git submodules or with explicitly named, released and
versioned things, that wouldn't add value to the development process (now).

Programming languages
---------------------

Choosing the "right" tool among the several programming languages we have at our
disposal feels like art and is shaped by personal skills and experience.

The shell and other tools (`sed`, `awk`) that are defined by the POSIX standard,
are preferred for the orchestration of the programs.
The expressiveness and simplicity of this programming paradigm shines for this
use case, and the inefficiency of an interpreted language is of no concern due
to the negligible resource requirements of those tiny tasks.

Golang compiles to machine code and excels at concurrent programs, e.g. the
`select` statement can be used to wait for multiple things and continue with the
one that becomes ready first.

eBPF programs are mostly written in C.

Pure functions
--------------

The functional programming paradigm defines the concept of pure functions:
functions, whose output only depends on its arguments.
A pure function is not allowed to cause or depend on side effects, e.g. the tick
of a clock should be passed in as an argument.

It is good practice to implement the business logic with pure functions.

Minimal dependency surface
--------------------------

The proliferation of (transitive) dependencies can be controlled by defining
data structures that are exchanged at the boundaries between the different Go
packages.

Use `metrics.Inc` instead of
`github.com/prometheus/client_golang/prometheus.CounterVec`, or `packet.Packet`
instead of `github.com/google/gopacket.Packet`.

This makes unit tests easier without the need for ceremonial mocking.

Graceful shutdown
-----------------

Make sure all the components are shut down in a clean and graceful way.

The docker containers should handle the SIGTERM signal and all the processes
should be stopped in a clean way.

The golang application should also handle the SIGTERM signal and stop the go
routines in a clean way.

Self monitoring
---------------

Expose, capture and visualize metrics that are needed for self monitoring.

There are dashboards for cgroup based CPU and memory metrics, golang metrics,
and application level metrics.
All the captured metrics should be meaningful for the use case and should be
shown on a dashboard.

Deploy the source code
----------------------

> Here is my source code,
>
> run it in the cloud for me,
>
> I do not care how.

// Haiku from @onsijoe about Cloud Foundry

Cloud Foundry uses build packs to build the executable artifacts in the cloud,
to simplify the interactive development workflow.

Conventional CI/CD pipelines tend to be complicated, slow and wasteful when it
comes to resource usage.
They build a castle each time all over again from grains of sand, and tend not
to profit from caching on different layers to avoid wasteful work.

Proper, content based caches with Git and Docker guarantee reproducible and
consistent build artifacts.

Image registries are shared among developers and are a global resource.
During the development workflow, building an image locally or in a CI/CD
environment takes time, incurs network traffic and it typically doesn't utilize
caches to avoid wasteful work.

This project explores the idea to use init containers to build Docker images
directly on the node in a development setup.
This approach benefits from the content based caching feature of docker.

Furthermore, this project explores the idea to compile the go dependencies only
once, seal them in a docker image with the Golang package build cache and use
that image to build the real application.
Building the source code of the application is just as fast in the cloud as on a
laptop, where Go can easily manage its caches in the background.

This way it is possible to deploy the the source code directly to the cloud.
Building the necessary container images is performed automatically if needed,
intermediate artifacts are cached, wasteful work is avoided.

[markdown lint]: https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint
[golang-design-documents]: https://github.com/golang/proposal#design-documents
[one-sentence-per-line]: https://rhodesmill.org/brandon/2012/one-sentence-per-line/
[reflow-markdown]: https://marketplace.visualstudio.com/items?itemName=marvhen.reflow-markdown

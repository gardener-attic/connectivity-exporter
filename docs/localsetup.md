# Local Setup

## Using multipass

### Install [multipass](https://multipass.run)

On the Mac, install multipass with `brew install multipass`.

### Create a VM (Ubuntu 22.04 LTS)

```shell
multipass launch --name vm --cpus 2 --mem 2048M --disk 5G jammy
```

### Mount the repository

```shell
multipass mount $(pwd) vm
```

### Shell onto the vm

```shell
multipass shell vm
```

### Install OS level dependencies

```shell
ubuntu@vm$ sudo apt update && sudo apt install -y clang make golang-1.18 libbpf-dev
ubuntu@vm$ # Add go to the Path
ubuntu@vm$ echo 'PATH=$PATH:/usr/lib/go-1.18/bin' >> ~/.bashrc; source ~/.bashrc
```

### Compile the program

```shell
ubuntu@vm$ cd /to/mount/directory/connectivity-exporter
ubuntu@vm$ make build
```

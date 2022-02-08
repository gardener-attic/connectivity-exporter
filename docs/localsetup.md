# Local Setup

## Using multipass

### Install [multipass](https://multipass.run)

On mac install via `brew install multipass`

### Create a VM

```shell
multipass launch --name vm --cpus 2 --mem 2048M --disk 5G impish
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
ubuntu@vm$ sudo apt update && sudo apt install -y clang make golang-1.16 libbpf-dev
ubuntu@vm$ # Add go to the Path
ubuntu@vm$ echo 'PATH=$PATH:/usr/lib/go-1.16/bin/' >> ~/.bashrc; source ~/.bashrc
```

### Compile the program

```shell
ubuntu@vm$ cd /to/mount/directory/connectivity-monitor
ubuntu@vm$ make build
```

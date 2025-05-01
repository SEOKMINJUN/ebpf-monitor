# EBPF-MONITOR

ebpf-monitor 는 시스템 활동을 모니터링하고 로그를 기록합니다.


## Build

```
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./include/vmlinux.h"
go generate && go build
```

## Run

```
sudo ./ebpf-monitor
```


## Manual compile bpf file

```
clang -O2 -g -target bpf -c input_bpf_src.bpf.c -o output_file.o
```
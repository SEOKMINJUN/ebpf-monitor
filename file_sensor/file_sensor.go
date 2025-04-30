package file_sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux file file.bpf.c

func FileSensorStart() {
	go start()
}

func start() {

}

package main

//go:generate go generate ./file_sensor
//go:generate go generate ./process_sensor
//go:generate go generate ./tcp_sensor

import (
	"ebpf-monitor/file_sensor"
	"ebpf-monitor/process_sensor"
	"ebpf-monitor/tcp_sensor"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	file_sensor_signal := make(chan os.Signal, 1)
	process_sensor_signal := make(chan os.Signal, 1)
	tcp_sensor_signal := make(chan os.Signal, 1)

	signal.Notify(file_sensor_signal, os.Interrupt, syscall.SIGTERM)
	signal.Notify(process_sensor_signal, os.Interrupt, syscall.SIGTERM)
	signal.Notify(tcp_sensor_signal, os.Interrupt, syscall.SIGTERM)

	file_sensor_end := make(chan bool)
	process_sensor_end := make(chan bool)
	tcp_sensor_end := make(chan bool)

	go file_sensor.FileSensorStart(file_sensor_signal, file_sensor_end)
	go process_sensor.ProcessSensorStart(process_sensor_signal, process_sensor_end)
	go tcp_sensor.TcpSensorStart(tcp_sensor_signal, tcp_sensor_end)

	<-file_sensor_end
	<-process_sensor_end
	<-tcp_sensor_end
}

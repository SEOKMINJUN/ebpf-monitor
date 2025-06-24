package main

//go:generate go generate ./file_sensor
//go:generate go generate ./process_sensor
//go:generate go generate ./tcp_sensor
//go:generate go generate ./shell_sensor

import (
	"ebpf-monitor/file_sensor"
	"ebpf-monitor/helper"
	"ebpf-monitor/logger"
	"ebpf-monitor/process_sensor"
	"ebpf-monitor/shell_sensor"
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

	logger.Init()
	defer logger.Close()

	helper.InitBroker()

	termSignal := make(chan os.Signal, 1)
	go func() {
		<-termSignal
		helper.GlobalBroker.Publish(true)
	}()
	signal.Notify(termSignal, os.Interrupt, syscall.SIGTERM)

	file_sensor_end := make(chan bool)
	process_sensor_end := make(chan bool)
	tcp_sensor_end := make(chan bool)
	shell_sensor_end := make(chan bool)

	go file_sensor.FileSensorStart(file_sensor_end)
	go process_sensor.ProcessSensorStart(process_sensor_end)
	go tcp_sensor.TcpSensorStart(tcp_sensor_end)
	go shell_sensor.SensorStart(shell_sensor_end)

	<-file_sensor_end
	<-process_sensor_end
	<-tcp_sensor_end
	<-shell_sensor_end

}

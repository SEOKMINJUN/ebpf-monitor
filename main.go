package main

//go:generate go generate ./file_sensor
//go:generate go generate ./process_sensor

import (
	"ebpf-monitor/file_sensor"
	"ebpf-monitor/process_sensor"

	"github.com/cilium/ebpf/rlimit"
)

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	file_sensor_end := make(chan bool)
	go file_sensor.FileSensorStart(file_sensor_end)

	process_sensor_end := make(chan bool)
	go process_sensor.ProcessSensorStart(process_sensor_end)

	<-file_sensor_end
	<-process_sensor_end
}

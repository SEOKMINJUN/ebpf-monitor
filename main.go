package main

//go:generate go generate ./file_sensor

import (
	"ebpf-monitor/file_sensor"
	"fmt"
)

func main() {
	fmt.Println("Hello World!")
	file_sensor.FileSensorStart()
}

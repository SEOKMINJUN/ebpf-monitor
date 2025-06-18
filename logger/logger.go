package logger

import (
	"ebpf-monitor/helper"
	"encoding/json"
	"log"
	"os"
	"time"
)

var PRINT_OUTPUT = true
var OUTPUT = make(chan []byte)

func Init() {

	f, err := os.OpenFile("output.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open or create output log")
		return
	}

	go func() {
		var log_string []byte = nil
		for {
			log_string = <-OUTPUT
			if log_string == nil || len(log_string) == 0 {
				f.Close()
				break
			}
			f.Write(log_string)
			f.Write([]byte{0x0A})
		}

	}()
}

func LogEvent(event_type string, timestamp int64, obj interface{}) {
	event := helper.Event{}
	event.TYPE = event_type
	event.TIMESTAMP = time.Unix(timestamp, 0).Format(time.RFC3339Nano)
	event.Data = helper.StructToMap(obj)
	//Do send trace
}

func WriteOutput(sensor_type int, jsonBytes []byte) {
	if !json.Valid(jsonBytes) {
		log.Fatalf("Get invalid json object from %s", sensor_type)
	}

	// if sensor_type == 0 {
	// 	return
	// }

	OUTPUT <- jsonBytes
}

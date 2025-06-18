package shell_sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf bpf.c -- -I../include -g

import (
	"bytes"
	"ebpf-monitor/helper"
	"ebpf-monitor/logger"
	"encoding/binary"
	"errors"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type perfEvent struct {
	eventType     int32
	readlineEvent bpfReadlineEvent
}

// EVENT TYPE
const (
	EVENT_TYPE_EXIT = -1
	EVENT_TYPE_CMD  = 0
)

// CONST
const (
	binPath  = "/bin/bash"
	funcName = "readline"
)

func SensorStart(termSignal chan os.Signal, end chan bool) {
	// Load pre-compiled bpf programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	exec, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	up, err := exec.Uretprobe(funcName, objs.UretprobeBashReadline, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer up.Close()

	eventsReader, err := perf.NewReader(objs.ReadlineEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer eventsReader.Close()

	eventChan := make(chan perfEvent)

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-termSignal

		if err := eventsReader.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}

		eventChan <- perfEvent{eventType: EVENT_TYPE_EXIT}
	}()

	log.Println("Waiting for events..")

	//Receive events from ringBuffer
	go func() {
		var readlineEvt bpfReadlineEvent
		for {
			event, err := eventsReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					log.Println("Received signal, exiting shell sensor..")
					eventChan <- perfEvent{eventType: EVENT_TYPE_EXIT}
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			if event.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", event.LostSamples)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(event.RawSample), binary.LittleEndian, &readlineEvt); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			eventChan <- perfEvent{eventType: EVENT_TYPE_CMD, readlineEvent: readlineEvt}
		}
	}()

	// Create Event from bpf perf event and Handle it
	var event perfEvent
	for {
		event = <-eventChan
		switch event.eventType {
		case EVENT_TYPE_EXIT:
			end <- true
			return
		case EVENT_TYPE_CMD:
			readlineEvent_Handle(event.readlineEvent)
			continue
		}
	}
}

func readlineEvent_Handle(bpfEvent bpfReadlineEvent) {
	event := helper.ShellReadlineEvent{}
	event.PID = bpfEvent.Pid
	event.UID = bpfEvent.Uid
	event.CMD = unix.ByteSliceToString(bpfEvent.Line[:])

	logger.LogEvent("SHELL_READLINE", int64(bpfEvent.Timestamp), event)

	// jsonBytes, err := json.Marshal(&event)
	// if err != nil {
	// 	log.Fatalf("Failed marshal object: %s", err)
	// }
	// logger.WriteOutput(1, jsonBytes)
	// log.Printf("READLINE: %s\n", unix.ByteSliceToString(jsonBytes))
}

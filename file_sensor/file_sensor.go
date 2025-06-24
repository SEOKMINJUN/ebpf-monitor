package file_sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf bpf.c -- -I../include

import (
	"bytes"
	"ebpf-monitor/helper"
	"ebpf-monitor/logger"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	EVENT_TYPE_EXIT      = -1
	EVENT_TYPE_FILE_OPEN = 0
)

type ringEvent struct {
	eventType int32
	openEvent bpfFileOpenEvent
}

func FileSensorStart(end chan bool) {
	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("do_sys_openat2", objs.KprobeDoSysOpenat2, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		termSignal := helper.GlobalBroker.Subscribe()
		<-termSignal

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	eventChan := make(chan ringEvent)
	go func() {
		var event bpfFileOpenEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting file sensor..")
					eventChan <- ringEvent{eventType: EVENT_TYPE_EXIT}
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			eventChan <- ringEvent{eventType: EVENT_TYPE_FILE_OPEN, openEvent: event}
			// log.Printf("OPEN:: pid: %d, filename = %s, flag = %d, mode = %d\n", event.Pid, unix.ByteSliceToString(event.Name[:]), event.Flags, event.Mode)
		}
	}()

	var event ringEvent
	for {
		event = <-eventChan
		switch event.eventType {
		case EVENT_TYPE_EXIT:
			log.Println("Exiting file sensor..")
			end <- true
			return
		case EVENT_TYPE_FILE_OPEN:
			fileOpenEvent_Handle(event.openEvent)
			continue
		}
	}
}

func fileOpenEvent_Handle(bpfEvent bpfFileOpenEvent) {
	event := helper.FileOpenEvent{}
	event.PID = bpfEvent.Pid
	event.UID = bpfEvent.Uid
	event.FNAME = unix.ByteSliceToString(bpfEvent.Name[:])
	event.FLAGS = bpfEvent.Flags
	event.MODE = bpfEvent.Mode

	logger.LogEvent("FILE_OPEN", int64(bpfEvent.Timestamp), event)
	// jsonBytes, err := json.Marshal(&event)
	// if err != nil {
	// 	log.Fatalf("Failed marshal object: %s", err)
	// }
	// logger.WriteOutput(0, jsonBytes)
	// log.Printf("FILE_OPEN: %s\n", unix.ByteSliceToString(jsonBytes))
}

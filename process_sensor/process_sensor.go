package process_sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf bpf.c -- -I../include -g

import (
	"bytes"
	"ebpf-monitor/logger"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type processCreateEvent struct {
	TYPE      string
	TIMESTAMP string   `json:"timestamp"`
	PID       uint32   `json:"pid"`
	UID       uint32   `json:"uid"`
	NAME      string   `json:"name"`
	ARGV      []string `json:"argv"`
	ENVP      []string `json:"envp"`
	FLAGS     uint32   `json:"flags"`
	PPID      uint32   `json:"ppid"`
	PCMD      string   `json:"pcmd"`
}

type processTerminateEvent struct {
	TYPE       string
	TIMESTAMP  string `json:"timestamp"`
	PID        uint32 `json:"pid"`
	UID        uint32 `json:"uid"`
	PPID       uint32 `json:"ppid"`
	PCMD       string `json:"pcmd"`
	RETURNCODE uint32 `json:"returncode"`
}

const (
	EVENT_TYPE_EXIT           = -1
	EVENT_TYPE_PROC_CREATE    = 0
	EVENT_TYPE_PROC_TERMINATE = 1
)

type ringEvent struct {
	eventType      int32
	createEvent    bpfCreateEvent
	terminateEvent bpfTerminateEvent
}

func ProcessSensorStart(termSignal chan os.Signal, end chan bool) {
	// Load pre-compiled bpf programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// link kprobe to bpf program
	// do_execveat_common.isra.0 can be found on /proc/kallsyms
	kp, err := link.Kprobe("do_execveat_common.isra.0", objs.KprobeDoExecveatCommon, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// create RingBuffer reader for do_execveat_common
	createRingReader, err := ringbuf.NewReader(objs.CreateRingBuffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer createRingReader.Close()

	// link kprobe to bpf program
	lk, err := link.Tracepoint("sched", "sched_process_exit", objs.TpProcessExit, nil)
	if err != nil {
		log.Fatalf("linking tracepoint: %s", err)
	}
	defer lk.Close()

	// create RingBuffer reader for do_execveat_common
	terminateRingReader, err := ringbuf.NewReader(objs.TerminateRingBuffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer createRingReader.Close()

	eventChan := make(chan ringEvent)

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-termSignal

		if err := createRingReader.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
		if err := terminateRingReader.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}

		eventChan <- ringEvent{eventType: EVENT_TYPE_EXIT}
	}()

	log.Println("Waiting for events..")

	//Receive events from ringBuffer
	go func() {
		var createEvent bpfCreateEvent
		for {
			record, err := createRingReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting process sensor..")
					eventChan <- ringEvent{eventType: EVENT_TYPE_EXIT}
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &createEvent); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			eventChan <- ringEvent{eventType: EVENT_TYPE_PROC_CREATE, createEvent: createEvent}
		}
	}()
	go func() {
		var terminateEvent bpfTerminateEvent
		for {
			record, err := terminateRingReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting process sensor..")
					eventChan <- ringEvent{eventType: EVENT_TYPE_EXIT}
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &terminateEvent); err != nil {
				log.Printf("parsing ringbuf event: %s", err)
				continue
			}

			eventChan <- ringEvent{eventType: EVENT_TYPE_PROC_TERMINATE, terminateEvent: terminateEvent}
		}
	}()

	// Create Event from bpf ringBuffer and Handle it
	var event ringEvent
	for {
		event = <-eventChan
		switch event.eventType {
		case EVENT_TYPE_EXIT:
			end <- true
			return
		case EVENT_TYPE_PROC_CREATE:
			processCreateEvent := processCreateEvent_Create(event.createEvent)
			processCreateEvent_Handle(processCreateEvent)
			continue
		case EVENT_TYPE_PROC_TERMINATE:
			processTerminateEvent := processTerminateEvent_Create(event.terminateEvent)
			processTerminateEvent_Handle(processTerminateEvent)
			continue
		}
	}
}

func processCreateEvent_Create(bpfEvent bpfCreateEvent) processCreateEvent {
	event := processCreateEvent{
		TYPE:      "PROC_CREATE",
		TIMESTAMP: time.Unix(int64(bpfEvent.Timestamp), 0).Format(time.RFC3339Nano),
		PID:       bpfEvent.Pid,
		UID:       bpfEvent.Uid,
		FLAGS:     bpfEvent.Flags,
		NAME:      unix.ByteSliceToString(bpfEvent.Name[:]),
		PPID:      bpfEvent.Ppid,
		PCMD:      unix.ByteSliceToString(bpfEvent.Comm[:]),
	}
	for _, bytes := range bpfEvent.Argv {
		if bytes[0] == 0 {
			break
		}
		event.ARGV = append(event.ARGV, unix.ByteSliceToString(bytes[:]))
	}

	for _, bytes := range bpfEvent.Envp {
		if bytes[0] == 0 {
			break
		}
		event.ENVP = append(event.ENVP, unix.ByteSliceToString(bytes[:]))
	}
	return event
}

func processCreateEvent_Handle(event processCreateEvent) {
	jsonBytes, err := json.Marshal(&event)
	if err != nil {
		log.Fatalf("Failed marshal object: %s", err)
	}
	logger.WriteOutput(1, jsonBytes)
	log.Printf("PROCESS_CREATE: %s\n", unix.ByteSliceToString(jsonBytes))
}

func processTerminateEvent_Create(bpfEvent bpfTerminateEvent) processTerminateEvent {
	event := processTerminateEvent{
		TYPE:       "PROC_TERM",
		TIMESTAMP:  time.Unix(int64(bpfEvent.Timestamp), 0).Format(time.RFC3339Nano),
		PID:        bpfEvent.Pid,
		UID:        bpfEvent.Uid,
		RETURNCODE: bpfEvent.Code,
		PPID:       bpfEvent.Ppid,
		PCMD:       unix.ByteSliceToString(bpfEvent.Comm[:]),
	}

	return event
}

func processTerminateEvent_Handle(event processTerminateEvent) {
	jsonBytes, err := json.Marshal(&event)
	if err != nil {
		log.Fatalf("Failed marshal object: %s", err)
	}
	logger.WriteOutput(2, jsonBytes)
	log.Printf("PROCESS_TERM: %s\n", unix.ByteSliceToString(jsonBytes))
}

package process_sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf bpf.c -- -I../include -g

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

type processCreateEvent struct {
	pid   uint32
	uid   uint32
	name  string
	argv  []string
	envp  []string
	flags uint32
	ppid  uint32
	pcmd  string
}

type processTerminateEvent struct {
	pid  uint32
	uid  uint32
	ppid uint32
	pcmd string
	code uint32
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

// TODO : add prefix to log
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
	kp2, err := link.Kprobe("do_exit", objs.KprobeDoExit, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp2.Close()

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
		pid:   bpfEvent.Pid,
		uid:   bpfEvent.Uid,
		flags: bpfEvent.Flags,
		name:  unix.ByteSliceToString(bpfEvent.Name[:]),
		ppid:  bpfEvent.Ppid,
		pcmd:  unix.ByteSliceToString(bpfEvent.Comm[:]),
	}
	for _, bytes := range bpfEvent.Argv {
		if bytes[0] == 0 {
			break
		}
		event.argv = append(event.argv, unix.ByteSliceToString(bytes[:]))
	}

	for _, bytes := range bpfEvent.Envp {
		if bytes[0] == 0 {
			break
		}
		event.envp = append(event.envp, unix.ByteSliceToString(bytes[:]))
	}
	return event
}

func processCreateEvent_Handle(event processCreateEvent) {
	log.Printf("PROCESS_CREATE: pid: %d\t uid: %d\t ppid: %d\tflags: %d\t pcmd = %s\t\t filename = %s\t\t\t\t argv = %s\t envp = %s\n",
		event.pid, event.uid, event.ppid, event.flags, event.pcmd, event.name, strings.Join(event.argv, " "), strings.Join(event.envp, " "))
}

func processTerminateEvent_Create(bpfEvent bpfTerminateEvent) processTerminateEvent {
	event := processTerminateEvent{
		pid:  bpfEvent.Pid,
		uid:  bpfEvent.Uid,
		code: bpfEvent.Code,
		ppid: bpfEvent.Ppid,
		pcmd: unix.ByteSliceToString(bpfEvent.Comm[:]),
	}

	return event
}

func processTerminateEvent_Handle(event processTerminateEvent) {
	log.Printf("PROCESS_TERM: pid: %d\t uid: %d\t ppid: %d\t code: %d\t pcmd: %s\n",
		event.pid, event.uid, event.ppid, event.code, event.pcmd)
}

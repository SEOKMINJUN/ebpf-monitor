package tcp_sensor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf bpf.c -- -I../include -g

import (
	"bytes"
	"ebpf-monitor/helper"
	"ebpf-monitor/logger"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type tcpConnectEvent struct {
	TYPE      string
	TIMESTAMP uint64
	PID       uint32
	UID       uint32
	FAMILY    uint16
	SADDR     uint32
	SPORT     uint16
	DADDR     uint32
	DPORT     uint16
}

const (
	EVENT_TYPE_EXIT        = -1
	EVENT_TYPE_TCP_CONNECT = 0
)

type ringEvent struct {
	eventType   int32
	createEvent bpfAcceptEvent
}

func inet_ntoa(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF)
}

func TcpSensorStart(termSignal chan os.Signal, end chan bool) {
	// Load pre-compiled bpf programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// link kprobe to bpf program
	// kp, err := link.Kprobe("sys_accept", objs.KprobeSysAccept, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer kp.Close()
	// krp, err := link.Kretprobe("sys_accept", objs.KretprobeSysAccept, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer krp.Close()

	// kp2, err := link.Kprobe("sys_accept4", objs.KprobeSysAccept4, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer kp2.Close()
	// krp2, err := link.Kretprobe("sys_accept4", objs.KretprobeSysAccept4, nil)
	// if err != nil {
	// 	log.Fatalf("opening kprobe: %s", err)
	// }
	// defer krp2.Close()

	kp3, err := link.Kprobe("tcp_v4_connect", objs.KprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp3.Close()
	krp3, err := link.Kretprobe("tcp_v4_connect", objs.KretprobeTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer krp3.Close()

	// create RingBuffer reader for do_execveat_common
	rd, err := ringbuf.NewReader(objs.AcceptRingBuffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	eventChan := make(chan ringEvent)

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-termSignal

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}

		eventChan <- ringEvent{eventType: EVENT_TYPE_EXIT}
	}()

	log.Println("Waiting for events..")

	//Receive events from ringBuffer
	go func() {
		var createEvent bpfAcceptEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting tcp sensor..")
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

			eventChan <- ringEvent{eventType: EVENT_TYPE_TCP_CONNECT, createEvent: createEvent}
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
		case EVENT_TYPE_TCP_CONNECT:
			tcpConnectEvent_Handle(event.createEvent)
			continue
		}
	}
}

func tcpConnectEvent_Handle(bpfEvent bpfAcceptEvent) {
	event := helper.TcpConnectEvent{}
	event.PID = bpfEvent.Pid
	event.UID = bpfEvent.Uid
	event.FAMILY = bpfEvent.Family
	event.SADDR = bpfEvent.SrcAddr
	event.SPORT = bpfEvent.SrcPort
	event.DADDR = bpfEvent.DestAddr
	event.DPORT = bpfEvent.DestPort

	logger.LogEvent("TCP_CONNECT", int64(bpfEvent.Timestamp), event)

	// jsonBytes, err := json.Marshal(&event)
	// if err != nil {
	// 	log.Fatalf("Failed marshal object: %s", err)
	// }
	// logger.WriteOutput(3, jsonBytes)
	// log.Printf("TCP_CONNECT: %s\n", unix.ByteSliceToString(jsonBytes))
}

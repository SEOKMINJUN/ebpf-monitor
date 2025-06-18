package helper

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type basicInfo struct {
	PID uint32 `json:"pid"`
	UID uint32 `json:"uid"`
}

type processInfo struct {
	PNAME string   `json:"name"`
	ARGV  []string `json:"args"`
	ENVP  []string `json:"envp"`
	FLAGS uint32   `json:"flags"`
}

type fileInfo struct {
	FNAME string `json:"name"`
	FLAGS uint32 `json:"flags"`
	MODE  uint16 `json:"mode"`
}

type tcpInfo struct {
	FAMILY uint16 `json:"FAMILY"`
	SADDR  uint32 `json:"SADDR"`
	SPORT  uint16 `json:"SPORT"`
	DADDR  uint32 `json:"DADDR"`
	DPORT  uint16 `json:"DPORT"`
}

type TcpConnectEvent struct {
	basicInfo
	tcpInfo
}

type FileOpenEvent struct {
	basicInfo
	fileInfo
}

type ProcessCreateEvent struct {
	basicInfo
	processInfo
	PPID uint32 `json:"ppid"`
	PCMD string `json:"pcmd"`
}

type ProcessTerminateEvent struct {
	basicInfo
	PPID       uint32 `json:"ppid"`
	PCMD       string `json:"pcmd"`
	RETURNCODE uint32 `json:"returncode"`
}

type ShellReadlineEvent struct {
	basicInfo
	CMD string `json:"cmd"`
}

type basicEvent struct {
	TYPE      string `json:"type"`
	TIMESTAMP string `json:"timestamp"`
}

type Event struct {
	basicEvent
	Data interface{}
}

func (u *Event) SetInfo(eventType string, timestamp int64, obj interface{}) {
	u.TYPE = eventType
	u.TIMESTAMP = time.Unix(timestamp, 0).Format(time.RFC3339Nano)
	u.Data = obj
}

// Create Otel Trace span for each event
func (u *Event) Handle() {
	context := context.Background()
	tracer := otel.Tracer("event-tracer")
	switch u.TYPE {
	//Process
	case "PROC_CREATE":
		ctx, span := tracer.Start(context, "Process")
		span.SetAttributes(attribute.String("event.type", "PROC_CREATE"))
		AddPid(u.Data.(ProcessCreateEvent).PID, ctx)
		// fmt
	case "PROC_TERM":
		ctx, ok := GetContextByPid(u.Data.(ProcessTerminateEvent).PID)
		if !ok {
			return
		}
		defer DeletePid(u.Data.(ProcessTerminateEvent).PID)
		span := trace.SpanFromContext(ctx)
		if span != nil {
			span.SetAttributes(attribute.String("event.type", "PROC_TERM"))
			span.End()
		}

	//File
	case "FILE_OPEN":
		ctx, ok := GetContextByPid(u.Data.(FileOpenEvent).PID)
		if !ok {
			return
		}
		span := trace.SpanFromContext(ctx)
		if span != nil {
			_, childSpan := tracer.Start(ctx, "File Open")
			childSpan.SetAttributes(attribute.String("event.type", "FILE_OPEN"))
			childSpan.End()
		}
	//TCP
	case "TCP_CONNECT":
		ctx, ok := GetContextByPid(u.Data.(TcpConnectEvent).PID)
		if !ok {
			return
		}
		span := trace.SpanFromContext(ctx)
		if span != nil {
			_, childSpan := tracer.Start(ctx, "Tcp Connect")
			childSpan.SetAttributes(attribute.String("event.type", "TCP_CONNECT"))
			childSpan.End()
		}
	//Shell
	case "SHELL_READLINE":
		ctx, ok := GetContextByPid(u.Data.(ShellReadlineEvent).PID)
		if !ok {
			return
		}
		span := trace.SpanFromContext(ctx)
		if span != nil {
			_, childSpan := tracer.Start(ctx, "Shell Readline")
			childSpan.SetAttributes(attribute.String("event.type", "SHELL_READLINE"))
			childSpan.End()
		}
	}
}

// func (u *basicInfo) SetProcessInfo(proc basicInfo) {
// 	u.PID = proc.PID
// 	u.UID = proc.UID
// }

// func (u *FileOpenEvent) CreateFileOpenEvent(PID uint32, UID uint32, FNAME string, FLAGS uint, MODE uint) {
// 	u.PID = PID
// 	u.UID = UID
// }

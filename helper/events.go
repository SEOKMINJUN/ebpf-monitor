package helper

import (
	"context"
	"strings"
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
	SADDR  string `json:"SADDR"`
	SPORT  uint16 `json:"SPORT"`
	DADDR  string `json:"DADDR"`
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
	tracer := otel.Tracer("event-tracer")
	switch u.TYPE {
	//Process
	case "PROC_CREATE":
		data := u.Data.(ProcessCreateEvent)
		ctx, ok := GetContextByPid(data.PPID)
		var span trace.Span
		switch ok {
		case true:
			ctx, span = tracer.Start(ctx, "Process "+data.PNAME)
		case false:
			ctx, span = tracer.Start(context.Background(), "Process "+data.PNAME)
		}

		span.SetAttributes(attribute.Int("pid", (int)(data.PID)))
		span.SetAttributes(attribute.Int("uid", (int)(data.UID)))
		span.SetAttributes(attribute.Int("ppid", (int)(data.PPID)))
		span.SetAttributes(attribute.String("pcmd", data.PCMD))
		span.SetAttributes(attribute.String("name", data.PNAME))
		span.SetAttributes(attribute.String("argv", "{\""+strings.Join(data.ARGV, "\", \"")+"\"}"))
		span.SetAttributes(attribute.String("envp", "{\""+strings.Join(data.ENVP, "\", \"")+"\"}"))
		span.SetAttributes(attribute.Int("flags", (int)(data.FLAGS)))

		AddPid(data.PID, ctx)
		// fmt
	case "PROC_TERM":
		data := u.Data.(ProcessTerminateEvent)
		ctx, ok := GetContextByPid(data.PID)
		if !ok {
			return
		}
		defer DeletePid(data.PID)
		span := trace.SpanFromContext(ctx)
		if span != nil {
			span.SetAttributes(attribute.Int("returncode", (int)(data.RETURNCODE)))
			span.End()
		}

	//File
	case "FILE_OPEN":
		data := u.Data.(FileOpenEvent)
		ctx, ok := GetContextByPid(data.PID)
		if !ok {
			return
		}
		span := trace.SpanFromContext(ctx)
		if span != nil {
			span.AddEvent("File Open "+data.FNAME,
				trace.WithAttributes(attribute.String("filename", data.FNAME)),
				trace.WithAttributes(attribute.Int("flags", (int)(data.FLAGS))),
				trace.WithAttributes(attribute.Int("mode", (int)(data.MODE))),
			)
		}
	//TCP
	case "TCP_CONNECT":
		data := u.Data.(TcpConnectEvent)
		ctx, ok := GetContextByPid(data.PID)
		if !ok {
			return
		}
		span := trace.SpanFromContext(ctx)
		if span != nil {
			span.AddEvent("Tcp Connect",
				trace.WithAttributes(attribute.Int("family", (int)(data.FAMILY))),
				trace.WithAttributes(attribute.String("Source IP", data.SADDR)),
				trace.WithAttributes(attribute.Int("Source Port", (int)(data.SPORT))),
				trace.WithAttributes(attribute.String("Dest IP", data.DADDR)),
				trace.WithAttributes(attribute.Int("Dest Port", (int)(data.DPORT))),
			)
		}
	//Shell
	case "SHELL_READLINE":
		data := u.Data.(ShellReadlineEvent)
		ctx, ok := GetContextByPid(data.PID)
		if !ok {
			return
		}
		span := trace.SpanFromContext(ctx)
		if span != nil {
			span.AddEvent("Shell Readline",
				trace.WithAttributes(attribute.String("Command", data.CMD)),
			)
		}
	}
}

package helper

import (
	"context"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
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
	TYPE      string    `json:"type"`
	TIMESTAMP time.Time `json:"timestamp"`
}

type Event struct {
	basicEvent
	Data interface{}
}

func (u *Event) SetInfo(eventType string, timestamp int64, obj interface{}) {
	u.TYPE = eventType
	u.TIMESTAMP = time.Unix(0, ConvertMonotonicTimeToRealTime(timestamp))
	u.Data = obj
}

// Create Otel Trace span for each event
func (u *Event) Handle() {
	switch u.TYPE {
	//Process
	case "PROC_CREATE":
		data := u.Data.(ProcessCreateEvent)
		ctx, ok := GetContextByPid(data.PPID)
		var span trace.Span
		switch ok {
		case true:
			ctx, span = Tracer.Start(ctx, "Process "+data.PNAME, trace.WithTimestamp(u.TIMESTAMP))
		case false:
			ctx, span = Tracer.Start(context.Background(), "Process "+data.PNAME)
		}
		ARG_STR := "{\"" + strings.Join(data.ARGV, "\", \"") + "\"}"
		ENV_STR := "{\"" + strings.Join(data.ENVP, "\", \"") + "\"}"

		span.SetAttributes(attribute.Int("pid", (int)(data.PID)))
		span.SetAttributes(attribute.Int("uid", (int)(data.UID)))
		span.SetAttributes(attribute.Int("ppid", (int)(data.PPID)))
		span.SetAttributes(attribute.String("pcmd", data.PCMD))
		span.SetAttributes(attribute.String("name", data.PNAME))
		span.SetAttributes(attribute.String("argv", ARG_STR))
		span.SetAttributes(attribute.String("envp", ENV_STR))
		span.SetAttributes(attribute.Int("flags", (int)(data.FLAGS)))

		AddPid(data.PID, ctx)

		TraceID := span.SpanContext().TraceID().String()
		SpanID := span.SpanContext().SpanID().String()

		record := log.Record{}
		record.SetEventName("Process")
		record.SetSeverity(log.SeverityInfo)
		record.SetBody(log.StringValue("created"))
		record.AddAttributes(
			log.Int("pid", (int)(data.PID)),
			log.Int("uid", (int)(data.UID)),
			log.Int("ppid", (int)(data.PPID)),
			log.String("pcmd", data.PCMD),
			log.String("name", data.PNAME),
			log.String("argv", ARG_STR),
			log.String("envp", ENV_STR),
			log.Int("flags", (int)(data.FLAGS)),
			log.String("TraceID", TraceID),
			log.String("SpanID", SpanID),
		)
		Logger.Emit(ctx, record)
	case "PROC_TERM":
		data := u.Data.(ProcessTerminateEvent)
		ctx, ok := GetContextByPid(data.PID)
		if ok {
			defer DeletePid(data.PID)
			span := trace.SpanFromContext(ctx)
			if span != nil {
				span.SetAttributes(attribute.Int("returncode", (int)(data.RETURNCODE)))
				span.End(trace.WithTimestamp(u.TIMESTAMP))
			}
		}

		var TraceID string
		var SpanID string
		if ok {
			span := trace.SpanFromContext(ctx)
			TraceID = span.SpanContext().TraceID().String()
			SpanID = span.SpanContext().SpanID().String()
		} else {
			TraceID = ""
			SpanID = ""
		}

		record := log.Record{}
		record.SetEventName("Process")
		record.SetSeverity(log.SeverityInfo)
		record.SetBody(log.StringValue("terminated"))
		record.AddAttributes(
			log.Int("returncode", (int)(data.RETURNCODE)),
			log.String("TraceID", TraceID),
			log.String("SpanID", SpanID),
		)
		Logger.Emit(ctx, record)

	//File
	case "FILE_OPEN":
		data := u.Data.(FileOpenEvent)
		ctx, ok := GetContextByPid(data.PID)
		if ok {
			span := trace.SpanFromContext(ctx)
			if span != nil {
				span.AddEvent("File Open",
					trace.WithAttributes(attribute.String("filename", data.FNAME)),
					trace.WithAttributes(attribute.Int("flags", (int)(data.FLAGS))),
					trace.WithAttributes(attribute.Int("mode", (int)(data.MODE))),
				)
			}
		}

		var TraceID string
		var SpanID string
		if ok {
			span := trace.SpanFromContext(ctx)
			TraceID = span.SpanContext().TraceID().String()
			SpanID = span.SpanContext().SpanID().String()
		} else {
			TraceID = ""
			SpanID = ""
		}

		record := log.Record{}
		record.SetEventName("File")
		record.SetSeverity(log.SeverityInfo)
		record.SetBody(log.StringValue("Open"))
		record.AddAttributes(
			log.String("filename", data.FNAME),
			log.Int("flags", (int)(data.FLAGS)),
			log.Int("mode", (int)(data.MODE)),
			log.String("TraceID", TraceID),
			log.String("SpanID", SpanID),
		)
		Logger.Emit(ctx, record)
	//TCP
	case "TCP_CONNECT":
		data := u.Data.(TcpConnectEvent)
		ctx, ok := GetContextByPid(data.PID)
		if ok {
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
		}

		var TraceID string
		var SpanID string
		if ok {
			span := trace.SpanFromContext(ctx)
			TraceID = span.SpanContext().TraceID().String()
			SpanID = span.SpanContext().SpanID().String()
		} else {
			TraceID = ""
			SpanID = ""
		}

		record := log.Record{}
		record.SetEventName("Tcp")
		record.SetSeverity(log.SeverityInfo)
		record.SetBody(log.StringValue("Connect"))
		record.AddAttributes(
			log.Int("family", (int)(data.FAMILY)),
			log.String("Source IP", data.SADDR),
			log.Int("Source Port", (int)(data.SPORT)),
			log.String("Dest IP", data.DADDR),
			log.Int("Dest Port", (int)(data.DPORT)),
			log.String("TraceID", TraceID),
			log.String("SpanID", SpanID),
		)
		Logger.Emit(ctx, record)
	//Shell
	case "SHELL_READLINE":
		data := u.Data.(ShellReadlineEvent)
		ctx, ok := GetContextByPid(data.PID)
		if ok {
			span := trace.SpanFromContext(ctx)
			if span != nil {
				span.AddEvent("Shell Readline",
					trace.WithAttributes(attribute.String("Command", data.CMD)),
				)
			}
		}

		var TraceID string
		var SpanID string
		if ok {
			span := trace.SpanFromContext(ctx)
			TraceID = span.SpanContext().TraceID().String()
			SpanID = span.SpanContext().SpanID().String()
		} else {
			TraceID = ""
			SpanID = ""
		}

		record := log.Record{}
		record.SetEventName("Shell")
		record.SetSeverity(log.SeverityInfo)
		record.SetBody(log.StringValue("Readline"))
		record.AddAttributes(log.String("Command", data.CMD),
			log.String("TraceID", TraceID),
			log.String("SpanID", SpanID))
		Logger.Emit(ctx, record)
	}

}

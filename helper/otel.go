package helper

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.32.0"
	"go.opentelemetry.io/otel/trace"
)

var SERVICE_NAME string = "ebpf-monitor"
var SERVICE_VERSION string = "0.0.0"
var Logger otellog.Logger
var Tracer trace.Tracer

func InitTracer() {
	ctx := context.Background()
	client := otlptracegrpc.NewClient(otlptracegrpc.WithInsecure())
	exporter, err := otlptrace.New(ctx, client)

	if err != nil {
		log.Fatalf("failed to initialize exporter: %e", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(SERVICE_NAME),
			semconv.ServiceVersion(SERVICE_VERSION),
		),
	)
	if err != nil {
		log.Fatalf("failed to initialize resource: %e", err)
	}

	// Create the trace provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	// Set the global trace provider
	otel.SetTracerProvider(tp)

	// Log export
	logExporter, err := otlploghttp.New(ctx, otlploghttp.WithInsecure())
	if err != nil {
		panic("failed to initialize exporter")
	}

	// Create the logger provider
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(
			sdklog.NewBatchProcessor(logExporter),
		),
		sdklog.WithResource(res),
	)

	// Set the logger provider globally
	global.SetLoggerProvider(lp)

	// Set the propagator
	propagator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	otel.SetTextMapPropagator(propagator)

	Tracer = otel.Tracer("EVENT")
	Logger = global.GetLoggerProvider().Logger("EVENT-LOGGER")

	go func() {
		termSignal := GlobalBroker.Subscribe()
		<-termSignal

		if err := lp.Shutdown(ctx); err != nil {
			log.Fatalf("failed to shutdown logger provider: %e", err)
		}
		if err := tp.Shutdown(ctx); err != nil {
			log.Fatalf("failed to shutdown trace provider: %e", err)
		}
	}()
}

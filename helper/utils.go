package helper

import (
	"context"
	"log"
	"reflect"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var processMap map[uint32]context.Context = make(map[uint32]context.Context)
var mutex sync.RWMutex

func StructToMap(structObj interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	objValue := reflect.ValueOf(structObj)
	if objValue.Kind() == reflect.Ptr {
		objValue = objValue.Elem()
	}

	objType := objValue.Type()
	for i := 0; i < objValue.NumField(); i++ {
		fieldName := objType.Field(i).Name
		fieldValueKind := objValue.Field(i).Kind()
		var fieldValue interface{}
		if fieldValueKind == reflect.Struct {
			fieldValue = StructToMap(objValue.Field(i).Interface())
		} else {
			fieldValue = objValue.Field(i).Interface()
		}
		result[fieldName] = fieldValue
	}

	return result
}

func AddPid(pid uint32, ctx context.Context) {
	mutex.Lock()
	defer mutex.Unlock()

	processMap[pid] = ctx
}

func DeletePid(pid uint32) {
	mutex.Lock()
	defer mutex.Unlock()

	delete(processMap, pid)
}

func GetContextByPid(pid uint32) (context.Context, bool) {
	mutex.RLock()
	defer mutex.RUnlock()

	ctx, exist := processMap[pid]
	if !exist {
		return nil, false
	}
	return ctx, true
}

func InitTracer() {
	ctx := context.Background()
	client := otlptracegrpc.NewClient(otlptracegrpc.WithInsecure())
	exporter, err := otlptrace.New(ctx, client)

	if err != nil {
		log.Fatalf("failed to initialize exporter: %e", err)
	}

	res, err := resource.New(ctx)
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

	// Set the propagator
	propagator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	otel.SetTextMapPropagator(propagator)
}

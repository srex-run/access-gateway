package observability

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

type TracingConfig struct {
	ServiceName  string
	OTLPEndpoint string
}

func ConfigureTracing(ctx context.Context, config TracingConfig) (func(context.Context) error, error) {
	config.ServiceName = strings.TrimSpace(config.ServiceName)
	if config.ServiceName == "" {
		config.ServiceName = "access-gateway"
	}
	serviceResource, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceName(config.ServiceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("build tracing resource: %w", err)
	}
	options := []sdktrace.TracerProviderOption{sdktrace.WithResource(serviceResource)}
	if strings.TrimSpace(config.OTLPEndpoint) != "" {
		exporter, exporterErr := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(strings.TrimSpace(config.OTLPEndpoint)))
		if exporterErr != nil {
			return nil, fmt.Errorf("configure OTLP trace exporter: %w", exporterErr)
		}
		options = append(options, sdktrace.WithBatcher(exporter))
	}
	provider := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return provider.Shutdown, nil
}

package logger

import (
	"context"

	"go.opentelemetry.io/otel/log"
)

func Debug(ctx context.Context, logger log.Logger, msg string, attrs ...log.KeyValue) {
	record := log.Record{}
	record.SetSeverity(log.SeverityDebug)
	record.SetBody(log.StringValue(msg))
	if len(attrs) > 0 {
		record.AddAttributes(attrs...)
	}
	logger.Emit(ctx, record)
}

// Info emits an info log using OpenTelemetry logging
func Info(ctx context.Context, logger log.Logger, msg string, attrs ...log.KeyValue) {
	record := log.Record{}
	record.SetSeverity(log.SeverityInfo)
	record.SetBody(log.StringValue(msg))
	if len(attrs) > 0 {
		record.AddAttributes(attrs...)
	}
	logger.Emit(ctx, record)
}

// Warn emits a warning log using OpenTelemetry logging
func Warn(ctx context.Context, logger log.Logger, msg string, attrs ...log.KeyValue) {
	record := log.Record{}
	record.SetSeverity(log.SeverityWarn)
	record.SetBody(log.StringValue(msg))
	if len(attrs) > 0 {
		record.AddAttributes(attrs...)
	}
	logger.Emit(ctx, record)
}

// Error emits an error log using OpenTelemetry logging
func Error(ctx context.Context, logger log.Logger, msg string, attrs ...log.KeyValue) {
	record := log.Record{}
	record.SetSeverity(log.SeverityError)
	record.SetBody(log.StringValue(msg))
	if len(attrs) > 0 {
		record.AddAttributes(attrs...)
	}
	logger.Emit(ctx, record)
}

// Helper functions to create log attributes
func String(key, value string) log.KeyValue {
	return log.KeyValue{Key: key, Value: log.StringValue(value)}
}

func Int(key string, value int) log.KeyValue {
	return log.KeyValue{Key: key, Value: log.Int64Value(int64(value))}
}

func Int64(key string, value int64) log.KeyValue {
	return log.KeyValue{Key: key, Value: log.Int64Value(value)}
}

func Float64(key string, value float64) log.KeyValue {
	return log.KeyValue{Key: key, Value: log.Float64Value(value)}
}

func Bool(key string, value bool) log.KeyValue {
	return log.KeyValue{Key: key, Value: log.BoolValue(value)}
}

func Err(err error) log.KeyValue {
	return log.KeyValue{Key: "error", Value: log.StringValue(err.Error())}
}

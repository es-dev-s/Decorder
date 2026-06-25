// Package observability provides structured JSON event logging for the relay.
package observability

import (
	"log/slog"
	"os"
	"time"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelInfo,
	ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Int64("ts", time.Now().UnixMilli())
		}
		return a
	},
}))

// Event writes a structured log line: level, ts (unix ms), component, event, + attrs.
func Event(component, event string, attrs ...any) {
	args := make([]any, 0, 2+len(attrs))
	args = append(args, "component", component, "event", event)
	args = append(args, attrs...)
	logger.Info(event, args...)
}

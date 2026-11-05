package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLevelsGoToTheirDesignatedStream(t *testing.T) {
	var out, err bytes.Buffer
	l := slog.New(newStreamHandler(&out, &err, slog.LevelDebug)).WithGroup("auth").With("app", "test")
	l.Debug("debug-message")
	l.Info("info-message")
	l.Warn("warn-message")
	l.Error("error-message")
	for _, tc := range []struct {
		value  string
		stdout bool
	}{{"debug-message", true}, {"info-message", true}, {"warn-message", false}, {"error-message", false}} {
		if strings.Contains(out.String(), tc.value) != tc.stdout || strings.Contains(err.String(), tc.value) == tc.stdout {
			t.Fatalf("wrong stream for %s", tc.value)
		}
	}
	if !strings.Contains(out.String(), "auth.app=test") || !strings.Contains(err.String(), "auth.app=test") {
		t.Fatal("attributes/groups lost")
	}
}

func TestStreamHandlerHonorsMinimumLogLevel(t *testing.T) {
	var out, err bytes.Buffer
	l := slog.New(newStreamHandler(&out, &err, slog.LevelError))
	l.Info("hidden")
	l.Warn("hidden")
	l.Error("visible")
	if out.Len() != 0 || strings.Contains(err.String(), "hidden") || !strings.Contains(err.String(), "visible") {
		t.Fatal("minimum log level was ignored")
	}
}

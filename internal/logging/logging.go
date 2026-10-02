// Package logging builds deckard's structured logger: JSON to stdout by
// default (12-factor), with secret-looking attribute values redacted.
package logging

import (
	"io"
	"log/slog"
	"strings"

	"github.com/chainseer-xyz/deckard/internal/config"
)

const redacted = "[REDACTED]"

var secretFragments = []string{"token", "password", "passwd", "secret", "api_key", "apikey", "authorization", "credential"}

// New returns a logger writing to w.
func New(cfg config.LogConfig, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(cfg.Level), ReplaceAttr: redact}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func redact(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	for _, frag := range secretFragments {
		if strings.Contains(key, frag) {
			return slog.String(a.Key, redacted)
		}
	}
	return a
}

package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/chainseer-xyz/deckard/internal/api"
	"github.com/chainseer-xyz/deckard/internal/engine"
)

func TestTranslateActionErr(t *testing.T) {
	other := errors.New("boom")
	cases := []struct {
		name string
		in   error
		want error // matched with errors.Is; nil means passthrough of `in`
	}{
		{"nil", nil, nil},
		{"unknown source", &engine.UnknownSourceError{Name: "x"}, api.ErrUnknownSource},
		{"wrapped unknown source", fmt.Errorf("sync: %w", &engine.UnknownSourceError{Name: "x"}), api.ErrUnknownSource},
		{"not scannable", fmt.Errorf("rescan asset 3: %w", engine.ErrNotScannable), api.ErrNotScannable},
		{"no queue", engine.ErrNoQueue, api.ErrNotSupported},
		{"anything else is left alone", other, other},
	}
	for _, c := range cases {
		got := translateActionErr(c.in)
		if c.in == nil {
			if got != nil {
				t.Errorf("%s: got %v", c.name, got)
			}
			continue
		}
		if !errors.Is(got, c.want) {
			t.Errorf("%s: %v does not match %v", c.name, got, c.want)
		}
		if !errors.Is(got, c.in) {
			t.Errorf("%s: the original error was lost from the chain", c.name)
		}
	}
	if errors.Is(translateActionErr(other), api.ErrUnknownSource) {
		t.Error("an unrelated error must not become a 404")
	}
}

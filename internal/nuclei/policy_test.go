package nuclei

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fixturePolicy(context.Context, []string) ([]string, error) {
	// Compiled fake binaries only use local fixtures, never operator targets.
	return []string{"192.0.2.0/24"}, nil
}

func TestDestinationPolicyRequiredAndFreshAfterGate(t *testing.T) {
	args := []string{"-u", "https://owned.example.com/"}
	if _, _, err := (ExecRunner{}).destinationArgs(context.Background(), args); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("missing policy = %v", err)
	}
	gate := NewProcessGate(1)
	release, err := gate.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 1)
	r := ExecRunner{Gate: gate, Policy: func(context.Context, []string) ([]string, error) {
		called <- struct{}{}
		return nil, errors.New("ownership revoked while waiting")
	}}
	done := make(chan error, 1)
	go func() {
		_, err := r.Run(context.Background(), "must-not-start", args)
		done <- err
	}()
	select {
	case <-called:
		t.Fatal("policy ran before acquiring the process slot")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	if err := <-done; !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("revoked policy = %v", err)
	}
}

func TestDestinationPolicyTargetListAndFiles(t *testing.T) {
	list := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(list, []byte("https://b.example.com/\nhttps://a.example.com/path\nhttps://b.example.com/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	r := ExecRunner{Policy: func(_ context.Context, hosts []string) ([]string, error) {
		got = hosts
		return []string{"0.0.0.0/1", "::/0"}, nil
	}}
	args, cleanup, err := r.destinationArgs(context.Background(), []string{"-l", list})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !reflect.DeepEqual(got, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("policy hosts = %v", got)
	}
	data, err := os.ReadFile(argAfter(args, "-eh"))
	if err != nil || string(data) != "0.0.0.0/1\n::/0\n" {
		t.Fatalf("deny file = %q, %v", data, err)
	}
	config := argAfter(args, "-config")
	data, err = os.ReadFile(config)
	if err != nil || strings.TrimSpace(string(data)) != "{}" {
		t.Fatalf("isolated config = %q, %v", data, err)
	}
	cleanup()
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("policy files survived cleanup: %v", err)
	}
}

func TestDestinationPolicyRejectsOverridesAndMalformedTargets(t *testing.T) {
	r := ExecRunner{Policy: fixturePolicy}
	for _, args := range [][]string{
		{"-u"}, {"-l"}, {"-u", "https://user:pass@example.com"},
		{"-u", "https://example.com", "-proxy", "http://localhost:8080"},
		{"-u", "https://example.com", "-config", "untrusted.yaml"},
		{"-u", "https://example.com", "-eh", "0.0.0.0/0"},
	} {
		if _, _, err := r.destinationArgs(context.Background(), args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}

func TestDestinationPolicyCanonicalTargetArguments(t *testing.T) {
	list := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(list, []byte("https://app.example.com/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-u=https://app.example.com/"}, {"--target=https://app.example.com/"},
		{"--u", "https://app.example.com/"}, {"--target", "https://app.example.com/"},
		{"-l=" + list}, {"--list=" + list}, {"--l", list}, {"--list", list},
	} {
		if _, _, err := (ExecRunner{}).destinationArgs(context.Background(), args); !errors.Is(err, ErrOutOfScope) {
			t.Errorf("target variant bypassed mandatory policy: %v: %v", args, err)
		}
		var got []string
		r := ExecRunner{Policy: func(_ context.Context, hosts []string) ([]string, error) {
			got = hosts
			return fixturePolicy(context.Background(), hosts)
		}}
		_, cleanup, err := r.destinationArgs(context.Background(), args)
		if err != nil {
			t.Fatalf("target variant %v: %v", args, err)
		}
		cleanup()
		if !reflect.DeepEqual(got, []string{"app.example.com"}) {
			t.Errorf("target variant %v hosts = %v", args, got)
		}
	}
}

func TestDestinationPolicyCanonicalOverrideArguments(t *testing.T) {
	r := ExecRunner{Policy: fixturePolicy}
	for _, name := range []string{"p", "proxy", "config", "eh", "exclude-hosts", "elog", "error-log", "tp", "profile", "resume", "targets-inline"} {
		for _, prefix := range []string{"-", "--"} {
			for _, override := range [][]string{{prefix + name, "value"}, {prefix + name + "=value"}} {
				args := append([]string{"-u", "https://app.example.com/"}, override...)
				if _, cleanup, err := r.destinationArgs(context.Background(), args); err == nil {
					cleanup()
					t.Errorf("accepted policy override %v", args)
				}
			}
		}
	}
}

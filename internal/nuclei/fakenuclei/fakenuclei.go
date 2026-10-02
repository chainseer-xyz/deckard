package fakenuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// Probe makes a template "vulnerable": the fake binary GETs target+Path with
// a real HTTP request and reports a match when the status is 200 and the body
// contains Contains.
type Probe struct {
	TemplateID string `json:"template_id"`
	Path       string `json:"path"`
	Contains   string `json:"contains"`
}

// Conf scripts the fake binary. It is read from "<binary>.json" on every call,
// so a test can change it between calls (for example to publish a new release).
type Conf struct {
	// Version is the templates version written on -ut (default v1.0.0).
	Version string `json:"version,omitempty"`
	// Tree is copied into the -ud directory on -ut.
	Tree string `json:"tree,omitempty"`
	// NewAdditions is written to .new-additions on -ut.
	NewAdditions []string `json:"new_additions,omitempty"`
	// UpdateFail makes -ut exit 1 with this message.
	UpdateFail string `json:"update_fail,omitempty"`
	// Escape adds a symlink that points outside the tree on -ut.
	Escape bool `json:"escape,omitempty"`
	// Probes decide which templates match which targets on a scan.
	Probes []Probe `json:"probes,omitempty"`
	// Record is the JSONL file every invocation appends a Call to.
	Record string `json:"record,omitempty"`
	// ScanExit is the exit status of a scan (after emitting its matches).
	ScanExit int `json:"scan_exit,omitempty"`
	// ScanSleepMs delays a scan, for timeout tests.
	ScanSleepMs int `json:"scan_sleep_ms,omitempty"`
}

// Call is one recorded invocation.
type Call struct {
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Targets []string          `json:"targets,omitempty"` // contents of -l files and -u values
	// Templates are the template paths a scan was handed: the lines of a -t list
	// file (*.txt) or the -t values themselves.
	Templates []string `json:"templates,omitempty"`
}

// Binary is an installed fake nuclei.
type Binary struct {
	Path string
	tb   testing.TB
	conf Conf
}

var (
	buildOnce sync.Once
	builtPath string
	buildErr  error
)

func build() (string, error) {
	buildOnce.Do(func() {
		_, file, _, _ := runtime.Caller(0)
		dir, err := os.MkdirTemp("", "fakenuclei-build-")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "fakenuclei")
		cmd := exec.Command("go", "build", "-o", out, "./cmd/fakenuclei") // #nosec G204 -- fixed args, test support
		cmd.Dir = filepath.Dir(file)
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErr = &buildError{err: err, out: string(b)}
			return
		}
		builtPath = out
	})
	return builtPath, buildErr
}

type buildError struct {
	err error
	out string
}

func (e *buildError) Error() string { return "build fakenuclei: " + e.err.Error() + ": " + e.out }

// Install copies the fake binary into a fresh temp dir, writes conf next to
// it and returns it. The Record path defaults to "<binary>.calls".
// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func Install(tb testing.TB, c Conf) *Binary {
	tb.Helper()
	src, err := build()
	if err != nil {
		tb.Fatal(err)
	}
	data, err := os.ReadFile(src) // #nosec G304 -- our own build output
	if err != nil {
		tb.Fatal(err)
	}
	dst := filepath.Join(tb.TempDir(), "nuclei")
	// #nosec G306 G703 -- test binary must be executable, path is a test temp dir
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		tb.Fatal(err)
	}
	b := &Binary{Path: dst, tb: tb}
	if c.Record == "" {
		c.Record = dst + ".calls"
	}
	b.Set(func(x *Conf) { *x = c })
	return b
}

// Set rewrites the conf.
func (b *Binary) Set(f func(*Conf)) {
	b.tb.Helper()
	f(&b.conf)
	data, err := json.Marshal(b.conf)
	if err != nil {
		b.tb.Fatal(err)
	}
	if err := os.WriteFile(b.Path+".json", data, 0o600); err != nil {
		b.tb.Fatal(err)
	}
}

// Calls returns every recorded invocation, oldest first.
func (b *Binary) Calls() []Call {
	b.tb.Helper()
	data, err := os.ReadFile(b.conf.Record) // #nosec G304 -- test file
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		b.tb.Fatal(err)
	}
	var out []Call
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var c Call
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			b.tb.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// ScanCalls returns the invocations that were scans (not -ut updates).
func (b *Binary) ScanCalls() []Call {
	var out []Call
	for _, c := range b.Calls() {
		upd := false
		for _, a := range c.Args {
			if a == "-ut" || a == "-update-templates" {
				upd = true
			}
		}
		if !upd {
			out = append(out, c)
		}
	}
	return out
}

// Arg returns the values following every occurrence of flag in args.
func Arg(args []string, flag string) []string {
	var out []string
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

// Has reports whether args contains flag.
func Has(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// Command fakenuclei is a stand-in for the nuclei binary in tests. See package
// fakenuclei. It mimics the parts of nuclei v3.11.1 deckard relies on: -ut with
// -ud installs a template tree (a no-op when -duc is present, exactly like the
// real binary), and a scan emits -jsonl events for templates whose probe
// matches a live HTTP response.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chainseer-xyz/deckard/internal/nuclei/fakenuclei"
)

// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func main() {
	exe, _ := os.Executable()
	var conf fakenuclei.Conf
	if b, err := os.ReadFile(exe + ".json"); err == nil {
		_ = json.Unmarshal(b, &conf)
	}
	args := os.Args[1:]
	record(conf, args)
	if fakenuclei.Has(args, "-ut") || fakenuclei.Has(args, "-update-templates") {
		os.Exit(update(conf, args))
	}
	os.Exit(scan(conf, args))
}

// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func record(conf fakenuclei.Conf, args []string) {
	if conf.Record == "" {
		return
	}
	env := map[string]string{}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "NUCLEI_CONFIG_DIR", "NUCLEI_TEMPLATES_DIR", "TMPDIR", "PATH"} {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	c := fakenuclei.Call{Args: args, Env: env}
	c.Targets = append(c.Targets, fakenuclei.Arg(args, "-u")...)
	for _, l := range fakenuclei.Arg(args, "-l") {
		if f, err := os.Open(l); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if t := strings.TrimSpace(sc.Text()); t != "" {
					c.Targets = append(c.Targets, t)
				}
			}
			_ = f.Close()
		}
	}
	for _, tv := range fakenuclei.Arg(args, "-t") {
		if !strings.HasSuffix(tv, ".txt") {
			c.Templates = append(c.Templates, tv)
			continue
		}
		if f, err := os.Open(tv); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if t := strings.TrimSpace(sc.Text()); t != "" {
					c.Templates = append(c.Templates, t)
				}
			}
			_ = f.Close()
		}
	}
	line, _ := json.Marshal(c)
	f, err := os.OpenFile(conf.Record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
}

func configDir() string {
	if d := os.Getenv("NUCLEI_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "nuclei")
	}
	return filepath.Join(os.Getenv("HOME"), ".config", "nuclei")
}

// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func update(conf fakenuclei.Conf, args []string) int {
	if fakenuclei.Has(args, "-duc") || fakenuclei.Has(args, "-disable-update-check") {
		return 0 // the real binary does nothing here, silently
	}
	if conf.UpdateFail != "" {
		fmt.Fprintln(os.Stderr, "[FTL]", conf.UpdateFail)
		return 1
	}
	dirs := append(fakenuclei.Arg(args, "-ud"), fakenuclei.Arg(args, "-update-template-dir")...)
	if len(dirs) == 0 || conf.Tree == "" {
		fmt.Fprintln(os.Stderr, "[FTL] fake: -ud and a configured tree are required")
		return 1
	}
	dst := dirs[0]
	if err := copyTree(conf.Tree, dst); err != nil {
		fmt.Fprintln(os.Stderr, "[FTL]", err)
		return 1
	}
	_ = os.WriteFile(filepath.Join(dst, ".new-additions"), []byte(strings.Join(conf.NewAdditions, "\n")+"\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dst, ".checksum"), []byte(dst+"/README.md,0"), 0o600)
	if conf.Escape {
		_ = os.Symlink("/etc", filepath.Join(dst, "http", "escape"))
	}
	v := conf.Version
	if v == "" {
		v = "v1.0.0"
	}
	cfg := configDir()
	_ = os.MkdirAll(cfg, 0o750)
	body, _ := json.Marshal(map[string]string{"nuclei-templates-directory": dst, "nuclei-templates-version": v})
	if err := os.WriteFile(filepath.Join(cfg, ".templates-config.json"), body, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "[FTL]", err)
		return 1
	}
	fmt.Printf("[INF] Successfully updated nuclei-templates (%s) to %s. GoodLuck!\n", v, dst)
	return 0
}

// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o750)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(t, out)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o600)
	})
}

type tpl struct {
	id, name, severity string
	tags, cves         []string
}

// readTemplate does a deliberately dumb line parse of the header.
// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func readTemplate(path string) (tpl, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return tpl{}, false
	}
	var t tpl
	for _, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "id:"):
			t.id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(trim, "name:") && t.name == "":
			t.name = strings.TrimSpace(strings.TrimPrefix(trim, "name:"))
		case strings.HasPrefix(trim, "severity:"):
			t.severity = strings.TrimSpace(strings.TrimPrefix(trim, "severity:"))
		case strings.HasPrefix(trim, "tags:"):
			t.tags = splitCSV(strings.TrimPrefix(trim, "tags:"))
		case strings.HasPrefix(trim, "cve-id:"):
			t.cves = splitCSV(strings.TrimPrefix(trim, "cve-id:"))
		}
	}
	return t, t.id != ""
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func scan(conf fakenuclei.Conf, args []string) int {
	if conf.ScanSleepMs > 0 {
		time.Sleep(time.Duration(conf.ScanSleepMs) * time.Millisecond)
	}
	var files []string
	for _, t := range fakenuclei.Arg(args, "-t") {
		for _, one := range splitCSV(t) {
			st, err := os.Stat(one)
			if err != nil {
				fmt.Fprintln(os.Stderr, "[FTL] no templates found at", one)
				return 1
			}
			if !st.IsDir() {
				if strings.HasSuffix(one, ".yaml") || strings.HasSuffix(one, ".yml") {
					files = append(files, one)
					continue
				}
				// Like the real binary, -t accepts a file listing templates.
				if b, err := os.ReadFile(one); err == nil {
					for _, line := range strings.Split(string(b), "\n") {
						if line = strings.TrimSpace(line); line != "" {
							files = append(files, line)
						}
					}
				}
				continue
			}
			_ = filepath.WalkDir(one, func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.Type().IsRegular() && strings.HasSuffix(p, ".yaml") {
					files = append(files, p)
				}
				return nil
			})
		}
	}
	wantIDs := listFlag(args, "-id")
	wantTags := listFlag(args, "-tags")
	exTags := listFlag(args, "-etags")
	sevs := listFlag(args, "-severity")

	var targets []string
	targets = append(targets, fakenuclei.Arg(args, "-u")...)
	for _, l := range fakenuclei.Arg(args, "-l") {
		if f, err := os.Open(l); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if t := strings.TrimSpace(sc.Text()); t != "" {
					targets = append(targets, t)
				}
			}
			_ = f.Close()
		}
	}
	client := &http.Client{Timeout: 5 * time.Second}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, f := range files {
		t, ok := readTemplate(f)
		if !ok || !pass(t, wantIDs, wantTags, exTags, sevs) {
			continue
		}
		for _, target := range targets {
			for _, p := range conf.Probes {
				if p.TemplateID != t.id || !hit(client, target+p.Path, p.Contains) {
					continue
				}
				ev := map[string]any{
					"template-id": t.id, "type": "http", "host": target, "matched-at": target + p.Path,
					"info": map[string]any{
						"name": t.name, "severity": t.severity, "tags": t.tags,
						"classification": map[string]any{"cve-id": t.cves},
					},
				}
				line, _ := json.Marshal(ev)
				fmt.Fprintln(out, string(line))
			}
		}
	}
	return conf.ScanExit
}

func listFlag(args []string, flag string) []string {
	var out []string
	for _, v := range fakenuclei.Arg(args, flag) {
		out = append(out, splitCSV(v)...)
	}
	return out
}

func pass(t tpl, ids, tags, etags, sevs []string) bool {
	if len(ids) > 0 && !contains(ids, t.id) {
		return false
	}
	if len(tags) > 0 && !anyIn(tags, t.tags) {
		return false
	}
	if anyIn(etags, t.tags) {
		return false
	}
	return len(sevs) == 0 || contains(sevs, t.severity)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func anyIn(want, have []string) bool {
	for _, w := range want {
		if contains(have, w) {
			return true
		}
	}
	return false
}

// #nosec G304 G703 G122 G704 G107 -- test-only fake nuclei binary (never shipped): paths and URLs come from the test harness
func hit(c *http.Client, url, needle string) bool {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode == 200 && strings.Contains(string(b), needle)
}

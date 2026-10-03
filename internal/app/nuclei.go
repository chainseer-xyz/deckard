package app

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/chainseer-xyz/deckard/internal/config"
	"github.com/chainseer-xyz/deckard/internal/engine"
	"github.com/chainseer-xyz/deckard/internal/nuclei"
	"github.com/chainseer-xyz/deckard/internal/nuclei/updater"
)

const bakedNucleiTemplates = "/usr/local/share/deckard/nuclei-templates"

// nucleiWiring is everything the app builds around the nuclei binary: the
// effective config, the template updater (nil when off) and the template-
// limited scanner (nil when nuclei is off).
type nucleiWiring struct {
	cfg     config.NucleiConfig
	upd     *updater.Updater
	scanner *nuclei.Scanner
	opts    []nuclei.Option
	env     func() ([]string, func(), error)
	gate    *nuclei.ProcessGate
}

// nuclei builds the wiring once. It never touches the network and fails open:
// problems disable the affected piece with a log line, never the process.
func (a *App) nuclei() *nucleiWiring {
	if a.nw != nil {
		return a.nw
	}
	nw := &nucleiWiring{cfg: a.cfg.Nuclei}
	a.nw = nw
	if !nw.cfg.Enabled {
		return nw
	}
	// The slim image ships without nuclei: warn once and skip the check
	// instead of failing it on every scan.
	if _, err := exec.LookPath(nw.cfg.Binary); err != nil {
		a.log.Warn("nuclei binary not found; cve.nuclei is disabled (set nuclei.enabled=false to silence, or use the full image)", "binary", nw.cfg.Binary)
		nw.cfg.Enabled = false
		return nw
	}

	u := nw.cfg.Update
	nw.gate = nuclei.NewProcessGate(nw.cfg.ProcessConcurrency)
	switch {
	case !u.Enabled:
		a.log.Info("nuclei template updates are disabled; scans use the templates found at nuclei.templates_dir", "templates_dir", nw.cfg.TemplatesDir)
	case nw.cfg.TemplatesDir != nw.cfg.UpdateCurrentDir():
		// The operator pointed nuclei at their own templates: updating a
		// directory nothing reads would only burn bandwidth.
		a.log.Warn("nuclei.templates_dir is set explicitly, so the template updater is not used; set nuclei.update.enabled=false to silence this, or clear nuclei.templates_dir to use updates",
			"templates_dir", nw.cfg.TemplatesDir, "update_dir", u.Dir)
		nw.cfg.Update.Enabled = false
	default:
		upd, err := updater.New(updater.Config{Dir: u.Dir, BakedDir: bakedNucleiTemplates, Binary: nw.cfg.Binary, Timeout: u.Timeout, Logger: a.log})
		if err != nil {
			a.log.Error("nuclei template updater disabled", "err", err)
			nw.cfg.Update.Enabled = false
			break
		}
		nw.upd = upd
		nw.env = func() ([]string, func(), error) {
			values, cleanup, err := upd.ScanEnv()
			if err != nil {
				return nil, nil, err
			}
			values = append(values, "GOMEMLIMIT="+nw.cfg.ProcessMemoryLimit)
			return values, cleanup, nil
		}
		nw.opts = []nuclei.Option{nuclei.WithEnv(nw.env), nuclei.WithTemplateDir(func() (string, error) {
			dir, _, err := upd.ActiveDir()
			return dir, err
		})}
		a.seedTemplateMetrics(upd)
	}
	if _, err := os.Stat(filepath.Join(bakedNucleiTemplates, "deckard")); err == nil {
		nw.cfg.ExtraTemplatesDirs = append(nw.cfg.ExtraTemplatesDirs, filepath.Join(bakedNucleiTemplates, "deckard"))
	}
	if nw.env == nil {
		nw.env = func() ([]string, func(), error) {
			return []string{"GOMEMLIMIT=" + nw.cfg.ProcessMemoryLimit}, func() {}, nil
		}
	}
	runtimeOpts := append([]nuclei.Option{}, nw.opts...)
	runtimeOpts = append(runtimeOpts, nuclei.WithEnv(nw.env), nuclei.WithLogger(a.log),
		nuclei.WithRunObserver(a.metrics.ObserveNucleiRun), nuclei.WithProcessGate(nw.gate))
	if nw.upd != nil {
		upd := nw.upd
		runtimeOpts = append(runtimeOpts, nuclei.WithTemplateSource(func() string {
			_, source, err := upd.ActiveDir()
			if err != nil {
				return "configured"
			}
			return source
		}))
	}
	nw.scanner = nuclei.NewScanner(nw.cfg, nuclei.ScopeVerifier(a.guard.VerifyOwnedTarget),
		nuclei.ExecRunner{Env: nw.env, Gate: nw.gate}, a.cfg.Checks[nuclei.NameActive], runtimeOpts...)
	return nw
}

// checkUpdateDir warns early when the updater cannot write its state
// directory (a read-only root filesystem without the mounted volume).
func (a *App) checkUpdateDir(dir string) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		a.log.Warn("nuclei.update.dir is not writable: template updates will fail until a writable volume is mounted there (or set nuclei.update.enabled=false)", "dir", dir, "err", err)
		return
	}
	f, err := os.CreateTemp(dir, ".writecheck-")
	if err != nil {
		a.log.Warn("nuclei.update.dir is not writable: template updates will fail until a writable volume is mounted there (or set nuclei.update.enabled=false)", "dir", dir, "err", err)
		return
	}
	_ = f.Close()
	_ = os.Remove(filepath.Join(dir, filepath.Base(f.Name())))
}

// seedTemplateMetrics publishes the persisted template status at startup so
// the age gauge is right straight after a restart, on every role.
func (a *App) seedTemplateMetrics(upd *updater.Updater) {
	if a.metrics == nil {
		return
	}
	a.metrics.SetTemplateMaxAgeWarn(a.cfg.Nuclei.Update.MaxAgeWarn)
	if st, err := upd.Status(); err == nil && !st.CheckedAt.IsZero() {
		a.metrics.SetTemplateStatus(st.TemplateCount, st.CheckedAt)
	}
}

// engineTemplates returns the engine's template collaborators, nil (not a typed
// nil) when absent.
func (a *App) engineTemplates() (engine.TemplateManager, engine.DeltaScanner) {
	nw := a.nuclei()
	var tm engine.TemplateManager
	var ds engine.DeltaScanner
	if nw.upd != nil {
		tm = nw.upd
	}
	if nw.scanner != nil {
		ds = nw.scanner
	}
	return tm, ds
}

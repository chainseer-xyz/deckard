package nuclei

import (
	"path/filepath"

	"github.com/chainseer-xyz/deckard/internal/nuclei/templates"
)

const (
	maxCustomTemplateBytes = 512 << 20
	maxCustomTemplateFiles = 200_000
)

// validExtraDirs keeps official templates usable when an operator-mounted
// directory is absent, malformed, too large, or unsafe.
func validExtraDirs(dirs []string, o options) []string {
	var out []string
	for _, dir := range dirs {
		if _, err := templates.ValidateCustom(dir, maxCustomTemplateBytes, maxCustomTemplateFiles); err != nil {
			if o.logger != nil {
				o.logger.Warn("nuclei custom templates skipped", "dir", dir, "err", err)
			}
			if o.observe != nil {
				o.observe(0, 0, "configured", err)
			}
			continue
		}
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			out = append(out, real)
		}
	}
	return out
}

func customTemplateArgs(args []string, dirs []string) []string {
	for _, dir := range dirs {
		// -it keeps operator templates from being hidden by the official tag
		// selection; the directory has already passed protocol and safety checks.
		args = append(args, "-t", dir, "-it", dir)
	}
	return args
}

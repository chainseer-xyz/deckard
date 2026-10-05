package nuclei

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// DestinationPolicy returns a denylist enforced by Nuclei's network policy.
type DestinationPolicy func(context.Context, []string) ([]string, error)

func (r ExecRunner) destinationArgs(ctx context.Context, args []string) ([]string, func(), error) {
	hosts, err := argumentHosts(args)
	if err != nil {
		return nil, nil, err
	}
	if len(hosts) == 0 { // Non-scanning binary diagnostics need no destination.
		return args, func() {}, nil
	}
	if r.Policy == nil {
		return nil, nil, fmt.Errorf("%w: scanner destination policy is unavailable", ErrOutOfScope)
	}
	denied, err := r.Policy(ctx, hosts)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: scanner destination policy: %w", ErrOutOfScope, err)
	}
	if len(denied) == 0 {
		return nil, nil, fmt.Errorf("%w: empty scanner destination policy", ErrOutOfScope)
	}
	dir, err := os.MkdirTemp("", "deckard-nuclei-policy-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	denyFile := filepath.Join(dir, "denied.txt")
	// File-backed flags keep even large IPv6 complements below argv limits.
	if err := os.WriteFile(denyFile, []byte(strings.Join(denied, "\n")+"\n"), 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}
	configFile := filepath.Join(dir, "config.yaml")
	// An explicit config is not sufficient: Nuclei merges global defaults.
	// destinationEnv also isolates its home/config/cache directories.
	if err := os.WriteFile(configFile, []byte("{}\n"), 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}
	errorFile := filepath.Join(dir, "errors.fifo")
	if err := createRequestLog(errorFile); err != nil {
		cleanup()
		return nil, nil, err
	}
	return append(slices.Clone(args), "-config", configFile, "-eh", denyFile, "-elog", errorFile), cleanup, nil
}

func argumentHosts(args []string) ([]string, error) {
	var hosts []string
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			continue
		}
		flag, value, inline := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		switch flag {
		case "u", "target", "l", "list":
			if !inline {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("nuclei: missing %s argument", flag)
				}
				i++
				value = args[i]
			}
			if flag == "l" || flag == "list" {
				list, err := listHosts(value)
				if err != nil {
					return nil, err
				}
				hosts = append(hosts, list...)
				continue
			}
			host, err := targetHost(value)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, host)
		case "p", "proxy", "config", "eh", "exclude-hosts", "elog", "error-log", "profile", "tp", "targets-inline", "resume":
			return nil, fmt.Errorf("nuclei: scan cannot override destination policy")
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts), nil
}

func requestLogPath(args []string) string {
	for i := len(args) - 2; i >= 0; i-- {
		if args[i] == "-elog" {
			return args[i+1]
		}
	}
	return ""
}

// Nuclei loads global config before applying -config, so isolate both paths.
// Do not replace NUCLEI_TEMPLATES_DIR or operator-provided template secrets.
func destinationEnv(args []string) []string {
	path := requestLogPath(args)
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	return []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"),
		"XDG_CACHE_HOME=" + filepath.Join(dir, "cache"), "NUCLEI_CONFIG_DIR=" + filepath.Join(dir, "config", "nuclei")}
}

func targetHost(value string) (string, error) {
	target, err := urlTarget(value)
	if err != nil {
		return "", fmt.Errorf("nuclei: invalid policy target %q: %w", value, err)
	}
	return target.host, nil
}

func listHosts(path string) ([]string, error) {
	file, err := os.Open(path) // #nosec G304 -- Deckard-created private target list
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if value := strings.TrimSpace(scanner.Text()); value != "" {
			host, err := targetHost(value)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, host)
			if len(hosts) > 1024 {
				return nil, fmt.Errorf("nuclei: target list exceeds destination limit")
			}
		}
	}
	return hosts, scanner.Err()
}

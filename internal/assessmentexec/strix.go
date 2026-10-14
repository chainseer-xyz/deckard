package assessmentexec

import (
	"net/netip"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
)

func strixEnvironment(cmd *exec.Cmd, getenv func(string) string) error {
	cmd.Env = append(cmd.Env, "PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", "PYTHONPATH=/opt/strix:/opt/deckard", "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1", "STRIX_TELEMETRY=false", "OPENAI_AGENTS_DISABLE_TRACING=1", "LITELLM_LOCAL_MODEL_COST_MAP=true")
	runtimeURL, modelURL := getenv("DECKARD_RUNTIME_URL"), getenv("LLM_API_BASE")
	model := getenv("STRIX_LLM")
	if model == "" && modelURL == "" {
		return nil
	} // The genuine adapter emits model_unavailable without starting a tool session.
	if brokerEndpoint(strings.TrimSuffix(runtimeURL, "/"), "") != nil || modelEndpoint(modelURL) != nil {
		return ErrInvalid
	}
	cmd.Env = append(cmd.Env, "DECKARD_RUNTIME_URL="+runtimeURL, "LLM_API_BASE="+modelURL)
	if model == "" || len(model) > 200 || strings.ContainsAny(model, "\r\n\x00") {
		return ErrInvalid
	}
	path := getenv("DECKARD_RUNTIME_TOKEN_FILE")
	if _, err := readToken(path); err != nil {
		return ErrInvalid
	}
	cmd.Env = append(cmd.Env, "STRIX_LLM="+model, "DECKARD_RUNTIME_TOKEN_FILE="+path)
	if key := getenv("LLM_API_KEY"); key != "" {
		if len(key) > 4096 || strings.ContainsAny(key, "\r\n\x00") {
			return ErrInvalid
		}
		cmd.Env = append(cmd.Env, "LLM_API_KEY="+key)
	}
	return nil
}

func modelEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ErrInvalid
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return ErrInvalid
	}
	if port := u.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return ErrInvalid
		}
	}
	return nil
}

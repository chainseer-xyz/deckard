package config

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AssessmentConfig grants explicit, bounded, inventory-backed assessments.
// NetworkPolicyEnforced must follow a real positive/negative CNI fixture.
type AssessmentConfig struct {
	Enabled               bool              `koanf:"enabled"`
	Namespace             string            `koanf:"namespace"`
	BrokerAddr            string            `koanf:"broker_addr"`
	BrokerIPEnv           string            `koanf:"broker_ip_env"`
	NetworkPolicyEnforced bool              `koanf:"network_policy_enforced"`
	Images                map[string]string `koanf:"images"`
	UploaderImage         string            `koanf:"uploader_image"`
	StrixRuntimeImage     string            `koanf:"strix_runtime_image"`
	MaxSessions           int               `koanf:"max_sessions"`
	MaxRunning            int               `koanf:"max_running"`
	Timeout               time.Duration     `koanf:"timeout"`
	MaxRequests           int               `koanf:"max_requests"`
	MaxRequestBytes       int64             `koanf:"max_request_bytes"`
	MaxResponseBytes      int64             `koanf:"max_response_bytes"`
	ModelGatewayURL       string            `koanf:"model_gateway_url"`
	ModelGatewayIP        string            `koanf:"model_gateway_ip"`
	ModelGatewayPort      int32             `koanf:"model_gateway_port"`
	Model                 string            `koanf:"model"`
	ModelSecretName       string            `koanf:"model_secret_name"`
	ModelSecretKey        string            `koanf:"model_secret_key"`
	ZAPAuthSecretName     string            `koanf:"zap_auth_secret_name"`
}

var pinnedAssessmentImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[a-f0-9]{64}$`)
var assessmentNamespace = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func (c *Config) validateAssessment(add func(string, ...any)) {
	a := c.Assessment
	if !a.Enabled {
		return
	}
	if !a.NetworkPolicyEnforced {
		add("assessment.network_policy_enforced requires a verified live CNI containment fixture")
	}
	if !assessmentNamespace.MatchString(a.Namespace) || len(a.Namespace) > 63 || a.Namespace == "default" || strings.HasPrefix(a.Namespace, "kube-") {
		add("assessment.namespace must name a dedicated isolated namespace")
	}
	host, port, err := net.SplitHostPort(a.BrokerAddr)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || number == 0 || (host != "0.0.0.0" && host != "::") || !envName.MatchString(a.BrokerIPEnv) {
		add("assessment requires an explicit broker listener and Pod IP environment variable")
	}
	if !pinnedAssessmentImage.MatchString(a.UploaderImage) || len(a.Images) == 0 {
		add("assessment requires immutable uploader and scanner images")
	}
	for tool, image := range a.Images {
		if (tool != "zgrab2" && tool != "zap" && tool != "strix") || !pinnedAssessmentImage.MatchString(image) {
			add("assessment.images must contain supported, immutable tool images")
		}
		if tool == "strix" && (!pinnedAssessmentImage.MatchString(a.StrixRuntimeImage) || a.Model == "" || a.ModelGatewayURL == "" || a.ModelGatewayIP == "" || a.ModelGatewayPort < 1 || a.ModelGatewayPort > 65535) {
			add("assessment Strix requires an approved model gateway and immutable runtime image")
		}
	}
	if a.MaxSessions < 1 || a.MaxSessions > 16 || a.MaxRunning < 1 || a.MaxRunning > 2 || a.MaxRunning > a.MaxSessions || a.Timeout <= 0 || a.Timeout > 15*time.Minute || a.MaxRequests < 1 || a.MaxRequests > 10000 || a.MaxRequestBytes < 1 || a.MaxRequestBytes > 64<<20 || a.MaxResponseBytes < 1 || a.MaxResponseBytes > 64<<20 {
		add("assessment session and network budgets exceed their safety bounds")
	}
}

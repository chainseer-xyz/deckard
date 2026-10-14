package assessmentjob_test

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

func settings() assessmentjob.Settings {
	image := "ghcr.io/example/assessment@sha256:" + strings.Repeat("a", 64)
	return assessmentjob.Settings{Namespace: "deckard-assessment", BrokerIP: netip.MustParseAddr("10.20.30.50"), BrokerPort: 9092,
		Images: map[assessmentjob.Tool]string{assessmentjob.ToolZAP: image, assessmentjob.ToolZGrab2: image, assessmentjob.ToolStrix: image}, UploaderImage: image, StrixRuntimeImage: image,
		NetworkPolicyEnforced: true, MaxSessions: 16, MaxRunning: 2, SessionDuration: time.Minute}
}

func TestPlanSeparatesScannerAndUploaderAuthority(t *testing.T) {
	plan, err := assessmentjob.BuildPlan(context.Background(), settings(), assessmentjob.PlanInput{ID: "e4d0d507-7819-4e66-916d-bbd614c3a3f0", Tool: assessmentjob.ToolZAP,
		Targets:    []assessmentjob.Target{{AssetID: 1, Origin: "https://app.example.com:443", Addresses: []netip.Addr{netip.MustParseAddr("10.20.30.40")}, Port: 443}},
		ProxyToken: strings.Repeat("p", 43), UploadToken: strings.Repeat("u", 43), RuntimeToken: strings.Repeat("r", 43), CAPEM: []byte("public CA")})
	if err != nil {
		t.Fatal(err)
	}
	pod := plan.Job.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || pod.ServiceAccountName != assessmentjob.ServiceAccountName {
		t.Fatal("runner must use tokenless dedicated service account")
	}
	if len(pod.Containers) != 2 {
		t.Fatal("scanner and uploader must use separate containers")
	}
	for _, container := range pod.Containers {
		if container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem || *container.SecurityContext.AllowPrivilegeEscalation {
			t.Fatal("container is not hardened")
		}
		if _, exists := container.Resources.Limits["cpu"]; exists {
			t.Fatal("CPU limits are forbidden")
		}
		for _, mount := range container.VolumeMounts {
			if container.Name == "scanner" && mount.Name == "upload-token" {
				t.Fatal("scanner can read uploader credential")
			}
			if container.Name == "uploader" && mount.Name == "proxy-token" {
				t.Fatal("uploader does not need proxy authority")
			}
		}
	}
	if len(plan.Policies) != 1 || len(plan.Policies[0].Spec.Egress) != 1 {
		t.Fatal("ZAP must have exactly one egress rule")
	}
	rule := plan.Policies[0].Spec.Egress[0]
	if len(rule.To) != 1 || rule.To[0].IPBlock == nil || rule.To[0].IPBlock.CIDR != "10.20.30.50/32" || rule.Ports[0].Port.IntVal != 9092 {
		t.Fatal("runner egress must reach only literal broker IP and port")
	}
}

func TestPlanKeepsScannerPrivateWorkFilesAwayFromUploader(t *testing.T) {
	for _, tool := range []assessmentjob.Tool{assessmentjob.ToolZAP, assessmentjob.ToolZGrab2, assessmentjob.ToolStrix} {
		t.Run(string(tool), func(t *testing.T) {
			s, input := settings(), planInput()
			input.Tool = tool
			s.ZAPAuthSecretName = "target-auth"
			s.ModelGatewayIP = netip.MustParseAddr("10.20.30.60")
			s.ModelGatewayURL = "http://10.20.30.60:8000/v1"
			s.ModelGatewayPort = 8000
			s.Model = "openai/local-model"
			plan, err := assessmentjob.BuildPlan(context.Background(), s, input)
			if err != nil {
				t.Fatal(err)
			}
			var scannerTmp, uploaderTmp string
			for _, container := range plan.Job.Spec.Template.Spec.Containers {
				for _, mount := range container.VolumeMounts {
					if mount.MountPath == "/tmp" {
						if container.Name == "scanner" {
							scannerTmp = mount.Name
						} else {
							uploaderTmp = mount.Name
						}
					}
					if container.Name == "uploader" && mount.MountPath == "/report" && !mount.ReadOnly {
						t.Error("uploader can rewrite scanner completion/report files")
					}
				}
			}
			if scannerTmp == "" || uploaderTmp == "" || scannerTmp == uploaderTmp {
				t.Fatalf("uploader can read ZAP's proxy/app credentials from scanner work files: scanner=%q uploader=%q", scannerTmp, uploaderTmp)
			}
		})
	}
}

func planInput() assessmentjob.PlanInput {
	return assessmentjob.PlanInput{ID: "e4d0d507-7819-4e66-916d-bbd614c3a3f0", Tool: assessmentjob.ToolZAP, Targets: []assessmentjob.Target{{AssetID: 1, Origin: "https://app.example.com:443", Addresses: []netip.Addr{netip.MustParseAddr("10.20.30.40")}, Port: 443}}, ProxyToken: strings.Repeat("p", 43), UploadToken: strings.Repeat("u", 43), RuntimeToken: strings.Repeat("r", 43)}
}

func TestPlanRefusesUnenforcedMutableOrAmbiguousGrants(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings func(*assessmentjob.Settings)
		input    func(*assessmentjob.PlanInput)
	}{
		{name: "unenforced CNI", settings: func(s *assessmentjob.Settings) { s.NetworkPolicyEnforced = false }},
		{name: "mutable scanner image", settings: func(s *assessmentjob.Settings) { s.Images[assessmentjob.ToolZAP] = "ghcr.io/example/zap:latest" }},
		{name: "mutable uploader image", settings: func(s *assessmentjob.Settings) { s.UploaderImage = "ghcr.io/example/deckard:latest" }},
		{name: "excess duration", settings: func(s *assessmentjob.Settings) { s.SessionDuration = 16 * time.Minute }},
		{name: "unbounded requests", settings: func(s *assessmentjob.Settings) { s.Limits.MaxRequests = -1 }},
		{name: "shared authority token", input: func(i *assessmentjob.PlanInput) { i.UploadToken = i.ProxyToken }},
		{name: "origin port mismatch", input: func(i *assessmentjob.PlanInput) { i.Targets[0].Port = 8443 }},
		{name: "target path", input: func(i *assessmentjob.PlanInput) { i.Targets[0].Origin = "https://app.example.com/private" }},
		{name: "target query", input: func(i *assessmentjob.PlanInput) { i.Targets[0].Origin = "https://app.example.com/?credential=secret" }},
		{name: "unspecified address", input: func(i *assessmentjob.PlanInput) {
			i.Targets[0].Addresses = []netip.Addr{netip.MustParseAddr("0.0.0.0")}
		}},
		{name: "multicast address", input: func(i *assessmentjob.PlanInput) {
			i.Targets[0].Addresses = []netip.Addr{netip.MustParseAddr("224.0.0.1")}
		}},
		{name: "broker as target", input: func(i *assessmentjob.PlanInput) {
			i.Targets[0].Addresses = []netip.Addr{netip.MustParseAddr("10.20.30.50")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, i := settings(), planInput()
			if test.settings != nil {
				test.settings(&s)
			}
			if test.input != nil {
				test.input(&i)
			}
			if plan, err := assessmentjob.BuildPlan(context.Background(), s, i); err == nil || plan != nil {
				t.Fatal("invalid containment grant was rendered")
			}
		})
	}
}

func TestZGrabEgressKeepsEachIPPortPairDistinct(t *testing.T) {
	i := planInput()
	i.Tool = assessmentjob.ToolZGrab2
	i.Targets = append(i.Targets, assessmentjob.Target{AssetID: 2, Origin: "http://other.example.com:8080", Port: 8080, Addresses: []netip.Addr{netip.MustParseAddr("10.20.30.41")}})
	plan, err := assessmentjob.BuildPlan(context.Background(), settings(), i)
	if err != nil {
		t.Fatal(err)
	}
	rules := plan.Policies[0].Spec.Egress
	if len(rules) != 3 {
		t.Fatalf("need only uploaderbroker + two exactIP:port grants, got%d", len(rules))
	}
	if rules[1].To[0].IPBlock.CIDR != "10.20.30.40/32" || rules[1].Ports[0].Port.IntVal != 443 || rules[2].To[0].IPBlock.CIDR != "10.20.30.41/32" || rules[2].Ports[0].Port.IntVal != 8080 {
		t.Fatal("network policy broadened targets into IP/port crossproduct")
	}
}

func TestStrixModelGatewayRejectsUnsafeAddresses(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "0.1.2.3", "127.0.0.1", "100.100.100.200", "169.254.169.254", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "ff02::1", "fd00:ec2::254", "64:ff9b::a9fe:a9fe", "::ffff:169.254.169.254"} {
		t.Run(raw, func(t *testing.T) {
			s := settings()
			s.ModelGatewayIP = netip.MustParseAddr(raw)
			s.ModelGatewayURL = "http://" + net.JoinHostPort(raw, "8000") + "/v1"
			s.ModelGatewayPort = 8000
			s.Model = "openai/local-model"
			i := planInput()
			i.Tool = assessmentjob.ToolStrix
			if plan, err := assessmentjob.BuildPlan(context.Background(), s, i); err == nil || plan != nil {
				t.Fatal("unsafe model gateway gained kernel egress grant")
			}
		})
	}
}

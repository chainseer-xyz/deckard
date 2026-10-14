package config

import "testing"

func TestAssessmentRequiresExplicitContainment(t *testing.T) {
	for _, yaml := range []string{
		"assessment: {enabled: true}\n",
		"assessment: {enabled: true, namespace: default, network_policy_enforced: true}\n",
		"assessment: {enabled: true, namespace: deckard-assessments, network_policy_enforced: true, images: {zap: 'latest'}}\n",
	} {
		if _, err := Load(writeCfg(t, yaml), nil); err == nil {
			t.Fatal("unsafe assessment configuration accepted")
		}
	}
}

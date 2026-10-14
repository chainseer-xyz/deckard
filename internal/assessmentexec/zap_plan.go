package assessmentexec

import (
	"net/url"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

func zapPlan(r assessmentjob.ExecutionRequest, work string, cfg zapSettings) ([]byte, error) {
	proxy, _ := url.Parse(cfg.proxyURL)
	port, _ := strconv.Atoi(proxy.Port())
	paths := make([]string, 0, len(r.Targets))
	requests := make([]map[string]any, 0, len(r.Targets))
	for _, target := range r.Targets {
		paths = append(paths, originPattern(target))
		requests = append(requests, map[string]any{"url": target + "/", "method": "GET"})
	}
	jobs := zapJobs(r, work, requests)
	if len(cfg.auth) > 0 {
		rules := make([]map[string]any, 0, len(cfg.auth))
		for _, grant := range cfg.auth {
			rules = append(rules, map[string]any{"description": "Deckard exact-origin authentication", "url": originPattern(grant.Origin), "matchType": "req_header", "matchString": grant.Header, "matchRegex": false, "replacementString": grant.Value, "tokenProcessing": false})
		}
		jobs = append([]map[string]any{{"type": "replacer", "parameters": map[string]any{"deleteAllRules": true}, "rules": rules}}, jobs...)
	}
	return yaml.Marshal(map[string]any{
		"env": map[string]any{
			"contexts":   []map[string]any{{"name": "deckard", "urls": r.Targets, "includePaths": paths}},
			"parameters": map[string]any{"failOnError": true, "failOnWarning": true, "continueOnFailure": false, "progressToStdout": false, "maxDuration": r.TimeoutSeconds},
			"proxy":      map[string]any{"hostname": proxy.Hostname(), "port": port, "username": "deckard", "password": cfg.token},
			// env.proxy stores an Integer port. Normalize it before the generic
			// config reload: pinned ConnectionOptions reads this field as String.
			"configs": map[string]any{"network.connection.httpProxy.port": strconv.Itoa(port), "network.connection.httpProxy.enabled": true, "network.connection.httpProxy.authEnabled": true, "network.connection.httpProxy.storePass": false, "network.connection.timeoutInSecs": 10, "pscans.threads": 1},
		}, "jobs": jobs,
	})
}

func zapJobs(r assessmentjob.ExecutionRequest, work string, requests []map[string]any) []map[string]any {
	minutes := max(1, int(r.TimeoutSeconds/60))
	return []map[string]any{
		{"type": "requestor", "requests": requests},
		{"type": "spider", "parameters": map[string]any{"context": "deckard", "maxDuration": min(minutes, 2), "maxDepth": 3, "maxChildren": 20, "threadCount": 1, "postForm": false, "processForm": false, "acceptCookies": false, "parseComments": false, "parseRobotsTxt": false, "parseSitemapXml": false, "sendRefererHeader": false}},
		{"type": "passiveScan-wait", "parameters": map[string]any{"maxDuration": min(minutes, 1)}},
		{"type": "activeScan", "parameters": map[string]any{"context": "deckard", "maxRuleDurationInMins": 1, "maxScanDurationInMins": minutes, "threadPerHost": 1, "delayInMs": 50, "maxAlertsPerRule": 100}, "policyDefinition": map[string]any{"defaultStrength": "Low", "defaultThreshold": "Medium"}},
		{"type": "passiveScan-wait", "parameters": map[string]any{"maxDuration": min(minutes, 1)}},
		{"type": "report", "alwaysRun": true, "parameters": map[string]any{"template": "traditional-json", "reportDir": work, "reportFile": "native.json", "displayReport": false}},
	}
}

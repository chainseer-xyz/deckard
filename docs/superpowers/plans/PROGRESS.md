# Progress

All planned tasks are complete and verified. See `review-findings.md` for the independent review rounds.

- [x] Spec, plan
- [x] Foundation: model, interfaces, config, JSON logging, CLI
- [x] Postgres store + migrations (contract suite on real Postgres)
- [x] scope.Guard (independent security review; findings fixed with regression tests)
- [x] Sources: Cloudflare, Route 53, AWS (EC2/EIP/ELBv2/CloudFront), Kubernetes, static
- [x] Inventory, baseline learning, findings lifecycle, notification dispatcher with lineage
- [x] Discovery expansion (CT, wildcard-aware, opt-in brute force), scheduled
- [x] River engine: tiered cadence, per-check intervals, due logic from LastScans, derived-asset GC
- [x] Checks: DNS (dangling, takeover, hygiene), TLS, HTTP, origin (exposed, correlation), ports, services, TLS config, exposure paths, nuclei, exec plugins
- [x] Alertmanager notifier (Slack/Discord/ntfy via routing), Prometheus metrics, Grafana dashboard
- [x] API + auth (token/OIDC) + SSE + OpenAPI; React UI
- [x] Helm chart (CNPG option, NetworkPolicy default), compose, CI, release workflow
- [x] Composition root + serve/migrate/sync/scan/findings commands
- [x] End-to-end tests on real Postgres incl. safety property (non-owned never probed)
- [x] Review round 1 (core + API/auth): all findings fixed
- [x] Security gates: gosec 0 issues, Trivy clean (slim image 13 MB; nuclei built from pinned source with patched deps)
- [x] Live validation on a real 71-zone estate, with precision fixes re-verified
- [x] Project renamed blart -> deckard
- [x] Continuous CVE currency: nuclei template updater (6h, atomic swap), new-template and KEV-triggered targeted scans, partial-run semantics, open findings re-verified by their own template
- [x] Reference data refresh (takeover fingerprints, CDN/SaaS ranges) with embedded fallback
- [x] Exploit intelligence: CISA KEV + FIRST EPSS enrichment, KEV badge in the UI, kev alert label
- [x] Upkeep CI: Dependabot, daily govulncheck, weekly nuclei bump and image rebuild, signed images + SBOM + provenance (actions pinned by SHA)
- [x] End-to-end proof of the React2Shell-style scenario (KEV addition -> targeted scan -> critical finding -> alert -> correct resolve)


package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"golang.org/x/net/netutil"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/chainseer-xyz/deckard/internal/assessment"
	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
	"github.com/chainseer-xyz/deckard/internal/assessmentresult"
	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/model"
	"github.com/chainseer-xyz/deckard/internal/store"
)

func (a *App) buildAssessments() error {
	c := a.cfg.Assessment
	if !c.Enabled || !a.hasRole("api") {
		return nil
	}
	ip, err := netip.ParseAddr(a.opts.Getenv(c.BrokerIPEnv))
	if err != nil {
		return errors.New("assessment broker requires its literal Pod IP from the configured environment variable")
	}
	_, port, err := net.SplitHostPort(c.BrokerAddr)
	if err != nil {
		return errors.New("invalid assessment broker listener")
	}
	number, err := strconv.ParseInt(port, 10, 32)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("invalid assessment broker port")
	}
	kube := a.opts.AssessmentClient
	if kube == nil {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return errors.New("assessment requires an in-cluster service account")
		}
		kube, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return errors.New("assessment Kubernetes client unavailable")
		}
	}
	images := map[assessmentjob.Tool]string{}
	for tool, image := range c.Images {
		images[assessmentjob.Tool(tool)] = image
	}
	modelIP, _ := netip.ParseAddr(c.ModelGatewayIP)
	a.assessments, err = assessmentjob.NewManager(assessmentjob.Settings{
		Namespace: c.Namespace, BrokerIP: ip, BrokerPort: int32(number), Images: images, UploaderImage: c.UploaderImage, StrixRuntimeImage: c.StrixRuntimeImage,
		NetworkPolicyEnforced: c.NetworkPolicyEnforced, MaxSessions: c.MaxSessions, MaxRunning: c.MaxRunning, SessionDuration: c.Timeout,
		RefreshOwnership: a.inv.Rehydrate,
		Limits:           assessment.Limits{MaxRequests: c.MaxRequests, MaxRequestBytes: c.MaxRequestBytes, MaxResponseBytes: c.MaxResponseBytes, Timeout: c.Timeout},
		ModelGatewayURL:  c.ModelGatewayURL, ModelGatewayIP: modelIP, ModelGatewayPort: c.ModelGatewayPort, Model: c.Model,
		ModelSecretName: c.ModelSecretName, ModelSecretKey: c.ModelSecretKey, ZAPAuthSecretName: c.ZAPAuthSecretName,
	}, a.st, a.guard, kube, a.completeAssessment)
	if err != nil {
		return fmt.Errorf("assessment configuration: %w", err)
	}
	return nil
}

func assessmentScope(c assessmentjob.Completion, authProfile string) string {
	ids := append([]int64(nil), c.Session.AssetIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	data, _ := json.Marshal(struct {
		IDs     []int64
		Profile string
	}{ids, authProfile})
	sum := sha256.Sum256(data)
	return "assessment:" + hex.EncodeToString(sum[:])
}

func (a *App) completeAssessment(ctx context.Context, c assessmentjob.Completion) error {
	result, err := assessmentresult.Parse(c)
	if err != nil {
		return err
	}
	assets := map[int64]*model.Asset{}
	for _, target := range c.Targets {
		asset, err := a.st.GetAsset(ctx, target.AssetID)
		if err != nil || asset == nil || asset.Scope != model.ScopeOwned || asset.RemovedAt != nil {
			return errors.New("assessment target is no longer live and owned")
		}
		assets[asset.ID] = asset
	}
	findings := make([]ingest.Finding, 0, len(result.Findings))
	for _, item := range result.Findings {
		asset := assets[item.AssetID]
		if asset == nil {
			return errors.New("assessment finding is not bound to its authorized inventory target")
		}
		f := item.Data
		f.Asset = ingest.Asset{Ref: &ingest.AssetRef{Kind: asset.Kind, Key: asset.Key}}
		findings = append(findings, f)
	}
	observed := c.Session.CreatedAt
	request := ingest.Request{Tool: string(c.Session.Tool), Scope: assessmentScope(c, a.cfg.Assessment.ZAPAuthSecretName), Complete: result.Complete, ObservedAt: &observed, Findings: findings}
	if c.Session.Tool == assessmentjob.ToolZGrab2 {
		request.Complete = false
	}
	if problems := ingest.Validate(&request, ingest.Options{Now: time.Now()}); len(problems) > 0 {
		return errors.New("normalized assessment report failed ingest validation")
	}
	for id, observations := range result.Observations {
		asset := assets[id]
		if asset == nil {
			return errors.New("assessment observation has no authorized target")
		}
		for _, observation := range observations {
			if err := a.st.SaveObservation(ctx, asset.ID, observation, time.Now()); err != nil {
				return err
			}
		}
	}
	in := store.IngestInput{Tool: request.Tool, Scope: request.Scope, Check: model.IngestCheck(request.Tool), Source: model.IngestSource(request.Tool), Complete: request.Complete, ObservedAt: observed, Digest: ingest.Digest(&request)}
	for i, f := range findings {
		in.Items = append(in.Items, store.IngestItem{Index: i, Ref: true, AssetKind: f.Asset.Ref.Kind, AssetKey: f.Asset.Ref.Key, Finding: model.FindingInput{Key: f.Key, Title: f.Title, Description: f.Description, Severity: f.Severity, Remediation: f.Remediation, Evidence: f.Evidence, Tags: f.Tags}})
	}
	_, err = a.proc.Ingest(ctx, in)
	return err
}

func (a *App) serveAssessmentBroker(ctx context.Context) error {
	server := &http.Server{Addr: a.cfg.Assessment.BrokerAddr, Handler: http.HandlerFunc(a.assessments.ServeBroker), MaxHeaderBytes: 16 << 10, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", server.Addr)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { // #nosec G118 -- broker shutdown must outlive its canceled serve context
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
	}()
	// Header timeouts alone do not bound simultaneously allocated connections.
	err = server.Serve(netutil.LimitListener(listener, 32))
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}

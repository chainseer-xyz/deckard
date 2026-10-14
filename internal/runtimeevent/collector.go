// Package runtimeevent collects bounded, read-only Tetragon event windows.
package runtimeevent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/chainseer-xyz/deckard/internal/ingest"
	"github.com/chainseer-xyz/deckard/internal/ingest/tetragon"
)

type Collector struct {
	client   kubernetes.Interface
	settings Settings
	now      func() time.Time
}

// Collect accepts only an all-successful, bounded event batch. It does not
// assert runtime coverage: new pods, rotation, restart and outage gaps may exist.
func (c *Collector) Collect(ctx context.Context) (ingest.Request, error) {
	if c == nil || c.client == nil {
		return ingest.Request{}, errors.New("tetragon collector is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, c.settings.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return ingest.Request{}, err
	}
	end := c.now().UTC()
	since := metav1.NewTime(end.Add(-c.settings.Lookback))
	pods, err := c.listPods(ctx)
	if err != nil {
		return ingest.Request{}, err
	}
	logs, err := c.fetchLogs(ctx, pods, &since)
	if err != nil {
		return ingest.Request{}, err
	}
	findings, err := tetragon.Parse(logs, ingest.ParseOptions{Scope: c.settings.ClusterScope})
	if err != nil {
		return ingest.Request{}, err
	}
	if err := ctx.Err(); err != nil {
		return ingest.Request{}, err
	}
	report := ingest.Request{Tool: tetragon.Tool, Scope: c.settings.ClusterScope, Complete: false, ObservedAt: &end, Findings: findings}
	if len(ingest.Validate(&report, ingest.Options{Now: end})) != 0 {
		return ingest.Request{}, errors.New("collected runtime envelope failed validation")
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > ingest.MaxBodyBytes {
		return ingest.Request{}, errors.New("collected runtime envelope exceeds the wire limit")
	}
	return report, nil
}

func (c *Collector) listPods(ctx context.Context) ([]corev1.Pod, error) {
	pods, err := c.podPages(ctx)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		return nil, errors.New("tetragon sensor pod set is empty")
	}
	seen := map[string]bool{}
	for _, pod := range pods {
		if pod.Namespace != c.settings.Namespace || pod.Name == "" || pod.UID == "" || seen[pod.Name] {
			return nil, errors.New("tetragon sensor pod identity is invalid or duplicated")
		}
		seen[pod.Name] = true
		found := false
		for _, container := range pod.Spec.Containers {
			if container.Name == c.settings.Container {
				found = true
			}
		}
		if !found {
			return nil, errors.New("configured Tetragon export container is absent")
		}
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
	return pods, nil
}

func (c *Collector) podPages(ctx context.Context) ([]corev1.Pod, error) {
	var pods []corev1.Pod
	seen := map[string]bool{}
	opts := metav1.ListOptions{LabelSelector: c.settings.Selector}
	for pages := 0; pages <= MaxPods; pages++ {
		opts.Limit = int64(c.settings.MaxPods + 1 - len(pods))
		page, err := c.client.CoreV1().Pods(c.settings.Namespace).List(ctx, opts)
		if err != nil {
			return nil, requestError(ctx, "tetragon pod listing failed")
		}
		pods = append(pods, page.Items...)
		if len(pods) > c.settings.MaxPods {
			return nil, errors.New("tetragon sensor pod count exceeds the limit")
		}
		if page.Continue == "" {
			return pods, nil
		}
		if seen[page.Continue] {
			return nil, errors.New("tetragon pod list pagination is inconsistent")
		}
		seen[page.Continue] = true
		opts.Continue = page.Continue
	}
	return nil, errors.New("tetragon pod list pagination exceeds the limit")
}

func (c *Collector) fetchLogs(ctx context.Context, pods []corev1.Pod, since *metav1.Time) ([]byte, error) {
	var total atomic.Int64
	logs := make([][]byte, len(pods))
	group, workerCtx := errgroup.WithContext(ctx)
	group.SetLimit(c.settings.Concurrency)
	for i, pod := range pods {
		if workerCtx.Err() != nil {
			break
		}
		group.Go(func() error {
			body, err := c.readLog(workerCtx, pod.Name, since, &total)
			if err == nil {
				logs[i] = body
			}
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	combined := bytes.Join(logs, []byte("\n"))
	if int64(len(combined)) > c.settings.MaxTotalBytes {
		return nil, errors.New("tetragon aggregate log bound exceeded")
	}
	return combined, nil
}

func (c *Collector) readLog(ctx context.Context, pod string, since *metav1.Time, total *atomic.Int64) ([]byte, error) {
	stream, err := c.client.CoreV1().Pods(c.settings.Namespace).GetLogs(pod, &corev1.PodLogOptions{Container: c.settings.Container, SinceTime: since}).Stream(ctx)
	if err != nil {
		return nil, requestError(ctx, "tetragon pod log request failed")
	}
	defer func() { _ = stream.Close() }()
	reader := &budgetReader{Reader: stream, total: total, limit: c.settings.MaxTotalBytes}
	data, err := io.ReadAll(io.LimitReader(reader, c.settings.MaxPodBytes+1))
	if err != nil {
		return nil, requestError(ctx, "tetragon pod log read failed or aggregate bound exceeded")
	}
	if int64(len(data)) > c.settings.MaxPodBytes {
		return nil, errors.New("tetragon per-pod log bound exceeded")
	}
	return data, nil
}

type budgetReader struct {
	io.Reader
	total *atomic.Int64
	limit int64
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	n, err := r.Reader.Read(p)
	if r.total.Add(int64(n)) > r.limit {
		return n, errors.New("tetragon aggregate log bound exceeded")
	}
	return n, err
}

func requestError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w", message, err)
	}
	return errors.New(message)
}

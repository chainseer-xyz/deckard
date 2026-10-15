package runtimeevent

import (
	"errors"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const (
	MaxPods                 = 64
	MaxConcurrency          = 4
	MaxReadBytes      int64 = 10 << 20
	MaxTotalReadBytes int64 = 256 << 20
	DefaultLookback         = 6 * time.Minute
	MaxLookback             = time.Hour
	DefaultTimeout          = time.Minute
	MaxTimeout              = 2 * time.Minute
)

// Settings narrows read-only Kubernetes access. Zero bounds select defaults;
// positive values may lower caps. Lookback may explicitly extend up to one hour.
type Settings struct {
	Namespace, Selector, Container, ClusterScope string
	Lookback, Timeout                            time.Duration
	MaxPods, Concurrency                         int
	MaxPodBytes, MaxTotalBytes                   int64
}

type Option func(*Collector)

func WithClock(now func() time.Time) Option { return func(c *Collector) { c.now = now } }

func New(client kubernetes.Interface, settings Settings, opts ...Option) (*Collector, error) {
	if client == nil {
		return nil, errors.New("tetragon collector requires a Kubernetes client")
	}
	settings = defaults(settings)
	if err := validate(settings); err != nil {
		return nil, err
	}
	c := &Collector{client: client, settings: settings, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.now == nil {
		return nil, errors.New("tetragon collector clock is unavailable")
	}
	return c, nil
}

func defaults(s Settings) Settings {
	if s.Lookback == 0 {
		s.Lookback = DefaultLookback
	}
	if s.Timeout == 0 {
		s.Timeout = DefaultTimeout
	}
	if s.MaxPods == 0 {
		s.MaxPods = MaxPods
	}
	if s.Concurrency == 0 {
		s.Concurrency = MaxConcurrency
	}
	if s.MaxPodBytes == 0 {
		s.MaxPodBytes = MaxReadBytes
	}
	if s.MaxTotalBytes == 0 {
		s.MaxTotalBytes = MaxTotalReadBytes
	}
	return s
}

func validate(s Settings) error {
	if len(validation.IsDNS1123Label(s.Namespace)) != 0 || len(validation.IsDNS1123Label(s.Container)) != 0 {
		return errors.New("tetragon collector requires an explicit valid namespace and container")
	}
	selector, err := labels.Parse(s.Selector)
	if err != nil || selector.Empty() {
		return errors.New("tetragon collector requires a valid nonempty pod selector")
	}
	uid := strings.TrimPrefix(s.ClusterScope, "k8s:uid:")
	if !strings.HasPrefix(s.ClusterScope, "k8s:uid:") || uid == "" || len(uid) > 128 {
		return errors.New("tetragon collector requires an immutable k8s:uid cluster scope")
	}
	for _, r := range uid {
		if r != '-' && r != '_' && r != '.' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return errors.New("tetragon collector cluster UID is invalid")
		}
	}
	if s.Lookback <= 0 || s.Lookback > MaxLookback || s.Timeout <= 0 || s.Timeout > MaxTimeout || s.MaxPods <= 0 || s.MaxPods > MaxPods || s.Concurrency <= 0 || s.Concurrency > MaxConcurrency || s.MaxPodBytes <= 0 || s.MaxPodBytes > MaxReadBytes || s.MaxTotalBytes <= 0 || s.MaxTotalBytes > MaxTotalReadBytes {
		return errors.New("tetragon collector bounds must be positive and within hard caps")
	}
	return nil
}

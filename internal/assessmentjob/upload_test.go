package assessmentjob_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

type blockedReport struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockedReport) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func (b *blockedReport) Close() error { return nil }

type countedBody struct{ reads atomic.Int32 }

func (b *countedBody) Read([]byte) (int, error) { b.reads.Add(1); return 0, io.EOF }
func (*countedBody) Close() error               { return nil }

func TestReportReservesSessionBeforeReadingBody(t *testing.T) {
	m, session, _, secret, _ := running(t, settings())
	body := &blockedReport{entered: make(chan struct{}), release: make(chan struct{})}
	first := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/report", body)
	setReportIdentity(first, session, string(secret.Data["upload-token"]))
	finished := make(chan struct{})
	defer func() {
		close(body.release)
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("admitted reader did not exit")
		}
	}()
	go func() {
		defer close(finished)
		m.ServeBroker(httptest.NewRecorder(), first)
	}()
	select {
	case <-body.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first report did not begin reading")
	}
	secondBody := &countedBody{}
	second := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/report", secondBody)
	setReportIdentity(second, session, string(secret.Data["upload-token"]))
	w := httptest.NewRecorder()
	m.ServeBroker(w, second)
	if w.Code != http.StatusConflict || secondBody.reads.Load() != 0 {
		t.Fatalf("concurrent report read before admission: status=%d reads=%d", w.Code, secondBody.reads.Load())
	}
}

func setReportIdentity(r *http.Request, session assessmentjob.Session, token string) {
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Deckard-Session", session.ID)
	r.Header.Set("X-Deckard-Tool", string(session.Tool))
}

func TestCompletedReportRejectsDuplicateBeforeReadingBody(t *testing.T) {
	m, session, _, secret, _ := running(t, settings())
	if status := submit(t, m, session, string(secret.Data["upload-token"])); status != http.StatusAccepted {
		t.Fatal(status)
	}
	body := &countedBody{}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/report", body)
	setReportIdentity(r, session, string(secret.Data["upload-token"]))
	w := httptest.NewRecorder()
	m.ServeBroker(w, r)
	if w.Code != http.StatusConflict || body.reads.Load() != 0 {
		t.Fatalf("duplicate report allocated/read payload: status=%d reads=%d", w.Code, body.reads.Load())
	}
}

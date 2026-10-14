// Package assessmentexec implements trusted, bounded assessment wrappers. It
// does not replace the manager's ownership checks or network isolation.
package assessmentexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/chainseer-xyz/deckard/internal/assessmentjob"
)

var ErrInvalid = errors.New("invalid assessment execution or upload")
var sessionID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,34}[a-z0-9])?$`)

type UploadOptions struct {
	ReportFile, DoneFile, URL, TokenFile, Session string
	Tool                                          assessmentjob.Tool
	Timeout                                       time.Duration
}

func Upload(ctx context.Context, options UploadOptions) error {
	return upload(ctx, options, newUploadClient())
}

func newUploadClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func upload(ctx context.Context, o UploadOptions, client *http.Client) error {
	if !validTool(o.Tool) || !sessionID.MatchString(o.Session) || o.Timeout <= 0 || o.Timeout > 15*time.Minute || o.ReportFile == o.DoneFile || brokerEndpoint(o.URL, "/v1/report") != nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	token, err := readToken(o.TokenFile)
	if err != nil {
		return ErrInvalid
	}
	if err := awaitDone(ctx, o.DoneFile); err != nil {
		return err
	}
	body, err := readRegular(o.ReportFile, outputLimit(o.Tool), false)
	if err != nil || !validReport(body, o.Tool) {
		return ErrInvalid
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, o.URL, bytes.NewReader(body))
	if err != nil {
		return ErrInvalid
	}
	r.Header.Set("Authorization", "Bearer "+string(token))
	r.Header.Set("X-Deckard-Session", o.Session)
	r.Header.Set("X-Deckard-Tool", string(o.Tool))
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return ErrInvalid // Never expose URL/token-bearing transport errors.
	}
	defer func() { _ = response.Body.Close() }()
	return checkReceipt(response, o.Session)
}

func brokerEndpoint(raw, path string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != path {
		return ErrInvalid
	}
	ip, err := netip.ParseAddr(u.Hostname())
	port, portErr := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || portErr != nil || port == 0 || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return ErrInvalid
	}
	return nil
}

func awaitDone(ctx context.Context, path string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := readRegular(path, 128, false)
		if err == nil {
			var done struct {
				Status string `json:"status"`
			}
			if decodeStrict(raw, &done) != nil || (done.Status != "succeeded" && done.Status != "failed") {
				return ErrInvalid
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return ErrInvalid
		}
		select {
		case <-ctx.Done():
			return errors.Join(ErrInvalid, ctx.Err())
		case <-ticker.C:
		}
	}
}

func checkReceipt(r *http.Response, session string) error {
	if r.StatusCode != http.StatusAccepted {
		return ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (4<<10)+1))
	var receipt struct {
		Session string `json:"session_id"`
		Status  string `json:"status"`
	}
	if err != nil || len(raw) > 4<<10 || decodeStrict(raw, &receipt) != nil || receipt.Session != session || receipt.Status != "report_received" {
		return ErrInvalid
	}
	return nil
}

func decodeStrict(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func validTool(tool assessmentjob.Tool) bool {
	return tool == assessmentjob.ToolZGrab2 || tool == assessmentjob.ToolZAP || tool == assessmentjob.ToolStrix
}

func outputLimit(tool assessmentjob.Tool) int64 {
	if tool == assessmentjob.ToolStrix {
		return 4 << 20
	}
	return 32 << 20
}

func validReport(raw []byte, tool assessmentjob.Tool) bool {
	if tool != assessmentjob.ToolZGrab2 {
		return json.Valid(raw)
	}
	count := 0
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if !json.Valid(line) {
			return false
		}
		count++
	}
	return count > 0
}

func readToken(path string) ([]byte, error) {
	token, err := readRegular(path, 256, true)
	if err != nil || len(token) < 32 {
		return nil, ErrInvalid
	}
	for _, b := range token {
		if b < 33 || b > 126 {
			return nil, ErrInvalid
		}
	}
	return token, nil
}

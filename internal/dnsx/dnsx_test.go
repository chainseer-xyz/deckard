package dnsx

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testServer is an in-process authoritative-ish server on 127.0.0.1 serving
// UDP and TCP on the same port.
type testServer struct {
	addr string
	mu   sync.Mutex
	h    dns.HandlerFunc
	udp  atomic.Int64
	tcp  atomic.Int64
}

func startServer(t *testing.T, h dns.HandlerFunc) *testServer {
	t.Helper()
	ts := &testServer{h: h}
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; i < 20; i++ {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
		pc = nil
	}
	if pc == nil {
		t.Fatal("no free udp+tcp port")
	}
	ts.addr = pc.LocalAddr().String()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			ts.tcp.Add(1)
		} else {
			ts.udp.Add(1)
		}
		ts.mu.Lock()
		h := ts.h
		ts.mu.Unlock()
		h(w, r)
	})
	started := make(chan struct{}, 2)
	us := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { started <- struct{}{} }}
	ss := &dns.Server{Listener: ln, Handler: handler, NotifyStartedFunc: func() { started <- struct{}{} }}
	go us.ActivateAndServe()
	go ss.ActivateAndServe()
	<-started
	<-started
	t.Cleanup(func() { us.Shutdown(); ss.Shutdown() })
	return ts
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// zone answers from a static table: name -> rcode and records.
type zone map[string]struct {
	rcode int
	rrs   []string
}

func (z zone) handler(t *testing.T) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		e, ok := z[strings.ToLower(q.Name)]
		if !ok {
			m.Rcode = dns.RcodeNameError
		} else {
			m.Rcode = e.rcode
			for _, s := range e.rrs {
				x := rr(t, s)
				if x.Header().Rrtype == q.Qtype || x.Header().Rrtype == dns.TypeCNAME {
					m.Answer = append(m.Answer, x)
				}
			}
		}
		_ = w.WriteMsg(m)
	}
}

func client(ts *testServer, opts ...Option) *Client {
	return New(append([]Option{WithServers(ts.addr), WithTimeout(500 * time.Millisecond), WithRetries(1)}, opts...)...)
}

func TestQueryNXDomainWithCNAMEChain(t *testing.T) {
	// A resolver following the chain answers NXDOMAIN but still carries the
	// CNAMEs: the case Go's net.Resolver loses.
	ts := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		m.Answer = []dns.RR{
			rr(t, "blog.example.com. 60 IN CNAME mid.example.net."),
			rr(t, "mid.example.net. 60 IN CNAME gone.example.org."),
		}
		_ = w.WriteMsg(m)
	})
	resp, err := client(ts).Query(context.Background(), "Blog.Example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeNameError || resp.State() != StateNXDomain {
		t.Fatalf("rcode=%d state=%v", resp.Rcode, resp.State())
	}
	want := []Hop{{"blog.example.com", "mid.example.net"}, {"mid.example.net", "gone.example.org"}}
	if len(resp.Chain) != 2 || resp.Chain[0] != want[0] || resp.Chain[1] != want[1] || resp.Final != "gone.example.org" {
		t.Fatalf("chain=%+v final=%s", resp.Chain, resp.Final)
	}
	ch, err := ResolveChain(context.Background(), client(ts), "blog.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ch.State != StateNXDomain || ch.End != "gone.example.org" || ch.Len() != 2 {
		t.Fatalf("chain=%+v", ch)
	}
}

func TestResolveChainOneHopAtATime(t *testing.T) {
	z := zone{
		"a.example.com.": {0, []string{"a.example.com. 60 IN CNAME b.example.net."}},
		"b.example.net.": {0, []string{"b.example.net. 60 IN CNAME c.example.org."}},
		// c.example.org absent -> NXDOMAIN
	}
	ts := startServer(t, z.handler(t))
	ch, err := ResolveChain(context.Background(), client(ts), "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ch.State != StateNXDomain || ch.End != "c.example.org" || ch.Len() != 2 {
		t.Fatalf("%+v", ch)
	}
	if got := strings.Join(ch.Names(), ">"); got != "a.example.com>b.example.net>c.example.org" {
		t.Fatal(got)
	}
}

func TestResolveChainHealthyAndNoData(t *testing.T) {
	z := zone{
		"www.example.com.": {0, []string{"www.example.com. 60 IN CNAME lb.example.net."}},
		"lb.example.net.":  {0, []string{"lb.example.net. 60 IN A 192.0.2.1"}},
		"v6.example.com.":  {0, nil}, // exists, no A
		"w6.example.com.":  {0, []string{"w6.example.com. 60 IN CNAME v6.example.com."}},
	}
	ts := startServer(t, z.handler(t))
	c := client(ts)
	ch, _ := ResolveChain(context.Background(), c, "www.example.com")
	if ch.State != StateResolved || ch.End != "lb.example.net" {
		t.Fatalf("%+v", ch)
	}
	ch, _ = ResolveChain(context.Background(), c, "w6.example.com")
	if ch.State != StateNoData || ch.End != "v6.example.com" || ch.Len() != 1 {
		t.Fatalf("%+v", ch)
	}
	ch, _ = ResolveChain(context.Background(), c, "nothing.example.com")
	if ch.State != StateNXDomain || ch.Len() != 0 {
		t.Fatalf("%+v", ch)
	}
}

func TestResolveChainLoops(t *testing.T) {
	z := zone{
		"a.example.com.": {0, []string{"a.example.com. 60 IN CNAME b.example.com."}},
		"b.example.com.": {0, []string{"b.example.com. 60 IN CNAME a.example.com."}},
		"s.example.com.": {0, []string{"s.example.com. 60 IN CNAME s.example.com."}},
	}
	ts := startServer(t, z.handler(t))
	c := client(ts)
	for _, n := range []string{"a.example.com", "s.example.com"} {
		ch, err := ResolveChain(context.Background(), c, n)
		if err != nil || ch.State != StateLoop {
			t.Fatalf("%s: %+v err=%v", n, ch, err)
		}
	}
	// A loop inside a single message.
	ts2 := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{rr(t, "x.example.com. 60 IN CNAME y.example.com."), rr(t, "y.example.com. 60 IN CNAME x.example.com.")}
		_ = w.WriteMsg(m)
	})
	ch, _ := ResolveChain(context.Background(), client(ts2), "x.example.com")
	if ch.State != StateLoop {
		t.Fatalf("%+v", ch)
	}
}

func TestResolveChainTooDeep(t *testing.T) {
	z := zone{}
	for i := 0; i < 30; i++ {
		n := string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.com."
		next := string(rune('a'+(i+1)%26)) + string(rune('a'+(i+1)/26)) + ".example.com."
		z[n] = struct {
			rcode int
			rrs   []string
		}{0, []string{n + " 60 IN CNAME " + next}}
	}
	ts := startServer(t, z.handler(t))
	ch, _ := ResolveChain(context.Background(), client(ts), "aa.example.com")
	if ch.State != StateTooDeep || ch.Len() != MaxChainDepth+1 {
		t.Fatalf("state=%v len=%d", ch.State, ch.Len())
	}
}

func TestServfailIsUnknownNotNXDomain(t *testing.T) {
	ts := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	c := client(ts)
	resp, err := c.Query(context.Background(), "x.example.com", dns.TypeA)
	if err != nil || resp.Rcode != dns.RcodeServerFailure || resp.State() != StateUnknown {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	ch, err := ResolveChain(context.Background(), c, "x.example.com")
	if err != nil || ch.State != StateUnknown || ch.State == StateNXDomain {
		t.Fatalf("%+v err=%v", ch, err)
	}
}

func TestServfailMidChainIsUnknown(t *testing.T) {
	z := zone{
		"a.example.com.": {0, []string{"a.example.com. 60 IN CNAME b.example.net."}},
		"b.example.net.": {dns.RcodeServerFailure, nil},
	}
	ts := startServer(t, z.handler(t))
	ch, _ := ResolveChain(context.Background(), client(ts), "a.example.com")
	if ch.State != StateUnknown || ch.End != "b.example.net" || ch.Len() != 1 {
		t.Fatalf("%+v", ch)
	}
}

func TestRetryRotatesPastServfail(t *testing.T) {
	var n atomic.Int64
	ts := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		if n.Add(1) == 1 {
			m.SetRcode(r, dns.RcodeServerFailure)
		} else {
			m.SetReply(r)
			m.Answer = []dns.RR{rr(t, "x.example.com. 60 IN A 192.0.2.7")}
		}
		_ = w.WriteMsg(m)
	})
	resp, err := client(ts, WithRetries(2)).Query(context.Background(), "x.example.com", dns.TypeA)
	if err != nil || resp.State() != StateResolved {
		t.Fatalf("%+v %v", resp, err)
	}
}

func TestTimeoutIsUnavailableAndUnknown(t *testing.T) {
	// A UDP socket that never answers.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	c := New(WithServers(pc.LocalAddr().String()), WithTimeout(100*time.Millisecond), WithRetries(1))
	_, err = c.Query(context.Background(), "x.example.com", dns.TypeA)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err=%v", err)
	}
	ch, err := ResolveChain(context.Background(), c, "x.example.com")
	if err != nil || ch.State != StateUnknown || ch.Err == nil {
		t.Fatalf("%+v err=%v", ch, err)
	}
}

func TestContextCancel(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	c := New(WithServers(pc.LocalAddr().String()), WithTimeout(5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ResolveChain(ctx, c, "x.example.com")
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	var ts *testServer
	ts = startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if _, ok := w.RemoteAddr().(*net.TCPAddr); !ok {
			m.Truncated = true
		} else {
			m.Answer = []dns.RR{rr(t, "big.example.com. 60 IN TXT \"hello\"")}
		}
		_ = w.WriteMsg(m)
	})
	resp, err := client(ts).Query(context.Background(), "big.example.com", dns.TypeTXT)
	if err != nil || !resp.UsedTCP || resp.State() != StateResolved {
		t.Fatalf("%+v %v", resp, err)
	}
	if ts.udp.Load() != 1 || ts.tcp.Load() != 1 {
		t.Fatalf("udp=%d tcp=%d", ts.udp.Load(), ts.tcp.Load())
	}
}

func TestEDNSAndDOBit(t *testing.T) {
	var sawDO atomic.Int64
	var sawEDNS atomic.Int64
	ts := startServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if o := r.IsEdns0(); o != nil {
			sawEDNS.Add(1)
			if o.Do() {
				sawDO.Add(1)
			}
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = r.IsEdns0() != nil && r.IsEdns0().Do()
		m.Answer = []dns.RR{rr(t, "example.com. 60 IN A 192.0.2.1")}
		_ = w.WriteMsg(m)
	})
	c := client(ts)
	resp, _ := c.Query(context.Background(), "example.com", dns.TypeA)
	if sawEDNS.Load() != 1 || sawDO.Load() != 0 || resp.AD {
		t.Fatalf("edns=%d do=%d ad=%v", sawEDNS.Load(), sawDO.Load(), resp.AD)
	}
	resp, _ = c.Query(context.Background(), "example.com", dns.TypeDNSKEY)
	if sawDO.Load() != 1 || !resp.AD {
		t.Fatalf("do=%d ad=%v", sawDO.Load(), resp.AD)
	}
	resp, _ = client(ts, WithDNSSEC()).Query(context.Background(), "example.com", dns.TypeA)
	if sawDO.Load() != 2 || !resp.AD {
		t.Fatalf("do=%d ad=%v", sawDO.Load(), resp.AD)
	}
}

func TestNoServersAndFallbackOptIn(t *testing.T) {
	empty := t.TempDir() + "/resolv.conf"
	if err := writeFile(empty, "# none\n"); err != nil {
		t.Fatal(err)
	}
	c := New(WithResolvConf(empty))
	if _, err := c.Query(context.Background(), "example.com", dns.TypeA); !errors.Is(err, ErrNoServers) {
		t.Fatalf("err=%v", err)
	}
	s, err := New(WithResolvConf(empty), WithPublicFallback()).Servers()
	if err != nil || len(s) == 0 {
		t.Fatalf("%v %v", s, err)
	}
	cf := t.TempDir() + "/resolv.conf"
	_ = writeFile(cf, "nameserver 127.0.0.9\n")
	if s, _ := New(WithResolvConf(cf), WithPublicFallback()).Servers(); len(s) != 1 || s[0] != "127.0.0.9:53" {
		t.Fatalf("resolv.conf must win over the public fallback: %v", s)
	}
}

func TestInvalidName(t *testing.T) {
	c := New(WithServers("127.0.0.1:1"))
	if _, err := c.Query(context.Background(), "", dns.TypeA); !errors.Is(err, ErrInvalidName) {
		t.Fatal(err)
	}
}

func TestConcurrentQueries(t *testing.T) {
	z := zone{"a.example.com.": {0, []string{"a.example.com. 60 IN A 192.0.2.1"}}}
	ts := startServer(t, z.handler(t))
	c := client(ts)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := ResolveChain(context.Background(), c, "a.example.com")
			if err != nil || ch.State != StateResolved {
				t.Errorf("%+v %v", ch, err)
			}
		}()
	}
	wg.Wait()
}

func TestAXFR(t *testing.T) {
	open := startServer(t, nil)
	handler := func(allow bool) dns.HandlerFunc {
		return func(w dns.ResponseWriter, r *dns.Msg) {
			q := r.Question[0]
			switch q.Qtype {
			case dns.TypeAXFR:
				if !allow {
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeRefused)
					_ = w.WriteMsg(m)
					return
				}
				ch := make(chan *dns.Envelope)
				tr := new(dns.Transfer)
				done := make(chan struct{})
				go func() {
					_ = tr.Out(w, r, ch)
					close(done)
				}()
				soa := rr(t, "example.com. 60 IN SOA ns1.example.com. h.example.com. 1 2 3 4 5")
				ch <- &dns.Envelope{RR: []dns.RR{soa, rr(t, "www.example.com. 60 IN A 192.0.2.1"), soa}}
				close(ch)
				<-done
			case dns.TypeNS:
				m := new(dns.Msg)
				m.SetReply(r)
				m.Answer = []dns.RR{rr(t, "example.com. 60 IN NS ns1.example.com.")}
				_ = w.WriteMsg(m)
			case dns.TypeA:
				m := new(dns.Msg)
				m.SetReply(r)
				m.Answer = []dns.RR{rr(t, "ns1.example.com. 60 IN A 127.0.0.1")}
				_ = w.WriteMsg(m)
			default:
				m := new(dns.Msg)
				m.SetReply(r)
				_ = w.WriteMsg(m)
			}
		}
	}
	open.mu.Lock()
	open.h = handler(true)
	open.mu.Unlock()
	_, port, _ := net.SplitHostPort(open.addr)
	// Route the nameserver's :53 to the test server.
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
	rep, err := AttemptAXFR(context.Background(), client(open), "example.com", dial)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Open()) != 1 || rep.Open()[0].Records != 3 {
		t.Fatalf("%+v", rep)
	}

	open.mu.Lock()
	open.h = handler(false)
	open.mu.Unlock()
	rep, _ = AttemptAXFR(context.Background(), client(open), "example.com", dial)
	if len(rep.Open()) != 0 || len(rep.Attempts) != 1 || rep.Attempts[0].Outcome != AXFRRefused {
		t.Fatalf("%+v", rep)
	}

	// A dialer that refuses (e.g. scope: NS address not owned) => skipped.
	rep, _ = AttemptAXFR(context.Background(), client(open), "example.com", func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("not owned")
	})
	if len(rep.Attempts) != 1 || rep.Attempts[0].Outcome != AXFRSkipped || rep.Attempts[0].Note != "not owned" {
		t.Fatalf("%+v", rep)
	}
}

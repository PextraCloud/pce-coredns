package pce_coredns

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/miekg/dns"
)

type stubHandler struct {
	called bool
	code   int
	err    error
}

func (h *stubHandler) Name() string { return "stub" }

func (h *stubHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	h.called = true
	return h.code, h.err
}

func TestPcePluginName(t *testing.T) {
	if (&PcePlugin{}).Name() != PluginName {
		t.Fatalf("unexpected plugin name")
	}
}

func expectLoadZones(mock sqlmock.Sqlmock, zones ...string) {
	rows := sqlmock.NewRows([]string{"dns_zone"})
	for _, zone := range zones {
		rows.AddRow(zone)
	}
	mock.ExpectQuery(regexp.QuoteMeta(loadZonesQuery)).WillReturnRows(rows)
}

func TestServeDNSLoadZonesError(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()

	mock.ExpectQuery(regexp.QuoteMeta(loadZonesQuery)).WillReturnError(errors.New("boom"))

	p := &PcePlugin{db: db}
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	code, err := p.ServeDNS(context.Background(), w, req)
	if code != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %d", code)
	}
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected propagated error, got %v", err)
	}
	if w.lastMsg == nil || w.lastMsg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected writer to capture SERVFAIL response")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSZoneNotFoundFallsThrough(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()
	expectLoadZones(mock, "example.org.")

	next := &stubHandler{code: dns.RcodeSuccess}
	p := &PcePlugin{Next: next, db: db}
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("test.example.com.", dns.TypeA)

	code, err := p.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("expected response from next handler, got %d", code)
	}
	if !next.called {
		t.Fatalf("expected next handler to be called")
	}
	if w.lastMsg != nil {
		t.Fatalf("expected no response written by pce plugin when falling through")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSLookupError(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()
	expectLoadZones(mock, "example.com.")
	mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnError(errors.New("lookup failed"))

	p := &PcePlugin{db: db}
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("host.example.com.", dns.TypeA)

	code, err := p.ServeDNS(context.Background(), w, req)
	if code != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got %d", code)
	}
	if err == nil || !strings.Contains(err.Error(), "lookup failed") {
		t.Fatalf("expected lookup error, got %v", err)
	}
	if w.lastMsg == nil || w.lastMsg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL response")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSNoRecordsFallthrough(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()
	expectLoadZones(mock, "example.com.")
	nodeRows := sqlmock.NewRows([]string{"ip_address", "node_dns_label", "cluster_dns_label", "datacenter_dns_label"})
	mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnRows(nodeRows)
	clusterRows := sqlmock.NewRows([]string{"cluster_dns_label", "cluster_leader_node_id", "datacenter_dns_label", "node_id", "node_ip_address", "node_dns_label"})
	mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnRows(clusterRows)

	next := &stubHandler{code: dns.RcodeSuccess}
	p := &PcePlugin{Next: next, db: db}
	p.setFallthroughZones([]string{"example.com"})
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("host.example.com.", dns.TypeA)

	code, err := p.ServeDNS(context.Background(), w, req)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if code != dns.RcodeSuccess {
		t.Fatalf("expected fallthrough success, got %d", code)
	}
	if !next.called {
		t.Fatalf("expected next handler to be called")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSNoRecordsNxDomain(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()
	expectLoadZones(mock, "example.com.")
	nodeRows := sqlmock.NewRows([]string{"ip_address", "node_dns_label", "cluster_dns_label", "datacenter_dns_label"})
	mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnRows(nodeRows)
	clusterRows := sqlmock.NewRows([]string{"cluster_dns_label", "cluster_leader_node_id", "datacenter_dns_label", "node_id", "node_ip_address", "node_dns_label"})
	mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnRows(clusterRows)

	p := &PcePlugin{db: db}
	p.setFallthroughZones([]string{"other.com"})
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("host.example.com.", dns.TypeA)

	code, err := p.ServeDNS(context.Background(), w, req)
	if code != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", code)
	}
	if err != nil {
		t.Fatalf("expected nil error for NXDOMAIN, got %v", err)
	}
	if w.lastMsg == nil || w.lastMsg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN response")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSSuccessResponse(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()
	expectLoadZones(mock, "example.com.")
	nodeRows := sqlmock.NewRows([]string{"ip_address", "node_dns_label", "cluster_dns_label", "datacenter_dns_label"}).
		AddRow("10.0.0.1", "service", "cluster1", "dc1")
	mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnRows(nodeRows)
	clusterRows := sqlmock.NewRows([]string{"cluster_dns_label", "cluster_leader_node_id", "datacenter_dns_label", "node_id", "node_ip_address", "node_dns_label"})
	mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnRows(clusterRows)

	p := &PcePlugin{db: db}
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("service.cluster1.dc1.example.com.", dns.TypeA)

	code, err := p.ServeDNS(context.Background(), w, req)
	if code != dns.RcodeSuccess || err != nil {
		t.Fatalf("expected success, got code=%d err=%v", code, err)
	}
	if w.lastMsg == nil || len(w.lastMsg.Answer) != 1 {
		t.Fatalf("expected single answer in response")
	}
	arec, ok := w.lastMsg.Answer[0].(*dns.A)
	if !ok || arec.A.String() != "10.0.0.1" {
		t.Fatalf("unexpected A record in response: %#v", w.lastMsg.Answer[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRecordToRRConversions(t *testing.T) {
	cases := []struct {
		name   string
		record dbRecord
		check  func(t *testing.T, rr dns.RR)
	}{
		{
			name: "A",
			record: dbRecord{
				FQDN:    "a.example.com.",
				Type:    dns.TypeA,
				TTL:     30,
				Content: dbRecordContent{IP: net.ParseIP("10.0.0.1")},
			},
			check: func(t *testing.T, rr dns.RR) {
				arec, ok := rr.(*dns.A)
				if !ok || arec.A.String() != "10.0.0.1" {
					t.Fatalf("unexpected A record: %#v", rr)
				}
			},
		},
		{
			name: "AAAA",
			record: dbRecord{
				FQDN:    "aaaa.example.com.",
				Type:    dns.TypeAAAA,
				TTL:     30,
				Content: dbRecordContent{IP: net.ParseIP("2001:db8::1")},
			},
			check: func(t *testing.T, rr dns.RR) {
				r, ok := rr.(*dns.AAAA)
				if !ok || r.AAAA.String() != "2001:db8::1" {
					t.Fatalf("unexpected AAAA record: %#v", rr)
				}
			},
		},
		{
			name: "CNAME",
			record: dbRecord{
				FQDN:    "alias.example.com.",
				Type:    dns.TypeCNAME,
				TTL:     30,
				Content: dbRecordContent{CNAME: "target.example.com"},
			},
			check: func(t *testing.T, rr dns.RR) {
				r, ok := rr.(*dns.CNAME)
				if !ok || r.Target != "target.example.com." {
					t.Fatalf("unexpected CNAME record: %#v", rr)
				}
			},
		},
		{
			name: "SRV",
			record: dbRecord{
				FQDN:    "_svc._tcp.example.com.",
				Type:    dns.TypeSRV,
				TTL:     30,
				Content: dbRecordContent{Priority: 10, Weight: 5, Port: 443, Target: "server.example.com"},
			},
			check: func(t *testing.T, rr dns.RR) {
				r, ok := rr.(*dns.SRV)
				if !ok || r.Priority != 10 || r.Target != "server.example.com." {
					t.Fatalf("unexpected SRV record: %#v", rr)
				}
			},
		},
		{
			name: "TXT",
			record: dbRecord{
				FQDN:    "txt.example.com.",
				Type:    dns.TypeTXT,
				TTL:     30,
				Content: dbRecordContent{Data: strings.Repeat("x", 300)},
			},
			check: func(t *testing.T, rr dns.RR) {
				r, ok := rr.(*dns.TXT)
				if !ok || len(r.Txt) != 2 {
					t.Fatalf("unexpected TXT record: %#v", rr)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr, err := recordToRR(&tc.record)
			if err != nil {
				t.Fatalf("recordToRR returned error: %v", err)
			}
			tc.check(t, rr)
		})
	}
}

func TestRecordToRRUnsupported(t *testing.T) {
	_, err := recordToRR(&dbRecord{Type: 65000})
	if err == nil || !strings.Contains(err.Error(), "unsupported record type") {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestRecordsToRRs(t *testing.T) {
	records := []dbRecord{
		{
			FQDN:    "a.example.com.",
			Type:    dns.TypeA,
			TTL:     30,
			Content: dbRecordContent{IP: net.ParseIP("10.0.0.1")},
		},
		{
			FQDN:    "txt.example.com.",
			Type:    dns.TypeTXT,
			TTL:     30,
			Content: dbRecordContent{Data: "hello"},
		},
	}

	answers, rcode, err := recordsToRRs(records)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got rcode=%d err=%v", rcode, err)
	}
	if len(answers) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(answers))
	}
}

func TestRecordsToRRsError(t *testing.T) {
	records := []dbRecord{{Type: 65000}}
	answers, rcode, err := recordsToRRs(records)
	if err == nil {
		t.Fatalf("expected error for unsupported record")
	}
	if rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL rcode, got %d", rcode)
	}
	if answers != nil {
		t.Fatalf("expected nil answers when conversion fails")
	}
}

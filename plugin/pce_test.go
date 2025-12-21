/*
Copyright 2025 Pextra Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package pce_coredns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type testResponseWriter struct {
	lastMsg *dns.Msg
}

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

func (w *testResponseWriter) WriteMsg(m *dns.Msg) error {
	w.lastMsg = m
	return nil
}

func (w *testResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *testResponseWriter) Close() error                { return nil }
func (w *testResponseWriter) TsigStatus() error           { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)         {}
func (w *testResponseWriter) Hijack()                     {}
func (w *testResponseWriter) LocalAddr() net.Addr         { return testAddr("127.0.0.1:53") }
func (w *testResponseWriter) RemoteAddr() net.Addr        { return testAddr("127.0.0.1:12345") }

func TestPcePluginValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		plugin  PcePlugin
		wantErr bool
	}{
		{
			name: "valid config",
			plugin: PcePlugin{
				DataSource: "postgres://user:pass@localhost/db",
				TableName:  "records",
				DefaultTTL: 60,
			},
		},
		{name: "missing datasource", plugin: PcePlugin{TableName: "records", DefaultTTL: 60}, wantErr: true},
		{name: "missing table", plugin: PcePlugin{DataSource: "dsn", DefaultTTL: 60}, wantErr: true},
		{name: "invalid ttl", plugin: PcePlugin{DataSource: "dsn", TableName: "records"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.plugin.ValidateConfig()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSetFallthroughZones(t *testing.T) {
	p := &PcePlugin{}
	p.setFallthroughZones(nil)
	if !reflect.DeepEqual(p.fallthroughZones, []string{"."}) {
		t.Fatalf("expected default fallthrough zone '.', got %v", p.fallthroughZones)
	}

	p.setFallthroughZones([]string{"example.com"})
	if !reflect.DeepEqual(p.fallthroughZones, []string{"example.com."}) {
		t.Fatalf("expected normalized zone 'example.com.', got %v", p.fallthroughZones)
	}
}

func TestSetZones(t *testing.T) {
	p := &PcePlugin{}
	p.setZones([]string{"example.com", "_tcp.example.org."})
	expected := []string{"example.com.", "_tcp.example.org."}
	if !reflect.DeepEqual(p.zones, expected) {
		t.Fatalf("unexpected zones: got %v want %v", p.zones, expected)
	}
}

func TestCanFallthrough(t *testing.T) {
	p := &PcePlugin{}
	p.setFallthroughZones([]string{"example.com"})
	if !p.canFallthrough("www.example.com.") {
		t.Fatalf("expected fallthrough zone to match")
	}
	if p.canFallthrough("example.org.") {
		t.Fatalf("did not expect fallthrough for other zone")
	}
}

func TestToRelativeName(t *testing.T) {
	tests := []struct {
		name string
		fqdn string
		zone string
		exp  string
	}{
		{"apex", "example.com.", "example.com.", ""},
		{"subdomain", "api.example.com.", "example.com.", "api"},
		{"no trailing dot", "www.example.com", "example.com.", "www"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := toRelativeName(tc.fqdn, tc.zone); got != tc.exp {
				t.Fatalf("expected %q got %q", tc.exp, got)
			}
		})
	}
}

func TestSplitTxtData(t *testing.T) {
	input := strings.Repeat("a", 260)
	parts := splitTxtData(input)
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	if len(parts[0]) != 255 {
		t.Fatalf("expected first part length 255, got %d", len(parts[0]))
	}
	if parts[0]+parts[1] != input {
		t.Fatalf("split parts do not reassemble original")
	}
}

func TestLoadZones(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"zone"}).AddRow("example.com.").AddRow("example.org.")
	mock.ExpectQuery("SELECT DISTINCT zone FROM records").WillReturnRows(rows)

	p := &PcePlugin{TableName: "records", db: db}
	if err := p.loadZones(context.Background()); err != nil {
		t.Fatalf("loadZones failed: %v", err)
	}
	if !reflect.DeepEqual(p.zones, []string{"example.com.", "example.org."}) {
		t.Fatalf("unexpected zones: %v", p.zones)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLoadZonesQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT zone FROM records").WillReturnError(fmt.Errorf("db down"))

	p := &PcePlugin{TableName: "records", db: db}
	if err := p.loadZones(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to load zones") {
		t.Fatalf("expected loadZones to propagate query error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLoadZonesScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"zone"}).AddRow(nil)
	mock.ExpectQuery("SELECT DISTINCT zone FROM records").WillReturnRows(rows)

	p := &PcePlugin{TableName: "records", db: db}
	if err := p.loadZones(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to scan zone") {
		t.Fatalf("expected scan error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLookupRecords(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	query := regexp.QuoteMeta("SELECT name, zone, type, ttl, content FROM records WHERE zone=$1 AND name=$2 AND type=$3")
	rows := sqlmock.NewRows([]string{"name", "zone", "type", "ttl", "content"}).
		AddRow("", "example.com.", "A", 120, `{"ip":"1.2.3.4"}`)
	mock.ExpectQuery(query).WithArgs("example.com.", "", "A").WillReturnRows(rows)

	p := &PcePlugin{TableName: "records", db: db}
	records, err := p.lookupRecords(context.Background(), "example.com.", "example.com.", "A")
	if err != nil {
		t.Fatalf("lookupRecords failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Zone != "example.com." || records[0].Name != "" {
		t.Fatalf("unexpected record: %+v", records[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLookupRecordsQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	query := regexp.QuoteMeta("SELECT name, zone, type, ttl, content FROM records WHERE zone=$1 AND name=$2 AND type=$3")
	mock.ExpectQuery(query).WithArgs("example.com.", "api", "A").WillReturnError(fmt.Errorf("db down"))

	p := &PcePlugin{TableName: "records", db: db}
	if _, err := p.lookupRecords(context.Background(), "example.com.", "api.example.com.", "A"); err == nil {
		t.Fatalf("expected lookup to fail when query errors")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestLookupRecordsScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	query := regexp.QuoteMeta("SELECT name, zone, type, ttl, content FROM records WHERE zone=$1 AND name=$2 AND type=$3")
	rows := sqlmock.NewRows([]string{"name", "zone", "type", "ttl", "content"}).
		AddRow(nil, "example.com.", "A", 60, `{"ip":"1.2.3.4"}`)
	mock.ExpectQuery(query).WithArgs("example.com.", "", "A").WillReturnRows(rows)

	p := &PcePlugin{TableName: "records", db: db}
	if _, err := p.lookupRecords(context.Background(), "example.com.", "example.com.", "A"); err == nil || !strings.Contains(err.Error(), "Scan") {
		t.Fatalf("expected scan error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestConnectSuccess(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	mock.ExpectPing()
	original := sqlOpen
	sqlOpen = func(driverName, dataSourceName string) (*sql.DB, error) {
		if driverName != "postgres" {
			t.Fatalf("unexpected driver: %s", driverName)
		}
		return db, nil
	}
	t.Cleanup(func() {
		sqlOpen = original
		db.Close()
	})

	p := &PcePlugin{DataSource: "dsn"}
	if err := p.Connect(); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if p.db != db {
		t.Fatalf("expected plugin db to be assigned")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestConnectOpenError(t *testing.T) {
	original := sqlOpen
	sqlOpen = func(string, string) (*sql.DB, error) {
		return nil, fmt.Errorf("open failed")
	}
	t.Cleanup(func() { sqlOpen = original })

	p := &PcePlugin{DataSource: "dsn"}
	if err := p.Connect(); err == nil || !strings.Contains(err.Error(), "failed to open database") {
		t.Fatalf("expected open failure, got %v", err)
	}
}

func TestConnectPingError(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	pingErr := errors.New("ping failed")
	mock.ExpectPing().WillReturnError(pingErr)
	original := sqlOpen
	sqlOpen = func(string, string) (*sql.DB, error) {
		return db, nil
	}
	t.Cleanup(func() {
		sqlOpen = original
		db.Close()
	})

	p := &PcePlugin{DataSource: "dsn"}
	if err := p.Connect(); err == nil || !strings.Contains(err.Error(), "failed to connect to database") {
		t.Fatalf("expected ping failure, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRecordsToRRs(t *testing.T) {
	records := []dbRecord{
		{Name: "", Zone: "example.com.", Type: "A", TTL: 0, Content: `{"ip":"1.2.3.4"}`},
		{Name: "www", Zone: "example.com.", Type: "AAAA", TTL: 120, Content: `{"ip":"2001:db8::1"}`},
		{Name: "_sip._tcp", Zone: "example.com.", Type: "SRV", TTL: 50, Content: `{"priority":10,"weight":20,"port":5060,"target":"srv.example.com"}`},
		{Name: "txt", Zone: "example.com.", Type: "TXT", TTL: 70, Content: "abcdefghijklmnopqrstuvwxyz"},
	}
	answers, rcode, err := recordsToRRs(records, 30)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected error: %v rcode=%d", err, rcode)
	}
	if len(answers) != 4 {
		t.Fatalf("expected 4 answers, got %d", len(answers))
	}
	if a, ok := answers[0].(*dns.A); !ok || a.Hdr.Ttl != 30 || a.A.String() != "1.2.3.4" {
		t.Fatalf("unexpected A record: %#v", answers[0])
	}
	if aaaa, ok := answers[1].(*dns.AAAA); !ok || aaaa.Hdr.Ttl != 120 || aaaa.AAAA.String() != "2001:db8::1" {
		t.Fatalf("unexpected AAAA record: %#v", answers[1])
	}
	if srv, ok := answers[2].(*dns.SRV); !ok || srv.Priority != 10 || srv.Target != "srv.example.com." {
		t.Fatalf("unexpected SRV record: %#v", answers[2])
	}
	if txt, ok := answers[3].(*dns.TXT); !ok || len(txt.Txt) != 1 || txt.Txt[0] != "abcdefghijklmnopqrstuvwxyz" {
		t.Fatalf("unexpected TXT record: %#v", answers[3])
	}
}

func TestRecordsToRRsUnsupported(t *testing.T) {
	_, rcode, err := recordsToRRs([]dbRecord{{Name: "bad", Zone: "example.com.", Type: "CNAME"}}, 30)
	if err == nil || rcode != dns.RcodeServerFailure {
		t.Fatalf("expected failure for unsupported type")
	}
}

func TestRecordJSONUnmarshalErrors(t *testing.T) {
	if _, err := (&dbRecord{Zone: "example.com", Type: "A", Content: "notjson"}).AsARecord(); err == nil {
		t.Fatalf("expected A record unmarshal error")
	}
	if _, err := (&dbRecord{Zone: "example.com", Type: "AAAA", Content: "notjson"}).AsAAAARecord(); err == nil {
		t.Fatalf("expected AAAA record unmarshal error")
	}
	if _, err := (&dbRecord{Zone: "example.com", Type: "SRV", Content: "notjson"}).AsSRVRecord(); err == nil {
		t.Fatalf("expected SRV record unmarshal error")
	}
}

func TestErrResponse(t *testing.T) {
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	state := request.Request{W: w, Req: req}
	code, err := errResponse(state, dns.RcodeServerFailure, fmt.Errorf("boom"))
	if code != dns.RcodeServerFailure {
		t.Fatalf("unexpected rcode %d", code)
	}
	if err == nil {
		t.Fatalf("expected error to be returned")
	}
	if w.lastMsg == nil || w.lastMsg.Rcode != dns.RcodeServerFailure || !w.lastMsg.Authoritative {
		t.Fatalf("unexpected response message: %#v", w.lastMsg)
	}
}

func TestSuccessResponse(t *testing.T) {
	w := &testResponseWriter{}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	state := request.Request{W: w, Req: req}
	ans := []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}}}
	code, err := successResponse(state, ans)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("unexpected response: code=%d err=%v", code, err)
	}
	if w.lastMsg == nil || len(w.lastMsg.Answer) != 1 || w.lastMsg.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected message %+v", w.lastMsg)
	}
}

func TestServeDNSSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT zone FROM records").WillReturnRows(sqlmock.NewRows([]string{"zone"}).AddRow("example.com."))
	lookupQuery := regexp.QuoteMeta("SELECT name, zone, type, ttl, content FROM records WHERE zone=$1 AND name=$2 AND type=$3")
	mock.ExpectQuery(lookupQuery).
		WithArgs("example.com.", "", "A").
		WillReturnRows(sqlmock.NewRows([]string{"name", "zone", "type", "ttl", "content"}).
			AddRow("", "example.com.", "A", 0, `{"ip":"1.2.3.4"}`))

	p := &PcePlugin{TableName: "records", DefaultTTL: 42, db: db}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	w := &testResponseWriter{}
	code, err := p.ServeDNS(context.Background(), w, msg)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("ServeDNS unexpected error: code=%d err=%v", code, err)
	}
	if w.lastMsg == nil || len(w.lastMsg.Answer) != 1 {
		t.Fatalf("expected single answer, got %#v", w.lastMsg)
	}
	if a, ok := w.lastMsg.Answer[0].(*dns.A); !ok || a.Hdr.Ttl != 42 || a.A.String() != "1.2.3.4" {
		t.Fatalf("unexpected answer: %#v", w.lastMsg.Answer[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSFallthrough(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT zone FROM records").WillReturnRows(sqlmock.NewRows([]string{"zone"}).AddRow("example.com."))
	lookupQuery := regexp.QuoteMeta("SELECT name, zone, type, ttl, content FROM records WHERE zone=$1 AND name=$2 AND type=$3")
	mock.ExpectQuery(lookupQuery).
		WithArgs("example.com.", "", "A").
		WillReturnRows(sqlmock.NewRows([]string{"name", "zone", "type", "ttl", "content"}))

	nextCalled := false
	p := &PcePlugin{TableName: "records", DefaultTTL: 42, db: db}
	p.setFallthroughZones([]string{"example.com."})
	p.Next = plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		return dns.RcodeSuccess, nil
	})
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	w := &testResponseWriter{}
	code, err := p.ServeDNS(context.Background(), w, msg)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("ServeDNS unexpected error: code=%d err=%v", code, err)
	}
	if !nextCalled {
		t.Fatalf("expected next plugin to be called")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSNxDomain(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT zone FROM records").WillReturnRows(sqlmock.NewRows([]string{"zone"}).AddRow("example.com."))
	lookupQuery := regexp.QuoteMeta("SELECT name, zone, type, ttl, content FROM records WHERE zone=$1 AND name=$2 AND type=$3")
	mock.ExpectQuery(lookupQuery).
		WithArgs("example.com.", "", "A").
		WillReturnRows(sqlmock.NewRows([]string{"name", "zone", "type", "ttl", "content"}))

	nextCalled := false
	p := &PcePlugin{TableName: "records", DefaultTTL: 42, db: db}
	p.Next = plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		return dns.RcodeSuccess, nil
	})
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	w := &testResponseWriter{}
	code, err := p.ServeDNS(context.Background(), w, msg)
	if err != nil || code != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got code=%d err=%v", code, err)
	}
	if nextCalled {
		t.Fatalf("did not expect next plugin to run")
	}
	if w.lastMsg == nil || w.lastMsg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN response, got %#v", w.lastMsg)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSLoadZonesError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT zone FROM records").WillReturnError(fmt.Errorf("boom"))

	p := &PcePlugin{TableName: "records", DefaultTTL: 42, db: db}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	w := &testResponseWriter{}
	code, err := p.ServeDNS(context.Background(), w, msg)
	if err == nil || code != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when loadZones fails")
	}
	if w.lastMsg == nil || w.lastMsg.Rcode != dns.RcodeServerFailure {
		t.Fatalf("unexpected response: %#v", w.lastMsg)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestServeDNSNoMatchingZone(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT DISTINCT zone FROM records").
		WillReturnRows(sqlmock.NewRows([]string{"zone"}).AddRow("example.com."))

	nextCalled := false
	p := &PcePlugin{TableName: "records", DefaultTTL: 42, db: db}
	p.Next = plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		return dns.RcodeSuccess, nil
	})
	msg := new(dns.Msg)
	msg.SetQuestion("other.org.", dns.TypeA)
	w := &testResponseWriter{}
	code, err := p.ServeDNS(context.Background(), w, msg)
	if err != nil || code != dns.RcodeSuccess {
		t.Fatalf("expected next plugin to handle request, code=%d err=%v", code, err)
	}
	if !nextCalled {
		t.Fatalf("expected next plugin invocation")
	}
	if w.lastMsg != nil {
		t.Fatalf("serveDNS should not write response when delegating, got %#v", w.lastMsg)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

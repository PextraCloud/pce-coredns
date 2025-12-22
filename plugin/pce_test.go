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

func newSQLMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	return db, mock
}

func TestPcePluginValidateConfig(t *testing.T) {
	if err := (&PcePlugin{DataSource: "dsn"}).ValidateConfig(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	if err := (&PcePlugin{}).ValidateConfig(); err == nil {
		t.Fatalf("expected validation error for missing datasource")
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
	db, mock := newSQLMock(t)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"dns_zone"}).AddRow("example.com.").AddRow("example.org.")
	mock.ExpectQuery("SELECT dns_zone FROM organizations").WillReturnRows(rows)

	p := &PcePlugin{db: db}
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

func TestLoadZonesErrors(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		mock.ExpectQuery("SELECT dns_zone FROM organizations").WillReturnError(fmt.Errorf("boom"))

		p := &PcePlugin{db: db}
		if err := p.loadZones(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to load zones") {
			t.Fatalf("expected query error, got %v", err)
		}
	})

	t.Run("scan", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"dns_zone"}).AddRow(nil)
		mock.ExpectQuery("SELECT dns_zone FROM organizations").WillReturnRows(rows)

		p := &PcePlugin{db: db}
		if err := p.loadZones(context.Background()); err == nil || !strings.Contains(err.Error(), "failed to scan zone") {
			t.Fatalf("expected scan error, got %v", err)
		}
	})
}

func TestLoadNodeRecords(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"ip_address", "node_dns_label", "cluster_dns_label", "datacenter_dns_label"}).
		AddRow("10.0.0.1", "node1", "cluster1", "dc1")
	mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnRows(rows)

	p := &PcePlugin{db: db}
	records, err := p.loadNodeRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("loadNodeRecords failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	rec := records[0]
	if rec.FQDN != "node1.cluster1.dc1.example.com." || rec.Type != dns.TypeA || rec.TTL != 30 {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.Content.IP.String() != "10.0.0.1" {
		t.Fatalf("unexpected IP: %v", rec.Content.IP)
	}
}

func TestLoadNodeRecordsErrors(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnError(fmt.Errorf("boom"))

		p := &PcePlugin{db: db}
		if _, err := p.loadNodeRecords(context.Background(), "example.com."); err == nil {
			t.Fatalf("expected query error")
		}
	})

	t.Run("scan", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"ip_address", "node_dns_label", "cluster_dns_label", "datacenter_dns_label"}).
			AddRow(nil, "node1", "cluster1", "dc1")
		mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnRows(rows)

		p := &PcePlugin{db: db}
		if _, err := p.loadNodeRecords(context.Background(), "example.com."); err == nil || !strings.Contains(err.Error(), "Scan") {
			t.Fatalf("expected scan error, got %v", err)
		}
	})
}

func TestLoadClusterRecords(t *testing.T) {
	db, mock := newSQLMock(t)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"cluster_dns_label", "cluster_leader_node_id", "datacenter_dns_label", "node_id", "node_ip_address", "node_dns_label"}).
		AddRow("cluster1", "node1", "dc1", "node1", "10.0.0.1", "node-one").
		AddRow("cluster1", "node1", "dc1", "node2", "10.0.0.2", "node-two")
	mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnRows(rows)

	p := &PcePlugin{db: db}
	records, err := p.loadClusterRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("loadClusterRecords failed: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records (2 A, 1 CNAME), got %d", len(records))
	}
	var cnameCount int
	for _, rec := range records {
		if rec.Type == dns.TypeCNAME {
			cnameCount++
		}
	}
	if cnameCount != 1 {
		t.Fatalf("expected single CNAME record, got %d", cnameCount)
	}
}

func TestLoadClusterRecordsErrors(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnError(fmt.Errorf("boom"))

		p := &PcePlugin{db: db}
		if _, err := p.loadClusterRecords(context.Background(), "example.com."); err == nil {
			t.Fatalf("expected query error")
		}
	})

	t.Run("scan", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		rows := sqlmock.NewRows([]string{"cluster_dns_label", "cluster_leader_node_id", "datacenter_dns_label", "node_id", "node_ip_address", "node_dns_label"}).
			AddRow(nil, "leader", "dc1", "node1", "10.0.0.1", "node-one")
		mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnRows(rows)

		p := &PcePlugin{db: db}
		if _, err := p.loadClusterRecords(context.Background(), "example.com."); err == nil || !strings.Contains(err.Error(), "Scan") {
			t.Fatalf("expected scan error, got %v", err)
		}
	})
}

func TestLookupRecords(t *testing.T) {
	setup := func(t *testing.T) (*PcePlugin, sqlmock.Sqlmock, func()) {
		db, mock := newSQLMock(t)
		cleanup := func() { db.Close() }

		nRows := sqlmock.NewRows([]string{"ip_address", "node_dns_label", "cluster_dns_label", "datacenter_dns_label"}).
			AddRow("10.0.0.1", "node1", "cluster1", "dc1")
		mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnRows(nRows)

		cRows := sqlmock.NewRows([]string{"cluster_dns_label", "cluster_leader_node_id", "datacenter_dns_label", "node_id", "node_ip_address", "node_dns_label"}).
			AddRow("cluster1", "leader", "dc1", "leader", "10.0.0.2", "nodeleader").
			AddRow("cluster1", "leader", "dc1", "node2", "10.0.0.3", "node-two")
		mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnRows(cRows)

		return &PcePlugin{db: db}, mock, cleanup
	}

	t.Run("exact A match", func(t *testing.T) {
		p, mock, cleanup := setup(t)
		defer cleanup()

		records, err := p.lookupRecords(context.Background(), "example.com.", "node1.cluster1.dc1.example.com.", dns.TypeA)
		if err != nil {
			t.Fatalf("lookupRecords failed: %v", err)
		}
		if len(records) != 1 || records[0].Type != dns.TypeA {
			t.Fatalf("expected 1 A record, got %+v", records)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("include CNAME for A query", func(t *testing.T) {
		p, mock, cleanup := setup(t)
		defer cleanup()

		records, err := p.lookupRecords(context.Background(), "example.com.", "leader.cluster1.dc1.example.com.", dns.TypeA)
		if err != nil {
			t.Fatalf("lookupRecords failed: %v", err)
		}
		if len(records) != 1 || records[0].Type != dns.TypeCNAME {
			t.Fatalf("expected leader CNAME, got %+v", records)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("ANY returns all matches", func(t *testing.T) {
		p, mock, cleanup := setup(t)
		defer cleanup()

		records, err := p.lookupRecords(context.Background(), "example.com.", "cluster1.dc1.example.com.", dns.TypeANY)
		if err != nil {
			t.Fatalf("lookupRecords failed: %v", err)
		}
		if len(records) != 2 {
			t.Fatalf("expected 2 A records, got %d", len(records))
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet expectations: %v", err)
		}
	})

	t.Run("loadNodeRecords error bubbles up", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnError(fmt.Errorf("boom"))

		p := &PcePlugin{db: db}
		if _, err := p.lookupRecords(context.Background(), "example.com.", "name", dns.TypeA); err == nil {
			t.Fatalf("expected node records error")
		}
	})

	t.Run("loadClusterRecords error bubbles up", func(t *testing.T) {
		db, mock := newSQLMock(t)
		defer db.Close()

		nRows := sqlmock.NewRows([]string{"ip_address", "node_dns_label", "cluster_dns_label", "datacenter_dns_label"})
		mock.ExpectQuery(regexp.QuoteMeta(nodeRecordsQuery)).WithArgs("example.com.").WillReturnRows(nRows)
		mock.ExpectQuery(regexp.QuoteMeta(clusterRecordsQuery)).WithArgs("example.com.").WillReturnError(fmt.Errorf("boom"))

		p := &PcePlugin{db: db}
		if _, err := p.lookupRecords(context.Background(), "example.com.", "name", dns.TypeA); err == nil {
			t.Fatalf("expected cluster records error")
		}
	})
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
		t.Fatalf("expected db handle assignment")
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
	mock.ExpectPing().WillReturnError(errors.New("ping failed"))
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

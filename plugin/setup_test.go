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
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
)

func stubSQLOpen(t *testing.T, db *sql.DB) {
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
}

func TestParseConfigSuccess(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	mock.ExpectPing()
	stubSQLOpen(t, db)

	c := caddy.NewTestController("dns", `pce {
		datasource postgres://user:pass@localhost/db
		table records
		ttl 120
		fallthrough example.com example.org
	}`)
	p, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig failed: %v", err)
	}
	if p.DataSource != "postgres://user:pass@localhost/db" {
		t.Fatalf("unexpected datasource: %s", p.DataSource)
	}
	if p.TableName != "records" {
		t.Fatalf("unexpected table name: %s", p.TableName)
	}
	if p.DefaultTTL != 120 {
		t.Fatalf("unexpected ttl: %d", p.DefaultTTL)
	}
	expectedZones := []string{"example.com.", "example.org."}
	if !reflect.DeepEqual(p.fallthroughZones, expectedZones) {
		t.Fatalf("unexpected fallthrough zones: %v", p.fallthroughZones)
	}
	if p.db != db {
		t.Fatalf("database handle was not assigned")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestParseConfigValidationError(t *testing.T) {
	c := caddy.NewTestController("dns", `pce {
		datasource dsn
		table records
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestParseConfigInvalidTTL(t *testing.T) {
	c := caddy.NewTestController("dns", `pce {
		datasource dsn
		table records
		ttl nope
	}`)
	if _, err := parseConfig(c); err == nil || !strings.Contains(err.Error(), "invalid ttl value") {
		t.Fatalf("expected invalid ttl error, got %v", err)
	}
}

func TestParseConfigUnknownProperty(t *testing.T) {
	c := caddy.NewTestController("dns", `pce {
		datasource dsn
		bogus value
	}`)
	if _, err := parseConfig(c); err == nil || !strings.Contains(err.Error(), "unknown property") {
		t.Fatalf("expected unknown property error, got %v", err)
	}
}

func TestParseConfigMissingDatasourceArg(t *testing.T) {
	c := caddy.NewTestController("dns", `pce {
		datasource
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatalf("expected missing argument error")
	}
}

func TestSetupRegistersPlugin(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	mock.ExpectPing()
	stubSQLOpen(t, db)

	c := caddy.NewTestController("dns", `pce {
		datasource postgres://user:pass@localhost/db
		table records
		ttl 60
	}`)
	if err := setup(c); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	_ = dnsserver.GetConfig(c)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSetupPropagatesError(t *testing.T) {
	c := caddy.NewTestController("dns", `pce {
		datasource dsn
		table records
	}`)
	if err := setup(c); err == nil {
		t.Fatalf("expected setup to fail when parseConfig fails")
	}
}

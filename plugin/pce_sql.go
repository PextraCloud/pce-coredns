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
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

func (p *PcePlugin) Connect() error {
	db, err := sql.Open("postgres", p.DataSource)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// Test db connection
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to connect to database: %v", err)
	}

	// TODO: make configurable
	db.SetConnMaxLifetime(time.Minute)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	p.db = db
	return nil
}

func (p *PcePlugin) loadZones(ctx context.Context) error {
	query := `SELECT DISTINCT zone FROM ` + p.TableName
	rows, err := p.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to load zones from database: %v", err)
	}
	defer rows.Close()

	var zones []string
	var zone string
	for rows.Next() {
		if err := rows.Scan(&zone); err != nil {
			return fmt.Errorf("failed to scan zone: %v", err)
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating over zones: %v", err)
	}

	p.setZones(zones)
	return nil
}

// toRelativeName converts a FQDN to a name relative to the given zone.
func toRelativeName(name, zone string) string {
	// Remove trailing dots (normalize)
	zone = strings.TrimSuffix(zone, ".")
	name = strings.TrimSuffix(name, ".")

	// Zone apex
	if name == zone {
		return ""
	}

	// Remove zone suffix from name
	return strings.TrimSuffix(name, "."+zone)
}

func (p *PcePlugin) lookupRecords(ctx context.Context, zone, name string, qtype string) ([]dbRecord, error) {
	relativeName := toRelativeName(name, zone)
	query := `SELECT name, zone, type, ttl, content FROM ` + p.TableName + ` WHERE zone=$1 AND name=$2 AND type=$3`
	rows, err := p.db.QueryContext(ctx, query, zone, relativeName, qtype)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []dbRecord
	var rName, rZone, rType, rContent string
	var rTTL int
	for rows.Next() {
		if err := rows.Scan(&rName, &rZone, &rType, &rTTL, &rContent); err != nil {
			return nil, err
		}

		records = append(records, dbRecord{
			Name:    rName,
			Zone:    rZone,
			Type:    rType,
			TTL:     uint32(rTTL),
			Content: rContent,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

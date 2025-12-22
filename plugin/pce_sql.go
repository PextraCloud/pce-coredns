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
	"net"
	"time"

	_ "github.com/lib/pq"
	"github.com/miekg/dns"
)

const loadZonesQuery = `SELECT dns_zone FROM organizations`
const nodeRecordsQuery = `SELECT
	nodes.ip_address,
	nodes.dns_label AS node_dns_label,
	clusters.dns_label AS cluster_dns_label,
	datacenters.dns_label AS datacenter_dns_label
FROM nodes
	INNER JOIN clusters ON nodes.cluster_id = clusters.id
	INNER JOIN datacenters ON clusters.datacenter_id = datacenters.id
	INNER JOIN organizations ON datacenters.organization_id = organizations.id
WHERE
	nodes.alive = true
	AND nodes.last_seen >= NOW() - INTERVAL '60 seconds'
	AND organizations.dns_zone = $1`
const clusterRecordsQuery = `SELECT
	clusters.dns_label AS cluster_dns_label,
	clusters.leader_id AS cluster_leader_node_id,
	datacenters.dns_label AS datacenter_dns_label,
	nodes.id AS node_id,
	nodes.ip_address AS node_ip_address,
	nodes.dns_label AS node_dns_label
FROM nodes
	INNER JOIN clusters ON nodes.cluster_id = clusters.id
	INNER JOIN datacenters ON clusters.datacenter_id = datacenters.id
	INNER JOIN organizations ON datacenters.organization_id = organizations.id
WHERE
	nodes.alive = true
	AND nodes.last_seen >= NOW() - INTERVAL '60 seconds'
	AND organizations.dns_zone = $1`

var sqlOpen = sql.Open

func (p *PcePlugin) Connect() error {
	db, err := sqlOpen("postgres", p.DataSource)
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
	rows, err := p.db.QueryContext(ctx, loadZonesQuery)
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

func (p *PcePlugin) loadNodeRecords(ctx context.Context, zone string) ([]dbRecord, error) {
	// TODO: support ipv6 (AAAA)
	rows, err := p.db.QueryContext(ctx, nodeRecordsQuery, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []dbRecord
	var ipAddress, nodeDNSLabel, clusterDNSLabel, datacenterDNSLabel string
	for rows.Next() {
		if err := rows.Scan(&ipAddress, &nodeDNSLabel, &clusterDNSLabel, &datacenterDNSLabel); err != nil {
			return nil, err
		}

		fqdn := dns.Fqdn(fmt.Sprintf("%s.%s.%s.%s", nodeDNSLabel, clusterDNSLabel, datacenterDNSLabel, zone))
		records = append(records, dbRecord{
			FQDN: fqdn,
			Type: dns.TypeA,
			TTL:  30,
			// TODO: potential panic (net.ParseIP) if IP is invalid
			Content: dbRecordContent{IP: net.ParseIP(ipAddress)},
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (p *PcePlugin) loadClusterRecords(ctx context.Context, zone string) ([]dbRecord, error) {
	// TODO: support ipv6 (AAAA)
	rows, err := p.db.QueryContext(ctx, clusterRecordsQuery, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []dbRecord
	var clusterDNSLabel, clusterLeaderNodeID, datacenterDNSLabel, nodeID, nodeIPAddress, nodeDNSLabel string
	for rows.Next() {
		if err := rows.Scan(&clusterDNSLabel, &clusterLeaderNodeID, &datacenterDNSLabel, &nodeID, &nodeIPAddress, &nodeDNSLabel); err != nil {
			return nil, err
		}

		// Cluster nodes: `<cluster>.<datacenter>.<organization zone>`
		fqdn := dns.Fqdn(fmt.Sprintf("%s.%s.%s", clusterDNSLabel, datacenterDNSLabel, zone))
		records = append(records, dbRecord{
			FQDN:    fqdn,
			Type:    dns.TypeA,
			TTL:     30,
			Content: dbRecordContent{IP: net.ParseIP(nodeIPAddress)},
		})

		// Cluster leader CNAME: `leader.<cluster>.<datacenter>.<organization zone>`
		if nodeID == clusterLeaderNodeID {
			leaderFQDN := dns.Fqdn(fmt.Sprintf("leader.%s.%s.%s", clusterDNSLabel, datacenterDNSLabel, zone))
			nodeFQDN := dns.Fqdn(fmt.Sprintf("%s.%s.%s.%s", nodeDNSLabel, clusterDNSLabel, datacenterDNSLabel, zone))

			records = append(records, dbRecord{
				FQDN:    leaderFQDN,
				Type:    dns.TypeCNAME,
				TTL:     30,
				Content: dbRecordContent{CNAME: nodeFQDN},
			})
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (p *PcePlugin) lookupRecords(ctx context.Context, zone, name string, qtype uint16) ([]dbRecord, error) {
	records, err := p.loadNodeRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	clusterRecords, err := p.loadClusterRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	records = append(records, clusterRecords...)

	nameFqdn := dns.Fqdn(name)
	var filtered []dbRecord

	// Find matches based on FQDN and query type
	for _, record := range records {
		if record.FQDN != nameFqdn {
			continue
		}

		if qtype == dns.TypeANY || record.Type == qtype {
			// Match type if not ANY
			filtered = append(filtered, record)
		} else if (qtype == dns.TypeA || qtype == dns.TypeAAAA) && record.Type == dns.TypeCNAME {
			// Special case: include CNAME records when querying A/AAAA
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

/*
Copyright 2026 Pextra Inc.

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
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	ilog "github.com/PextraCloud/pce-coredns/internal/log"
	"github.com/PextraCloud/pce-coredns/internal/util"
	"github.com/lib/pq"
	"github.com/miekg/dns"
)

const nodeRecordsQuery = `SELECT
	node_addresses.node_id,
	HOST(node_addresses.address) AS address,
	FAMILY(node_addresses.address) AS address_family,
	node_addresses.is_default,
	COALESCE(ARRAY_REMOVE(ARRAY_AGG(node_address_roles.role), NULL), ARRAY[]::text[]) AS address_roles
FROM node_addresses
	LEFT JOIN node_address_roles ON node_addresses.id = node_address_roles.node_address_id
GROUP BY
	node_addresses.node_id,
	address,
	address_family,
	node_addresses.is_default;`

type nodeRecord struct {
	Address       string
	AddressFamily string
	IsDefault     bool
	Roles         []string
}
type defaultAddressMapV struct {
	Address       string
	AddressFamily string
}

func getFqdnsForNode(nodeId string, roles []string) []string {
	fqdns := []string{}
	for _, role := range roles {
		// <nodeId>-<role>.pce.internal.
		fqdns = append(fqdns, dns.CanonicalName(fmt.Sprintf("%s-%s.%s", nodeId, role, util.ZoneDynamic)))
	}
	return fqdns
}

func (p *Plugin) loadNodeRecords(ctx context.Context) ([]util.Record, error) {
	if p.db == nil {
		p.Connect()
	}
	if p.db == nil {
		return nil, fmt.Errorf("db connection not initialized")
	}

	rows, err := p.queryNodeRecords(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodeRecordsMap, defaultAddressMap, err := scanNodeRecords(rows)
	if err != nil {
		return nil, err
	}

	records, err := buildDNSRecords(nodeRecordsMap, defaultAddressMap)
	if err != nil {
		return nil, err
	}

	if err := rows.Err(); err != nil {
		ilog.Log.Errorf("db: rows error while loading records: %v", err)
		return nil, err
	}

	ilog.Log.Debugf("db: loaded %d record(s)", len(records))
	return records, nil
}

func (p *Plugin) queryNodeRecords(ctx context.Context) (*sql.Rows, error) {
	rows, err := p.db.QueryContext(ctx, nodeRecordsQuery)
	if err != nil {
		ilog.Log.Errorf("db: failed to query node records: %v", err)
		return nil, err
	}
	return rows, nil
}

func scanNodeRecords(rows *sql.Rows) (map[string][]nodeRecord, map[string]defaultAddressMapV, error) {
	// `nodeId` -> `[]nodeRecord`
	nodeRecordsMap := make(map[string][]nodeRecord)
	// `nodeId` -> `defaultAddressMapV`
	defaultAddressMap := make(map[string]defaultAddressMapV)

	for rows.Next() {
		var nodeId string
		r := nodeRecord{}
		if err := rows.Scan(&nodeId, &r.Address, &r.AddressFamily, &r.IsDefault, pq.Array(&r.Roles)); err != nil {
			ilog.Log.Errorf("db: failed to scan node record: %v", err)
			return nil, nil, err
		}

		// Group records by node ID
		nodeRecordsMap[nodeId] = append(nodeRecordsMap[nodeId], r)

		// Store default address (for unassigned roles fallback)
		if r.IsDefault {
			defaultAddressMap[nodeId] = defaultAddressMapV{
				Address:       r.Address,
				AddressFamily: r.AddressFamily,
			}
		}
	}
	return nodeRecordsMap, defaultAddressMap, nil
}

func buildDNSRecords(nodeRecordsMap map[string][]nodeRecord, defaultAddressMap map[string]defaultAddressMapV) ([]util.Record, error) {
	records := []util.Record{}
	// Process each node's records
	for nodeId, nodeRecords := range nodeRecordsMap {
		finalNodeRecords := expandRolesWithDefaults(nodeId, nodeRecords, defaultAddressMap)

		// Create actual util.Record records for all nodeRecords
		for _, r := range finalNodeRecords {
			recs, err := recordsForNodeRecord(nodeId, r)
			if err != nil {
				return nil, err
			}
			records = append(records, recs...)
		}
	}
	return records, nil
}

func expandRolesWithDefaults(nodeId string, nodeRecords []nodeRecord, defaultAddressMap map[string]defaultAddressMapV) []nodeRecord {
	// Gather explicitly assigned roles; unassigned roles fallback to default address
	assignedRoles := map[string]struct{}{}
	for _, r := range nodeRecords {
		for _, role := range r.Roles {
			assignedRoles[role] = struct{}{}
		}
	}
	// Add synthetic records for unassigned roles using default address
	if defaultAddr, ok := defaultAddressMap[nodeId]; ok {
		for _, role := range util.RolesList {
			if _, assigned := assignedRoles[role]; !assigned {
				nodeRecords = append(nodeRecords, nodeRecord{
					Address:       defaultAddr.Address,
					AddressFamily: defaultAddr.AddressFamily,
					IsDefault:     true,
					Roles:         []string{role},
				})
			}
		}
	}

	return nodeRecords
}

func recordsForNodeRecord(nodeId string, r nodeRecord) ([]util.Record, error) {
	fqdns := getFqdnsForNode(nodeId, r.Roles)
	ip := net.ParseIP(r.Address)
	if ip == nil {
		ilog.Log.Warningf("db: skipping node %q with invalid IP %q", nodeId, r.Address)
		return nil, nil
	}

	switch r.AddressFamily {
	case "4":
		return buildIPRecords(fqdns, dns.TypeA, ip), nil
	case "6":
		return buildIPRecords(fqdns, dns.TypeAAAA, ip), nil
	default:
		return nil, fmt.Errorf("unknown address family %q for node %q", r.AddressFamily, nodeId)
	}
}

func buildIPRecords(fqdns []string, recordType uint16, ip net.IP) []util.Record {
	records := make([]util.Record, 0, len(fqdns))
	for _, fqdn := range fqdns {
		records = append(records, util.Record{
			FQDN: fqdn,
			Type: recordType,
			TTL:  30,
			Content: util.RecordContent{
				IP: ip,
			},
		})
	}
	return records
}

func (p *Plugin) LookupRecords(ctx context.Context, name string, qtype uint16) ([]util.Record, error) {
	// TODO: cache to avoid hitting DB on every query
	records, err := p.loadNodeRecords(ctx)
	if err != nil {
		ilog.Log.Warningf("db: failed to load records for %q: %v", name, err)
		return nil, err
	}

	nameFqdn := dns.CanonicalName(name)
	var filtered []util.Record

	// Find matches based on FQDN and query type
	for _, record := range records {
		if dns.CanonicalName(record.FQDN) != nameFqdn {
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

	ilog.Log.Debugf("db: lookup matched %d record(s) for name=%q", len(filtered), name)
	return filtered, nil
}

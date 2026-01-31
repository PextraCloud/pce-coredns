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
	"fmt"
	"net"

	ilog "github.com/PextraCloud/pce-coredns/internal/log"
	"github.com/PextraCloud/pce-coredns/internal/util"
	"github.com/miekg/dns"
)

const zoneSuffix = "pce.internal."

const nodeRecordsQuery = `SELECT
	node_addresses.node_id,
	host(node_addresses.address) AS address,
	family(node_addresses.address) AS address_family,
	node_addresses.is_default,
	array_agg(node_address_roles.role) AS address_roles
FROM node_addresses
	INNER JOIN nodes ON node_addresses.node_id = nodes.id
	INNER JOIN node_address_roles ON node_addresses.id = node_address_roles.node_address_id
WHERE
	nodes.alive = true
	AND nodes.last_seen >= NOW() - INTERVAL '60 seconds'
GROUP BY
	node_addresses.node_id,
	node_addresses.address,
	node_addresses.is_default;`

func getFqdnsForNode(nodeId string, roles []string, isDefault bool) []string {
	fqdns := []string{}
	if isDefault {
		// <nodeId>.pce.internal.
		fqdns = append(fqdns, dns.Fqdn(fmt.Sprintf("%s.%s", nodeId, zoneSuffix)))
	}
	for _, role := range roles {
		// <nodeId>-<role>.pce.internal.
		fqdns = append(fqdns, dns.Fqdn(fmt.Sprintf("%s-%s.%s", nodeId, role, zoneSuffix)))
	}
	return fqdns
}

func (p *Plugin) loadNodeRecords(ctx context.Context) ([]util.Record, error) {
	if p.db == nil {
		ilog.Log.Warningf("db: lookup requested with no active connection")
		return nil, fmt.Errorf("db connection not initialized")
	}

	ilog.Log.Debugf("db: loading node records")
	rows, err := p.db.QueryContext(ctx, nodeRecordsQuery)
	if err != nil {
		ilog.Log.Errorf("db: failed to query node records: %v", err)
		return nil, err
	}
	defer rows.Close()

	records := []util.Record{}
	for rows.Next() {
		var nodeId string
		var address string
		var addressFamily string
		var isDefault bool
		var roles []string

		if err := rows.Scan(&nodeId, &address, &addressFamily, &isDefault, &roles); err != nil {
			ilog.Log.Errorf("db: failed to scan node record: %v", err)
			return nil, err
		}

		fqdns := getFqdnsForNode(nodeId, roles, isDefault)
		switch addressFamily {
		case "4":
			for _, fqdn := range fqdns {
				records = append(records, util.Record{
					FQDN: fqdn,
					Type: dns.TypeA,
					TTL:  30,
					Content: util.RecordContent{
						IP: net.ParseIP(address),
					},
				})
			}
		case "6":
			for _, fqdn := range fqdns {
				records = append(records, util.Record{
					FQDN: fqdn,
					Type: dns.TypeAAAA,
					TTL:  30,
					Content: util.RecordContent{
						IP: net.ParseIP(address),
					},
				})
			}
		default:
			ilog.Log.Warningf("db: unknown address family %q for node %q", addressFamily, nodeId)
			return nil, fmt.Errorf("unknown address family %q for node %q", addressFamily, nodeId)
		}
	}

	if err := rows.Err(); err != nil {
		ilog.Log.Errorf("db: rows error while loading records: %v", err)
		return nil, err
	}

	ilog.Log.Debugf("db: loaded %d record(s)", len(records))
	return records, nil
}

func (p *Plugin) LookupRecords(ctx context.Context, name string, qtype uint16) ([]util.Record, error) {
	typeName := dns.TypeToString[qtype]
	if typeName == "" {
		typeName = fmt.Sprintf("%d", qtype)
	}
	ilog.Log.Debugf("db: lookup name=%q qtype=%s", name, typeName)

	records, err := p.loadNodeRecords(ctx)
	if err != nil {
		ilog.Log.Errorf("db: failed to load records for %q: %v", name, err)
		return nil, err
	}

	nameFqdn := dns.Fqdn(name)
	var filtered []util.Record

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

	ilog.Log.Debugf("db: lookup matched %d record(s) for name=%q", len(filtered), name)
	return filtered, nil
}

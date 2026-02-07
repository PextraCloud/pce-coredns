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
package static

import (
	"encoding/json"
	"net"
	"os"

	ilog "github.com/PextraCloud/pce-coredns/internal/log"
	"github.com/PextraCloud/pce-coredns/internal/util"
	"github.com/miekg/dns"
)

type staticFile struct {
	Version string `json:"version"`
	// id -> IP address
	Nodes            map[string]string `json:"nodes"`
	ClusterId        string            `json:"cluster_id"`
	DatacenterId     string            `json:"datacenter_id"`
	JoiningToCluster bool              `json:"joining_to_cluster"`
}

// parseStaticFile reads and parses the static config file, returning the list of records.
func parseStaticFile(file *os.File, ttl uint32) ([]util.Record, error) {
	decoder := json.NewDecoder(file)
	var config staticFile
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	records := make([]util.Record, 0, len(config.Nodes))
	for nodeId, ipStr := range config.Nodes {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			ilog.Log.Warningf("static: skipping node %q with invalid IP %q", nodeId, ipStr)
			continue
		}

		var recType uint16
		if ip.To4() != nil {
			recType = dns.TypeA
		} else {
			recType = dns.TypeAAAA
		}
		record := util.Record{
			FQDN: dns.CanonicalName(nodeId + "." + util.ZoneBootstrap),
			Type: recType,
			TTL:  ttl,
			Content: util.RecordContent{
				IP: ip,
			},
		}
		records = append(records, record)
	}
	return records, nil
}

func (p *Plugin) ReadStatic() {
	file, err := os.Open(p.Path)
	if err != nil {
		ilog.Log.Debugf("static: failed to open file %s: %v", p.Path, err)
		return
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		ilog.Log.Warningf("static: failed to stat file %s: %v", p.Path, err)
		return
	}

	p.mu.RLock()
	unchanged := (stat.Size() == p.cachedSize) && stat.ModTime().Equal(p.cachedMtime)
	p.mu.RUnlock()
	if unchanged {
		// No changes
		return
	}

	records, err := parseStaticFile(file, p.TTL)
	if err != nil {
		ilog.Log.Errorf("static: failed to parse file %s: %v", p.Path, err)
		return
	}

	p.mu.Lock()
	p.records = records
	p.cachedSize = stat.Size()
	p.cachedMtime = stat.ModTime()
	p.mu.Unlock()

	ilog.Log.Infof("static: refreshed %d record(s) from %s", len(records), p.Path)
}

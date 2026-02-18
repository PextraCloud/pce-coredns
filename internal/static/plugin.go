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
	"context"
	"sync"
	"time"

	ilog "github.com/PextraCloud/pce-coredns/internal/log"
	"github.com/PextraCloud/pce-coredns/internal/util"
	"github.com/miekg/dns"
)

type Plugin struct {
	// Interval is the refresh interval for re-reading the static config file
	Interval time.Duration
	// Path is the path to the static config file
	Path string
	// TTL is the TTL to set on returned records
	TTL uint32

	mu sync.RWMutex
	// cachedSize is the size of the cached file (change detection)
	cachedSize int64
	// cachedMtime is the modification time of the cached file (change detection)
	cachedMtime time.Time

	// records is the in-memory cache of static records
	records []util.Record

	// loop is used to signal the background goroutine to stop
	loop *chan struct{}
}

func NewPlugin() *Plugin {
	return &Plugin{
		Interval: 5 * time.Second,
		TTL:      10,
		Path:     "/var/lib/pce/crdb-locality",
	}
}

// comp-time check: Plugin implements util.Adapter
var _ util.Adapter = (*Plugin)(nil)

func (p *Plugin) Start() {
	if p.loop != nil {
		// Already started
		return
	}

	if p.Path == "" {
		ilog.Log.Errorf("static: no path to static config file provided")
		return
	}
	if p.TTL == 0 {
		ilog.Log.Warningf("static: TTL of 0 provided, defaulting to 10 seconds")
		p.TTL = 10
	}
	if p.Interval <= 0 {
		ilog.Log.Warningf("static: invalid refresh interval, skipping periodic reload")
		// Run once
		p.ReadStatic()
		return
	}

	ticker := time.NewTicker(p.Interval)
	loop := make(chan struct{})
	p.loop = &loop

	go func() {
		for {
			select {
			// Periodic update
			case <-ticker.C:
				p.ReadStatic()
			// Shutdown signal
			case <-loop:
				ticker.Stop()
				return
			}
		}
	}()

	// Run immediately
	p.ReadStatic()
}

func (p *Plugin) Close() error {
	if p.loop != nil {
		close(*p.loop)
		p.loop = nil
	}
	return nil
}

func (p *Plugin) LookupRecords(ctx context.Context, name string, qtype uint16) ([]util.Record, bool, error) {
	var results []util.Record
	nameExists := false
	p.mu.RLock()
	defer p.mu.RUnlock()

	nameFqdn := dns.CanonicalName(name)
	// Find matches based on FQDN and query type
	for _, record := range p.records {
		if dns.CanonicalName(record.FQDN) != nameFqdn {
			continue
		}
		nameExists = true

		if qtype == dns.TypeANY || record.Type == qtype {
			// Match type if not ANY
			results = append(results, record)
		} else if (qtype == dns.TypeA || qtype == dns.TypeAAAA) && record.Type == dns.TypeCNAME {
			// Special case: include CNAME records when querying A/AAAA
			results = append(results, record)
		}
	}

	return results, nameExists, nil
}

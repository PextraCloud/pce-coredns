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
package pce

import (
	"context"

	"github.com/PextraCloud/pce-coredns/internal/log"
	"github.com/PextraCloud/pce-coredns/internal/util"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

func (p *PcePlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qName := state.Name()
	qType := state.QType()
	qTypeStr := state.Type()

	// Check if name matches a zone we are authoritative for
	zone := plugin.Zones(p.zones()).Matches(qName)
	if zone == "" {
		log.Log.Debugf("zone not found for query name=%q, passing to next plugin", qName)
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	var records []util.Record
	var nameExists bool
	var err error

	adapter, err := p.adapterFromZone(zone)
	if err != nil {
		// This should never happen, since we only match zones we are authoritative for
		log.Log.Errorf("failed to get adapter for zone %q: %v", zone, err)
		// SERVFAIL
		return errResponse(state, dns.RcodeServerFailure, err)
	}
	if records, nameExists, err = adapter.LookupRecords(ctx, qName, qType); err != nil {
		log.Log.Errorf("lookup failed for name=%q type=%s: %v", qName, qTypeStr, err)
		// SERVFAIL
		return errResponse(state, dns.RcodeServerFailure, err)
	}

	hasRecords := len(records) > 0
	if hasRecords {
		log.Log.Debugf("found %d record(s) for name=%q type=%s", len(records), qName, qTypeStr)
		var answers []dns.RR
		if answers, err = util.RecordsToRRs(records); err != nil {
			log.Log.Errorf("failed to convert records to RRs for name=%q type=%s: %v", qName, qTypeStr, err)
			// SERVFAIL
			return errResponse(state, dns.RcodeServerFailure, err)
		}

		// SUCCESS
		return successResponse(state, answers)
	}
	if nameExists {
		log.Log.Debugf("name exists but no records for type for name=%q type=%s", qName, qTypeStr)
		// NOERROR (NODATA)
		return successResponse(state, nil)
	}

	log.Log.Debugf("no records found for name=%q type=%s", qName, qTypeStr)
	// NXDOMAIN
	return errResponse(state, dns.RcodeNameError, nil)
}

func errResponse(state request.Request, rcode int, err error) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(state.Req, rcode)
	m.Authoritative = true
	m.RecursionAvailable = false
	m.Compress = true

	state.SizeAndDo(m)
	state.W.WriteMsg(m)
	return rcode, err
}

func successResponse(state request.Request, answers []dns.RR) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	m.RecursionAvailable = false
	m.Compress = true
	m.Answer = answers

	state.SizeAndDo(m)
	m = state.Scrub(m)
	state.W.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

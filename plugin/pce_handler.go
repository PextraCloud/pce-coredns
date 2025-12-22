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

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

func (p *PcePlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qName := state.Name()

	// Load zones
	if err := p.loadZones(ctx); err != nil {
		return errResponse(state, dns.RcodeServerFailure, err)
	}

	// Get most specific matching zone (if any)
	qZone := plugin.Zones(p.zones).Matches(qName)
	if qZone == "" {
		// Fallthrough to next plugin
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	qType := state.QType()
	// Lookup records in db
	records, err := p.lookupRecords(ctx, qZone, qName, qType)
	if err != nil {
		return errResponse(state, dns.RcodeServerFailure, err)
	}

	// No records found
	if len(records) == 0 {
		// Only fallthrough if config allows it for this zone
		canFallthrough := p.canFallthrough(qZone)
		if canFallthrough {
			return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
		} else {
			return errResponse(state, dns.RcodeNameError, nil)
		}
	}

	// Convert to DNS RRs and send response
	answers, rcode, err := recordsToRRs(records)
	if err != nil {
		return errResponse(state, rcode, err)
	}

	return successResponse(state, answers)
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

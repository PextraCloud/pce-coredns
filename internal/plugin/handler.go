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

	typeName := dns.TypeToString[qType]
	if typeName == "" {
		typeName = "UNKNOWN"
	}
	log.Log.Debugf("request: name=%q type=%s from=%s", qName, typeName, state.IP())

	tryServe := func(source string, records []util.Record, err error) (int, error) {
		if err != nil {
			log.Log.Errorf("%s: lookup failed for name=%q type=%s: %v", source, qName, typeName, err)
			return errResponse(state, dns.RcodeServerFailure, err)
		}
		// If records found, return them
		if len(records) > 0 {
			log.Log.Debugf("%s: matched %d record(s) for name=%q", source, len(records), qName)
			answers, rcode, err := util.RecordsToRRs(records)
			if err != nil {
				return errResponse(state, rcode, err)
			}
			return successResponse(state, answers)
		}
		log.Log.Debugf("%s: no records for name=%q", source, qName)
		return -1, nil // indicate no records found
	}

	// Load static records
	records, err := p.static.LookupRecords(ctx, qName, qType)
	tryServeResult, err := tryServe("static", records, err)
	if tryServeResult != -1 {
		return tryServeResult, err
	}

	// Load dynamic records from DB
	records, err = p.db.LookupRecords(ctx, qName, qType)
	tryServeResult, err = tryServe("db", records, err)
	if tryServeResult != -1 {
		return tryServeResult, err
	}

	// No records found in either static or DB, handle fallthrough
	// Fallthrough: only if config allows it for this zone
	// TODO: we don't populate p.zones anywhere, need to fix that.
	qZone := plugin.Zones(p.zones).Matches(qName)
	canFallthrough := p.canFallthrough(qZone)
	if canFallthrough {
		log.Log.Debugf("fallthrough: passing to next plugin for name=%q", qName)
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	} else {
		log.Log.Debugf("nxdomain: no records for name=%q", qName)
		return errResponse(state, dns.RcodeNameError, nil)
	}
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

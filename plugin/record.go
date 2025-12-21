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
	"encoding/json"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type dbRecord struct {
	Name    string
	Zone    string
	Type    string
	TTL     uint32
	Content string
}

func (r *dbRecord) fqdn() string {
	// If Name is empty, it represents the zone apex (e.g., example.com)
	if r.Name == "" {
		return dns.Fqdn(r.Zone)
	}
	return dns.Fqdn(r.Name + "." + r.Zone)
}

func splitTxtData(content string) []string {
	// TXT records can have multiple strings, each up to 255 bytes.
	// Split the input string into chunks of 255 bytes.
	var result []string
	for len(content) > 255 {
		result = append(result, content[:255])
		content = content[255:]
	}
	result = append(result, content)
	return result
}

type ARecord struct {
	IP net.IP `json:"ip"`
}
type AAAARecord struct {
	IP net.IP `json:"ip"`
}
type SRVRecord struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

func (dbr *dbRecord) AsARecord() (dns.RR, error) {
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dbr.fqdn(),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    dbr.TTL,
		},
	}

	var rec ARecord
	if err := json.Unmarshal([]byte(dbr.Content), &rec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal A record Content: %v", err)
	}
	rr.A = rec.IP

	return rr, nil
}
func (r *dbRecord) AsAAAARecord() (dns.RR, error) {
	var rec AAAARecord
	if err := json.Unmarshal([]byte(r.Content), &rec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AAAA record Content: %v", err)
	}

	rr := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   r.fqdn(),
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		AAAA: rec.IP,
	}
	return rr, nil
}
func (r *dbRecord) AsSRVRecord() (dns.RR, error) {
	var rec SRVRecord
	if err := json.Unmarshal([]byte(r.Content), &rec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SRV record Content: %v", err)
	}

	rr := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   r.fqdn(),
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Priority: rec.Priority,
		Weight:   rec.Weight,
		Port:     rec.Port,
		Target:   dns.Fqdn(rec.Target),
	}
	return rr, nil
}
func (r *dbRecord) AsTXTRecord() (dns.RR, error) {
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.fqdn(),
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Txt: splitTxtData(r.Content),
	}
	return rr, nil
}

func recordToRR(record *dbRecord, defaultTtl uint32) (dns.RR, error) {
	// Use default TTL if unset
	if record.TTL == 0 {
		record.TTL = defaultTtl
	}

	switch record.Type {
	case "A":
		return record.AsARecord()
	case "AAAA":
		return record.AsAAAARecord()
	case "SRV":
		return record.AsSRVRecord()
	case "TXT":
		return record.AsTXTRecord()
	default:
		return nil, fmt.Errorf("unsupported record type: %s", record.Type)
	}
}

func recordsToRRs(records []dbRecord, defaultTtl uint32) ([]dns.RR, int, error) {
	answers := make([]dns.RR, 0, len(records))
	for _, record := range records {
		rr, err := recordToRR(&record, defaultTtl)
		if err != nil {
			return nil, dns.RcodeServerFailure, err
		}
		answers = append(answers, rr)
	}
	return answers, dns.RcodeSuccess, nil
}

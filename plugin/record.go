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
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type dbRecord struct {
	FQDN    string
	Type    uint16
	TTL     uint32
	Content dbRecordContent
}
type dbRecordContent struct {
	// A/AAAA fields
	IP net.IP

	// CNAME fields
	CNAME string

	// SRV fields
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string

	// TXT fields
	Data string
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

func (dbr *dbRecord) AsARecord() (dns.RR, error) {
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dbr.FQDN,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    dbr.TTL,
		},
		A: dbr.Content.IP,
	}
	return rr, nil
}
func (r *dbRecord) AsAAAARecord() (dns.RR, error) {
	rr := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   r.FQDN,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		AAAA: r.Content.IP,
	}
	return rr, nil
}
func (r *dbRecord) AsCNAMERecord() (dns.RR, error) {
	rr := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   r.FQDN,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Target: dns.Fqdn(r.Content.CNAME),
	}
	return rr, nil
}
func (r *dbRecord) AsSRVRecord() (dns.RR, error) {
	rr := &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   r.FQDN,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Priority: r.Content.Priority,
		Weight:   r.Content.Weight,
		Port:     r.Content.Port,
		Target:   dns.Fqdn(r.Content.Target),
	}
	return rr, nil
}
func (r *dbRecord) AsTXTRecord() (dns.RR, error) {
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.FQDN,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Txt: splitTxtData(r.Content.Data),
	}
	return rr, nil
}

func recordToRR(record *dbRecord) (dns.RR, error) {
	switch record.Type {
	case dns.TypeA:
		return record.AsARecord()
	case dns.TypeAAAA:
		return record.AsAAAARecord()
	case dns.TypeCNAME:
		return record.AsCNAMERecord()
	case dns.TypeSRV:
		return record.AsSRVRecord()
	case dns.TypeTXT:
		return record.AsTXTRecord()
	default:
		return nil, fmt.Errorf("unsupported record type: %d", record.Type)
	}
}

func recordsToRRs(records []dbRecord) ([]dns.RR, int, error) {
	answers := make([]dns.RR, 0, len(records))
	for _, record := range records {
		rr, err := recordToRR(&record)
		if err != nil {
			return nil, dns.RcodeServerFailure, err
		}
		answers = append(answers, rr)
	}
	return answers, dns.RcodeSuccess, nil
}

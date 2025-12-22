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
	"database/sql"
	"fmt"

	"github.com/coredns/coredns/plugin"
)

const PluginName = "pce"

type PcePlugin struct {
	// Next is the next plugin in the chain
	Next plugin.Handler

	// DataSource is the database connection string
	DataSource string

	// fallthroughZones is the list of zones for which queries should be
	// passed to the next plugin if no records are found
	fallthroughZones []string
	// zones is the list of zones this plugin will handle
	zones []string

	// db is the database connection pool
	db *sql.DB
}

// comp-time check: PcePlugin implements plugin.Handler
var _ plugin.Handler = (*PcePlugin)(nil)

func (p *PcePlugin) Name() string { return PluginName }

func (p *PcePlugin) ValidateConfig() error {
	if p.DataSource == "" {
		return fmt.Errorf("datasource must be specified for %s plugin", PluginName)
	}
	return nil
}

func (p *PcePlugin) setFallthroughZones(zones []string) {
	// If no zones are specified, default to the root zone
	if len(zones) == 0 {
		zones = []string{"."}
	}

	res := []string{}
	for _, zone := range zones {
		res = append(res, plugin.Host(zone).NormalizeExact()...)
	}
	p.fallthroughZones = res
}

func (p *PcePlugin) setZones(zones []string) {
	res := []string{}
	for _, zone := range zones {
		res = append(res, plugin.Host(zone).NormalizeExact()...)
	}
	p.zones = res
}

func (p *PcePlugin) canFallthrough(qName string) bool {
	return plugin.Zones(p.fallthroughZones).Matches(qName) != ""
}

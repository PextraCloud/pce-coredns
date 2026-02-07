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
	"errors"

	"github.com/PextraCloud/pce-coredns/internal/db"
	"github.com/PextraCloud/pce-coredns/internal/log"
	"github.com/PextraCloud/pce-coredns/internal/static"
	"github.com/PextraCloud/pce-coredns/internal/util"
	"github.com/coredns/coredns/plugin"
)

type PcePlugin struct {
	// Next is the next plugin in the chain
	Next plugin.Handler

	// sql plugin serves from a PCE database
	db *db.Plugin
	// static plugin serves from a static PCE config
	static *static.Plugin
}

// comp-time check: PcePlugin implements plugin.Handler
var _ plugin.Handler = (*PcePlugin)(nil)

func (p *PcePlugin) Name() string { return log.PluginName }

// zones returns the zones that this plugin is authoritative for
func (p *PcePlugin) zones() []string {
	return util.ZonesList
}

func (p *PcePlugin) adapterFromZone(zone string) (util.Adapter, error) {
	switch zone {
	case util.ZoneDynamic:
		return p.db, nil
	case util.ZoneBootstrap:
		return p.static, nil
	default:
		return nil, errors.New("unknown zone: " + zone)
	}
}

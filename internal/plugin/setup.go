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
	"github.com/PextraCloud/pce-coredns/internal/db"
	"github.com/PextraCloud/pce-coredns/internal/log"
	"github.com/PextraCloud/pce-coredns/internal/static"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func parseConfig(c *caddy.Controller) (*PcePlugin, error) {
	c.Next() // skip the PluginName token
	log.Log.Debugf("config: parsing %s plugin", log.PluginName)

	s := static.NewPlugin()
	d := db.NewPlugin()

	pcePlugin := &PcePlugin{
		db:     d,
		static: s,
	}
	if c.NextBlock() {
		for {
			switch c.Val() {
			case "datasource":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				pcePlugin.db.DataSource = c.Val()
			case "fallthrough":
				pcePlugin.setFallthroughZones(c.RemainingArgs())
			default:
				// Handle unexpected tokens
				if c.Val() != "}" {
					return nil, c.Errf("unknown property '%s' for %s plugin", c.Val(), log.PluginName)
				}
			}

			if !c.Next() {
				break
			}
		}
	}

	// Attempt to connect to db
	pcePlugin.db.Connect()
	// Start static plugin
	pcePlugin.static.Start()
	log.Log.Debugf("config: %s plugin initialized", log.PluginName)

	// Cleanup on shutdown
	c.OnShutdown(func() error {
		log.Log.Debugf("shutdown: %s plugin stopping", log.PluginName)
		if pcePlugin.db != nil {
			return pcePlugin.db.Close()
		}
		if pcePlugin.static != nil {
			return pcePlugin.static.Close()
		}
		return nil
	})
	return pcePlugin, nil
}

func Setup(c *caddy.Controller) error {
	pce, err := parseConfig(c)
	if err != nil {
		return err
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		// For plugin chaining
		pce.Next = next
		return pce
	})
	return nil
}

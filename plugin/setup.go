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
	"strconv"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	caddy.RegisterPlugin(PluginName, caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func parseConfig(c *caddy.Controller) (*PcePlugin, error) {
	c.Next() // skip the PluginName token

	pcePlugin := &PcePlugin{}
	if c.NextBlock() {
		for {
			switch c.Val() {
			case "datasource":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				pcePlugin.DataSource = c.Val()
			case "table":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				pcePlugin.TableName = c.Val()
			case "ttl":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				ttl, err := strconv.Atoi(c.Val())
				if err != nil {
					return nil, c.Errf("invalid ttl value: %v", err)
				}
				pcePlugin.DefaultTTL = uint32(ttl)
			case "fallthrough":
				pcePlugin.setFallthroughZones(c.RemainingArgs())
			default:
				// Handle unexpected tokens
				if c.Val() != "}" {
					return nil, c.Errf("unknown property '%s' for %s plugin", c.Val(), PluginName)
				}
			}

			if !c.Next() {
				break
			}
		}
	}

	// Validate configuration
	if err := pcePlugin.ValidateConfig(); err != nil {
		return nil, err
	}
	// Attempt to connect to db
	if err := pcePlugin.Connect(); err != nil {
		return nil, err
	}

	return pcePlugin, nil
}

func setup(c *caddy.Controller) error {
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

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
package util

import "context"

const zoneBase = "pce.internal."

const ZoneDynamic = zoneBase
const ZoneBootstrap = "bootstrap." + zoneBase

var ZonesList = []string{
	ZoneDynamic,
	ZoneBootstrap,
}

type Adapter interface {
	LookupRecords(ctx context.Context, qName string, qType uint16) ([]Record, bool, error)
}

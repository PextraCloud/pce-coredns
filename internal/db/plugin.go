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
package db

import (
	"database/sql"
	"time"

	ilog "github.com/PextraCloud/pce-coredns/internal/log"
	_ "github.com/lib/pq"
)

type Plugin struct {
	// DataSource is the database connection string
	DataSource string
	// db is the database connection pool
	db *sql.DB
}

func NewPlugin() *Plugin {
	return &Plugin{}
}

// Connect establishes a connection to the database
var sqlOpen = sql.Open

func (p *Plugin) Connect() {
	if p.DataSource == "" {
		ilog.Log.Warningf("db: no datasource provided, skipping database connection")
		return
	}

	ilog.Log.Debugf("db: opening connection")
	db, err := sqlOpen("postgres", p.DataSource)
	if err != nil {
		ilog.Log.Errorf("db: failed to open connection: %v", err)
		return
	}

	// Test db connection, don't close on failure, it will be retried later
	if err := db.Ping(); err != nil {
		ilog.Log.Warningf("db: failed to ping database: %v", err)
		return
	}

	// TODO: make configurable
	db.SetConnMaxLifetime(time.Minute)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	p.db = db
	ilog.Log.Infof("db: connection established")
}

func (p *Plugin) Close() error {
	if p.db == nil {
		return nil
	}

	ilog.Log.Infof("db: closing postgres connection")
	if err := p.db.Close(); err != nil {
		ilog.Log.Errorf("db: failed to close connection: %v", err)
		return err
	}

	ilog.Log.Infof("db: postgres connection closed")
	return nil
}

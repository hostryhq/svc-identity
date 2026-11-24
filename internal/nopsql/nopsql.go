// Package nopsql is a database/sql driver that accepts every statement and stores nothing. The
// in-memory repository uses it so go-auth's vendor access hook (auth.WithAuditedTx), which needs a
// *sql.Tx, runs the same code path in the test double as against Postgres.
package nopsql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
)

// DB returns a *sql.DB backed by the no-op driver.
func DB() *sql.DB { return sql.OpenDB(connector{}) }

type connector struct{}

func (connector) Connect(context.Context) (driver.Conn, error) { return conn{}, nil }
func (connector) Driver() driver.Driver                        { return drv{} }

type drv struct{}

func (drv) Open(string) (driver.Conn, error) { return conn{}, nil }

type conn struct{}

func (conn) Prepare(string) (driver.Stmt, error) { return stmt{}, nil }
func (conn) Close() error                        { return nil }
func (conn) Begin() (driver.Tx, error)           { return tx{}, nil }

type tx struct{}

func (tx) Commit() error   { return nil }
func (tx) Rollback() error { return nil }

type stmt struct{}

func (stmt) Close() error                               { return nil }
func (stmt) NumInput() int                              { return -1 }
func (stmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(0), nil }
func (stmt) Query([]driver.Value) (driver.Rows, error)  { return rows{}, nil }

type rows struct{}

func (rows) Columns() []string         { return nil }
func (rows) Close() error              { return nil }
func (rows) Next([]driver.Value) error { return io.EOF }

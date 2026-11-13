// Package store is the only package that talks SQL to the control-plane
// database (design §8.1). Everything else goes through the types here.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/migrate"
	_ "modernc.org/sqlite" // pure Go, so the control plane cross-compiles with CGO_ENABLED=0
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// migrations is the registry bun/migrate applies at Open. The files are named
// NNN_description.tx.up.sql: the .tx. infix makes bun run each file inside one
// transaction, so a migration that fails halfway leaves no partial schema.
var migrations = migrate.NewMigrations()

func init() {

	if err := migrations.Discover(migrationFS); err != nil {

		panic("store: cannot read embedded migrations: " + err.Error())
	}
}

// rfc3339Dialect is sqlitedialect with timestamps written as RFC3339.
//
// Design §8.1 declares every TIMESTAMP column and this database stores them as
// TEXT. Everything that reads the file outside these models assumes RFC3339:
// internal/auditlog parses occurred_at itself, and the acceptance suite
// queries state.db with the sqlite3 CLI. Bun's base dialect would write
// "2006-01-02 15:04:05.999999-07:00" instead, so the format is pinned once here
// rather than at every call site that could forget it.
type rfc3339Dialect struct {
	*sqlitedialect.Dialect
}

func (rfc3339Dialect) AppendTime(b []byte, tm time.Time) []byte {

	b = append(b, '\'')
	b = tm.UTC().AppendFormat(b, time.RFC3339)
	return append(b, '\'')
}

// DB wraps the control-plane SQLite database.
//
// Writes go through a pool capped at one connection. That is not only about
// SQLite's single-writer model: internal/auditlog reads the chain head and
// appends the next row inside one transaction, and a second concurrent writer
// would let two rows claim the same prev_hash.
type DB struct {
	w *bun.DB
	r *bun.DB
}

// Open opens (creating if needed) the control-plane database at path and
// applies every pending migration.
func Open(ctx context.Context, path string) (*DB, error) {

	w, err := open(path, 1)
	if err != nil {

		return nil, err
	}
	r, err := open(path, 4)
	if err != nil {

		_ = w.Close()
		return nil, err
	}
	db := &DB{w: w, r: r}
	if err := db.migrate(ctx); err != nil {

		_ = db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	// The file holds the audit chain and every tenant's configuration. The
	// enclosing control/ directory is already 0700; this is the second lock on
	// the same door, and it costs nothing.
	for _, suffix := range []string{"", "-wal", "-shm"} {

		if err := os.Chmod(path+suffix, 0o600); err != nil && !os.IsNotExist(err) {

			_ = db.Close()
			return nil, err
		}
	}
	return db, nil
}

func open(path string, maxConns int) (*bun.DB, error) {

	dsn := "file:" + path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(ON)" +
		// Without it, INSERT OR REPLACE deletes a conflicting row WITHOUT
		// firing its DELETE triggers, which is a way round the append-only
		// triggers on audit_event and audit_anchor (INV-18).
		"&_pragma=recursive_triggers(ON)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)"
	h, err := sql.Open("sqlite", dsn)
	if err != nil {

		return nil, err
	}
	h.SetMaxOpenConns(maxConns)
	if err := h.Ping(); err != nil {

		_ = h.Close()
		return nil, err
	}
	return bun.NewDB(h, rfc3339Dialect{sqlitedialect.New()}), nil
}

// Reader returns the read pool. Callers must not write through it.
func (db *DB) Reader() *bun.DB { return db.r }

// Close releases both pools.
func (db *DB) Close() error {

	err := db.w.Close()
	if rerr := db.r.Close(); err == nil {

		err = rerr
	}
	return err
}

// Tx runs fn inside a single write transaction and commits if it returns nil.
//
// This is the unit every mutation in the control plane uses, because the audit
// event for a state change must be written in the same transaction as the
// change itself (design §14.4). A crash between the two would otherwise
// yield a state change nobody authorised and nobody can attribute.
func (db *DB) Tx(ctx context.Context, fn func(bun.Tx) error) error {

	return db.w.RunInTx(ctx, nil, func(_ context.Context, tx bun.Tx) error {

		return fn(tx)
	})
}

// migrate applies pending migrations through the single-connection write pool.
//
// WithMarkAppliedOnSuccess means a migration that fails is not recorded, so the
// next start retries it instead of skipping a schema that was never created.
func (db *DB) migrate(ctx context.Context) error {

	m := migrate.NewMigrator(db.w, migrations, migrate.WithMarkAppliedOnSuccess(true))
	if err := m.Init(ctx); err != nil {

		return err
	}
	_, err := m.Migrate(ctx)
	return err
}

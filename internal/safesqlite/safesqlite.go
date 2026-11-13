// Package safesqlite reads a SQLite database the host does not trust, from a
// file handle the caller has already opened and checked.
//
// Opening a database by path hands path resolution to SQLite, and SQLite
// resolves symlinks in the name before it opens anything. For a file under a
// tenant's pb_data that is the race INV-1 warns about: whatever the host
// checked about the path, the tenant can re-point it before SQLite opens it.
// Here SQLite never sees a path. It reads through a read-only VFS that serves
// exactly one file — the handle the caller opened with hostfs.OpenRegularUnder
// — and refuses every other name, so there is no journal, no -wal, no -shm and
// nothing to create, truncate or unlink.
package safesqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
	"modernc.org/sqlite/vfs"
)

// mainName is the only name the VFS answers to.
const mainName = "main.db"

// DefaultParams are the connection parameters for an untrusted database:
// read-only, no locking (INV-20), and a schema that is not trusted to run
// functions with side effects.
const DefaultParams = "mode=ro&immutable=1&_pragma=query_only(1)&_pragma=trusted_schema(0)&_pragma=cell_size_check(1)"

// DB is an open untrusted database. Close releases the connection and the
// VFS; the caller still owns, and must close, the file it passed in.
type DB struct {
	*sql.DB
	fsys *vfs.FS
}

// Open returns a single-connection handle reading f.
//
// params are DSN query parameters appended after the VFS selection; empty
// means DefaultParams.
func Open(f *os.File, params string) (*DB, error) {

	if f == nil {

		return nil, errors.New("safesqlite: nil file")
	}
	if params == "" {

		params = DefaultParams
	}
	name, fsys, err := vfs.New(oneFile{f: f})
	if err != nil {

		return nil, fmt.Errorf("safesqlite: register vfs: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+mainName+"?vfs="+name+"&"+strings.TrimPrefix(params, "&"))
	if err != nil {

		_ = fsys.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &DB{DB: db, fsys: fsys}, nil
}

// Close closes the connection, then unregisters the VFS.
func (d *DB) Close() error {

	err := d.DB.Close()
	if cerr := d.fsys.Close(); err == nil {

		err = cerr
	}
	return err
}

// oneFile is an fs.FS holding exactly one file, read through ReadAt so every
// handle SQLite opens keeps its own offset over the shared descriptor.
type oneFile struct {
	f *os.File
}

func (o oneFile) Open(name string) (fs.File, error) {

	if name != mainName {

		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &view{f: o.f}, nil
}

type view struct {
	f   *os.File
	off int64
}

func (v *view) Stat() (fs.FileInfo, error) {

	fi, err := v.f.Stat()
	if err != nil {

		return nil, err
	}
	return info{fi}, nil
}

func (v *view) Read(p []byte) (int, error) {

	n, err := v.f.ReadAt(p, v.off)
	v.off += int64(n)
	return n, err
}

func (v *view) Seek(offset int64, whence int) (int64, error) {

	var base int64
	switch whence {

	case io.SeekStart:
	case io.SeekCurrent:
		base = v.off
	case io.SeekEnd:
		fi, err := v.f.Stat()
		if err != nil {

			return 0, err
		}
		base = fi.Size()
	default:
		return 0, errors.New("safesqlite: bad whence")
	}
	if base+offset < 0 {

		return 0, errors.New("safesqlite: negative offset")
	}
	v.off = base + offset
	return v.off, nil
}

// Close is a no-op: the descriptor belongs to the caller.
func (v *view) Close() error { return nil }

// info renames the file to mainName so fs.Stat agrees with Open.
type info struct{ fs.FileInfo }

func (info) Name() string { return mainName }

// Package access holds the two values a deployment enforces but does not
// really own: the tier access table and the Patreon grant list. Together they
// are half of the magic config, and neither is about the deployment carrying
// it. Each is read from its own path, which may be shared between deployments
// or not, and this package does not care which: a path names a file, and what
// any two deployments choose to point at is a decision about the data.
//
// The package touches no backend or config of its own — the caller hands it
// hooks for opening paths and for the inline-config fallback, both of which
// stay coupled to the deployment that owns them.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// Grant is one entry of the Patreon grant list. The json tags match the
// inline config field it migrates out of.
type Grant struct {
	Category string `json:"category"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Tier     string `json:"tier"`
}

// Table is the tier -> feature -> option access table.
type Table map[string]map[string]map[string]string

// Hooks are the deployment-owned halves: how a path reaches its backend
// (credentials live with the caller) and how each value persists into the
// inline config while one still carries it. The inline hooks go away with
// the migration, once no config holds an inline table or grant list.
type Hooks struct {
	Open             func(ctx context.Context, path string) (io.ReadCloser, error)
	OpenWrite        func(ctx context.Context, path string) (io.WriteCloser, error)
	SaveTableInline  func(ctx context.Context, table Table) error
	SaveGrantsInline func(ctx context.Context, grants []Grant) error
}

// Sources says where a Load reads from: a path where one is configured, the
// fallback values the deployment config carries inline where none is. The
// fallback is what makes the move a migration rather than a flag day: this
// ships before any config is split, and each deployment moves when its own
// path is set.
type Sources struct {
	TablePath      string
	GrantsPath     string
	FallbackTable  Table
	FallbackGrants []Grant
}

// Client holds the loaded table and grants. Both are read on request paths
// and replaced whole by a reload or an admin save, so each travels as an
// immutable value behind a pointer: a reader either sees the old one or the
// new one, never one mid-change.
type Client struct {
	hooks Hooks

	// Serialises the writers (Load, SaveGrants); readers go through the
	// atomics and never block.
	mu      sync.Mutex
	sources Sources

	table  atomic.Pointer[Table]
	grants atomic.Pointer[[]Grant]
}

// New returns a Client that reads and writes through the given hooks; call
// Load before the first read.
func New(hooks Hooks) *Client {
	return &Client{hooks: hooks}
}

// Table returns the current access table. The result is shared and must not
// be modified.
func (c *Client) Table() Table {
	table := c.table.Load()
	if table == nil {
		return nil
	}
	return *table
}

// Grants returns the current grant list. The result is shared and must not
// be modified; build a new slice and hand it to SaveGrants instead.
func (c *Client) Grants() []Grant {
	grants := c.grants.Load()
	if grants == nil {
		return nil
	}
	return *grants
}

func (c *Client) setTable(table Table) {
	c.table.Store(&table)
}

func (c *Client) setGrants(grants []Grant) {
	c.grants.Store(&grants)
}

// Load fills the table and the grant list from the given sources and
// remembers them, so a later save or reload goes back to wherever each
// value came from.
func (c *Client) Load(ctx context.Context, sources Sources) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	table, err := c.loadTable(ctx, sources)
	if err != nil {
		return err
	}
	grants, err := c.loadGrants(ctx, sources)
	if err != nil {
		return err
	}

	c.sources = sources
	c.setTable(table)
	c.setGrants(grants)
	return nil
}

// ReloadTable re-reads just the access table, from the sources of the last
// Load, and publishes it on success. The grant list is not touched: the two
// values change independently, so a change to one must not re-fetch the
// other.
func (c *Client) ReloadTable(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	table, err := c.loadTable(ctx, c.sources)
	if err != nil {
		return err
	}
	c.setTable(table)
	return nil
}

// ReloadGrants re-reads just the grant list, from the sources of the last
// Load, and publishes it on success, mirroring ReloadTable.
func (c *Client) ReloadGrants(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	grants, err := c.loadGrants(ctx, c.sources)
	if err != nil {
		return err
	}
	c.setGrants(grants)
	return nil
}

func (c *Client) loadTable(ctx context.Context, sources Sources) (Table, error) {
	if sources.TablePath == "" {
		return sources.FallbackTable, nil
	}
	var table Table
	err := c.readJSONPath(ctx, sources.TablePath, &table)
	if err != nil {
		return nil, fmt.Errorf("acl %s: %w", sources.TablePath, err)
	}
	return table, nil
}

func (c *Client) loadGrants(ctx context.Context, sources Sources) ([]Grant, error) {
	if sources.GrantsPath == "" {
		return sources.FallbackGrants, nil
	}
	var grants []Grant
	err := c.readJSONPath(ctx, sources.GrantsPath, &grants)
	if err != nil {
		return nil, fmt.Errorf("grants %s: %w", sources.GrantsPath, err)
	}
	return grants, nil
}

// SaveGrants persists a new grant list to wherever the list was read from,
// and publishes it on success. With no path configured that is still the
// inline config, which is where the admin page has always written it.
func (c *Client) SaveGrants(ctx context.Context, grants []Grant) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sources.GrantsPath == "" {
		if err := c.hooks.SaveGrantsInline(ctx, grants); err != nil {
			return err
		}
		c.setGrants(grants)
		return nil
	}

	if err := c.writeJSONPath(ctx, c.sources.GrantsPath, grants); err != nil {
		return err
	}
	c.setGrants(grants)
	return nil
}

// SaveTable persists a new access table to wherever the table was read from,
// and publishes it on success, mirroring SaveGrants.
func (c *Client) SaveTable(ctx context.Context, table Table) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sources.TablePath == "" {
		if err := c.hooks.SaveTableInline(ctx, table); err != nil {
			return err
		}
		c.setTable(table)
		return nil
	}

	if err := c.writeJSONPath(ctx, c.sources.TablePath, table); err != nil {
		return err
	}
	c.setTable(table)
	return nil
}

// writeJSONPath encodes v as json at a path through the caller's OpenWrite
// hook.
func (c *Client) writeJSONPath(ctx context.Context, path string, v any) error {
	writer, err := c.hooks.OpenWrite(ctx, path)
	if err != nil {
		return err
	}
	err = json.NewEncoder(writer).Encode(v)
	// Close finalises the upload, so its error is the write's error too, and
	// a failure there must not be reported as a save.
	cerr := writer.Close()
	if err != nil {
		return err
	}
	return cerr
}

// readJSONPath decodes the json at a path into v, letting the caller's Open
// hook pick the backend.
func (c *Client) readJSONPath(ctx context.Context, path string, v any) error {
	reader, err := c.hooks.Open(ctx, path)
	if err != nil {
		return err
	}
	defer reader.Close()

	return json.NewDecoder(reader).Decode(v)
}

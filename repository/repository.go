// Package repository is the persistence interface of the identity service. The service layer
// depends only on these interfaces (go-service-standard: api -> service -> repository).
//
// Storage model: identity is a document-oriented service. Each entity is a JSON document of a
// named Kind, addressed by (scope, id) with up to two index keys for lookups. Tenant-owned kinds
// use the tenant id as scope and are isolated by row-level security (ADR-0003 section 6); kinds
// that must be found before a tenant is known (accounts, challenges, refresh tokens, device
// index, vendor realm) are service-global (ADR-0003 A1.6) and live in a separate table.
package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/hostryhq/go-common/events"
)

// Global is the scope of service-global kinds.
const Global = ""

// ErrConflict is returned by Put when a unique key is already taken by another record.
var ErrConflict = errors.New("repository: unique key conflict")

// Record is one stored document.
type Record struct {
	Kind  string
	Scope string // tenant id, or Global
	ID    string
	// K1 and K2 are optional lookup keys (exact match). Unique, when set, makes (Kind, Scope, K1)
	// unique across records.
	K1, K2 string
	Unique bool
	Doc    []byte
}

// Tx is one transaction. Reads take a row lock in a real database, so read-modify-write is safe.
type Tx interface {
	Get(kind, scope, id string) (Record, bool, error)
	Put(r Record) error
	Delete(kind, scope, id string) error
	// FindK1 returns records of the kind and scope whose K1 equals k, ordered by id.
	FindK1(kind, scope, k string) ([]Record, error)
	FindK2(kind, scope, k string) ([]Record, error)
	// List returns records ordered by id ascending, starting after the id `after`, at most limit
	// (limit <= 0 means no limit).
	List(kind, scope, after string, limit int) ([]Record, error)
	// Emit writes an event to the transactional outbox in this transaction (ADR-0011 B4).
	Emit(e events.Envelope) error
	// AppendAudit adds an entry to the append-only, hash-chained audit log of scope (a tenant id,
	// or Platform for the vendor log). Entries are never updated or deleted (IC-28).
	AppendAudit(scope, id string, doc []byte) error
	// ListAudit returns entries newest first, starting before the id `before` ("" for the newest).
	ListAudit(scope, before string, limit int) ([]Record, error)
	// VerifyAuditChain recomputes the chain of scope and reports the first broken entry id.
	VerifyAuditChain(scope string) (brokenID string, err error)
}

// Platform is the pseudo-tenant of the vendor realm: the scope of the vendor audit chain and the
// tenancy context of vendor operations that name no organisation.
const Platform = "00000000-0000-7000-8000-000000000000"

// ChainHash is the audit hash: sha256(prev || scope || id || doc), hex.
func ChainHash(prev, scope, id string, doc []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write(doc)
	return hex.EncodeToString(h.Sum(nil))
}

// Store opens transactions. scope is the tenant id for tenant work (it sets the database tenant
// context) or Global.
type Store interface {
	Tx(ctx context.Context, scope string, fn func(Tx) error) error
	Ping(ctx context.Context) error
}

var globalKinds = map[string]bool{}

// IsGlobal reports whether a kind is service-global.
func IsGlobal(kind string) bool { return globalKinds[kind] }

// RegisterGlobal declares kinds as service-global. Called from the service package at init.
func RegisterGlobal(kinds ...string) {
	for _, k := range kinds {
		globalKinds[k] = true
	}
}

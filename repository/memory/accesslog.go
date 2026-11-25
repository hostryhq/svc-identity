package memory

import (
	"context"
	"sync"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/tenancy"
)

// AccessLog is the in-memory vendor_access_log (ADR-0013 V5): it implements go-auth's
// auth.VendorAuditSink with failure injection for the fail-closed tests (IST-42).
type AccessLog struct {
	mu          sync.Mutex
	entries     []auth.VendorAccessEntry
	platform    []auth.VendorAccessEntry
	FailInTx    bool
	FailRefused bool
}

// RecordInTx implements auth.VendorAuditSink.
func (l *AccessLog) RecordInTx(_ context.Context, _ tenancy.Execer, e auth.VendorAccessEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.FailInTx {
		return errInjected
	}
	l.entries = append(l.entries, e)
	return nil
}

// RecordRefused implements auth.VendorAuditSink.
func (l *AccessLog) RecordRefused(_ context.Context, e auth.VendorAccessEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.FailRefused {
		return errInjected
	}
	l.entries = append(l.entries, e)
	return nil
}

// RecordPlatformInTx implements auth.PlatformAuditSink: the row has no tenant.
func (l *AccessLog) RecordPlatformInTx(_ context.Context, _ tenancy.Execer, e auth.VendorAccessEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.FailInTx {
		return errInjected
	}
	e.TenantID = ""
	l.platform = append(l.platform, e)
	return nil
}

// RecordPlatformRefused implements auth.PlatformAuditSink.
func (l *AccessLog) RecordPlatformRefused(_ context.Context, e auth.VendorAccessEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.FailRefused {
		return errInjected
	}
	e.TenantID = ""
	l.platform = append(l.platform, e)
	return nil
}

// PlatformEntries returns a copy of the platform rows (organisation-less routes) written so far.
func (l *AccessLog) PlatformEntries() []auth.VendorAccessEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]auth.VendorAccessEntry(nil), l.platform...)
}

// Entries returns a copy of the rows written so far.
func (l *AccessLog) Entries() []auth.VendorAccessEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]auth.VendorAccessEntry(nil), l.entries...)
}

type injected struct{}

func (injected) Error() string { return "memory: injected failure" }

var errInjected error = injected{}

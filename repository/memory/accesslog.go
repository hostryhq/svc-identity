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

// Entries returns a copy of the rows written so far.
func (l *AccessLog) Entries() []auth.VendorAccessEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]auth.VendorAccessEntry(nil), l.entries...)
}

type injected struct{}

func (injected) Error() string { return "memory: injected failure" }

var errInjected error = injected{}

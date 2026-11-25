package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hostryhq/svc-identity/repository"
	"github.com/hostryhq/svc-identity/repository/memory"
)

func init() { repository.RegisterGlobal("g") }

func TestTenantTransactionCannotSeeOrWriteAnotherTenant(t *testing.T) {
	s := memory.New()
	a, b := "tenant-a", "tenant-b"
	if err := s.Tx(context.Background(), a, func(tx repository.Tx) error {
		return tx.Put(repository.Record{Kind: "m", Scope: a, ID: "1", Doc: []byte(`{}`)})
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Tx(context.Background(), b, func(tx repository.Tx) error {
		if _, ok, _ := tx.Get("m", a, "1"); ok {
			t.Error("tenant B read tenant A's row")
		}
		if rs, _ := tx.List("m", a, "", 0); len(rs) != 0 {
			t.Error("tenant B listed tenant A's rows")
		}
		if err := tx.Put(repository.Record{Kind: "m", Scope: a, ID: "2", Doc: []byte(`{}`)}); !errors.Is(err, memory.ErrTenantMismatch) {
			t.Errorf("tenant B wrote tenant A's row: %v", err)
		}
		return nil
	})
}

func TestFailedTransactionPublishesAndStoresNothing(t *testing.T) {
	s := memory.New()
	boom := errors.New("boom")
	err := s.Tx(context.Background(), "t", func(tx repository.Tx) error {
		_ = tx.Put(repository.Record{Kind: "m", Scope: "t", ID: "1", Doc: []byte(`{}`)})
		_ = tx.AppendAudit("t", "a1", []byte(`{}`))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	_ = s.Tx(context.Background(), "t", func(tx repository.Tx) error {
		if _, ok, _ := tx.Get("m", "t", "1"); ok {
			t.Error("row survived a rolled-back transaction")
		}
		if rs, _ := tx.ListAudit("t", "", 10); len(rs) != 0 {
			t.Error("audit entry survived a rolled-back transaction")
		}
		return nil
	})
}

func TestUniqueKeyConflict(t *testing.T) {
	s := memory.New()
	err := s.Tx(context.Background(), repository.Global, func(tx repository.Tx) error {
		if err := tx.Put(repository.Record{Kind: "g", ID: "1", K1: "x", Unique: true, Doc: []byte(`{}`)}); err != nil {
			return err
		}
		return tx.Put(repository.Record{Kind: "g", ID: "2", K1: "x", Unique: true, Doc: []byte(`{}`)})
	})
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
}

// IST-40 (memory side): the audit hash chain verifies, and an altered entry is detected.
func TestAuditChainDetectsTampering(t *testing.T) {
	s := memory.New()
	_ = s.Tx(context.Background(), "t", func(tx repository.Tx) error {
		for _, id := range []string{"a1", "a2", "a3"} {
			if err := tx.AppendAudit("t", id, []byte(`{"n":"`+id+`"}`)); err != nil {
				return err
			}
		}
		if broken, _ := tx.VerifyAuditChain("t"); broken != "" {
			t.Errorf("fresh chain reports %q broken", broken)
		}
		return nil
	})
	s.TamperAudit("t", "a2", []byte(`{"n":"altered"}`))
	_ = s.Tx(context.Background(), "t", func(tx repository.Tx) error {
		if broken, _ := tx.VerifyAuditChain("t"); broken != "a2" {
			t.Errorf("tampered entry not detected: %q", broken)
		}
		return nil
	})
}

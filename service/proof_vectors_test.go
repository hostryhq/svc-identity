package service_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/hostryhq/svc-identity/service"
)

// The proof messages are a cross-service contract (ADR-0005 sections 7 and 8, A3.1): the offline shell
// builds them, identity recomputes them. testdata/conformance-approval-proof.v1.json is the
// `approval_proof` block of api-specs sync/conformance/v1.json (feat/phase2-specs 14c76fd); identity must
// build every message and proof.
func TestProofMessagesMatchConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/conformance-approval-proof.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ProofKey string `json:"proof_key"`
		Cases    []struct {
			Case        string    `json:"case"`
			Kind        string    `json:"kind"`
			DeviceID    string    `json:"device_id"`
			MemberID    string    `json:"member_id"`
			PackV       int       `json:"pack_v"`
			PinV        int       `json:"pin_v"`
			SessionID   string    `json:"session_id"`
			OpenedAt    time.Time `json:"opened_at"`
			ActionHash  string    `json:"action_hash"`
			ApprovalID  string    `json:"approval_id"`
			Permission  string    `json:"permission"`
			Target      string    `json:"target"`
			RequesterID string    `json:"requester_id"`
			ApprovedAt  time.Time `json:"approved_at"`
			Reason      string    `json:"reason"`
			Message     string    `json:"message"`
			Proof       string    `json:"proof"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	key, err := base64.RawURLEncoding.DecodeString(v.ProofKey)
	if err != nil || len(v.Cases) < 6 {
		t.Fatalf("vector file: key err %v, %d cases", err, len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Case, func(t *testing.T) {
			var msg string
			switch c.Kind {
			case "session":
				msg = service.SessionProofMessage(c.SessionID, c.DeviceID, c.MemberID, c.PackV, c.PinV, c.OpenedAt)
			case "approval":
				msg = service.ApprovalProofMessageBound(c.ActionHash, c.DeviceID, c.MemberID, c.PackV, c.PinV, service.ApprovalBound{
					ApprovalID: c.ApprovalID, Permission: c.Permission, Target: c.Target, Requester: c.RequesterID, Reason: c.Reason, ApprovedAt: c.ApprovedAt})
			default:
				t.Fatalf("unknown kind %q", c.Kind)
			}
			if msg != c.Message {
				t.Fatalf("message\n got %q\nwant %q", msg, c.Message)
			}
			if got := service.Proof(key, msg); got != c.Proof {
				t.Fatalf("proof got %s want %s", got, c.Proof)
			}
		})
	}
}

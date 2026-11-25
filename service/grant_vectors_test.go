package service_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/hostryhq/svc-identity/service"
)

// The subject-hash rules are a cross-service contract (ADR-0014 A2.6 item 2): identity computes the hash
// when it issues a grant and the executing service recomputes it. testdata/vendor-grant.vectors.v1.json is
// a copy of api-specs common/vendor-grant.vectors.v1.json (feat/phase2-specs 1462fb8); identity must
// reproduce every vector.
func TestGrantSubjectHashMatchesSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vendor-grant.vectors.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		SubjectHash []struct {
			Kind        string            `json:"kind"`
			Fields      map[string]string `json:"fields"`
			SubjectHash string            `json:"subject_hash"`
		} `json:"subject_hash"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.SubjectHash) != 4 {
		t.Fatalf("want one vector per grant kind, got %d", len(v.SubjectHash))
	}
	for _, c := range v.SubjectHash {
		got := service.GrantSubjectHash(c.Kind, c.Fields["organisation_id"], c.Fields["rule_set_id"], c.Fields["content_hash"], c.Fields["effective_date"])
		if got != c.SubjectHash {
			t.Errorf("%s: subject hash %s, vector %s", c.Kind, got, c.SubjectHash)
		}
	}
}

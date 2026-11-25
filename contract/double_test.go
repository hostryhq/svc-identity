package contract_test

import (
	"testing"

	"github.com/hostryhq/svc-identity/contract"
	"github.com/hostryhq/svc-identity/double"
	"github.com/hostryhq/svc-identity/service"
)

// TestContractAgainstDouble runs the shared contract suite against the in-memory double.
func TestContractAgainstDouble(t *testing.T) {
	contract.Run(t, func(t *testing.T, cfg func(*service.Config)) *contract.World {
		return &contract.World{D: double.New(double.Options{ExampleLiterals: true, WithTenancy: true, Config: cfg})}
	})
}

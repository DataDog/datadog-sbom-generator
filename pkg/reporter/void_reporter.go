package reporter

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/urfave/cli/v2"
)

// Effective returns r if non-nil, otherwise a VoidReporter that silently discards all output.
// Use this when constructing structs that hold a Reporter to guarantee the field is never nil.
func Effective(r Reporter) Reporter {
	if r == nil {
		return &VoidReporter{}
	}

	return r
}

type VoidReporter struct {
	hasErrored bool
}

func (r *VoidReporter) Errorf(msg string, a ...any) {
	r.hasErrored = true
}

func (r *VoidReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *VoidReporter) Warnf(msg string, a ...any) {
}

func (r *VoidReporter) Infof(msg string, a ...any) {
}

func (r *VoidReporter) Verbosef(msg string, a ...any) {
}

func (r *VoidReporter) PrintResult(context *cli.Context, vulnResult *models.VulnerabilityResults) error {
	return nil
}

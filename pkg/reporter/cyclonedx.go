package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/output/sbom"
	"github.com/urfave/cli/v2"

	"github.com/DataDog/datadog-sbom-generator/internal/output"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type CycloneDXReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func NewCycloneDXReporter(stdout, stderr io.Writer, level VerbosityLevel) *CycloneDXReporter {
	return &CycloneDXReporter{
		stdout:     stdout,
		stderr:     stderr,
		hasErrored: false,
		level:      level,
	}
}

func (r *CycloneDXReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.stderr, format, a...)
	r.hasErrored = true
}

func (r *CycloneDXReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *CycloneDXReporter) Warnf(format string, a ...any) {
	if WarnLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) Infof(format string, a ...any) {
	if InfoLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) Verbosef(format string, a ...any) {
	if VerboseLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *CycloneDXReporter) PrintResult(context *cli.Context, vulnerabilityResults *models.VulnerabilityResults) error {
	tool := sbom.Tool{Name: context.App.Name, Version: context.App.Version}
	errs := output.PrintCycloneDXResults(tool, vulnerabilityResults, r.stdout)
	if errs != nil {
		for _, err := range strings.Split(errs.Error(), "\n") {
			r.Warnf("Failed to parse package URL: %v", err)
		}
	}

	return nil
}

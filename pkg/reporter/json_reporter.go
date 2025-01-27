package reporter

import (
	"fmt"
	"io"

	"github.com/datadog/datadog-sbom-generator/internal/output"
	"github.com/datadog/datadog-sbom-generator/pkg/models"
)

// JSONReporter prints vulnerability results in JSON format to stdout. Runtime information
// will be written to stderr.
type JSONReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
}

func NewJSONReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *JSONReporter {
	return &JSONReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		hasErrored: false,
	}
}

func (r *JSONReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.stderr, format, a...)
	r.hasErrored = true
}

func (r *JSONReporter) Error(s string) {
	fmt.Fprint(r.stderr, s)
	r.hasErrored = true
}

func (r *JSONReporter) HasErrored() bool {
	return r.hasErrored
}

func (r *JSONReporter) Warnf(format string, a ...any) {
	if WarnLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *JSONReporter) Warn(s string) {
	if WarnLevel <= r.level {
		fmt.Fprint(r.stderr, s)
	}
}

func (r *JSONReporter) Infof(format string, a ...any) {
	if InfoLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *JSONReporter) Info(s string) {
	if InfoLevel <= r.level {
		fmt.Fprint(r.stderr, s)
	}
}

func (r *JSONReporter) Verbosef(format string, a ...any) {
	if VerboseLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *JSONReporter) Verbose(s string) {
	if VerboseLevel <= r.level {
		fmt.Fprint(r.stderr, s)
	}
}

func (r *JSONReporter) PrintResult(vulnResult *models.VulnerabilityResults) error {
	return output.PrintJSONResults(vulnResult, r.stdout)
}

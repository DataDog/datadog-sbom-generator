package reporter

import (
	"fmt"
	"io"

	"github.com/urfave/cli/v2"

	"github.com/DataDog/datadog-sbom-generator/internal/output"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// JSONReporter prints vulnerability results in JSON format to stdout. Runtime information
// will be written to stderr.
type JSONReporter struct {
	hasErrored bool
	stdout     io.Writer
	stderr     io.Writer
	level      VerbosityLevel
	pretty     bool
}

func NewJSONReporter(stdout io.Writer, stderr io.Writer, level VerbosityLevel) *JSONReporter {
	return NewJSONReporterWithPretty(stdout, stderr, level, true)
}

func NewJSONReporterWithPretty(stdout io.Writer, stderr io.Writer, level VerbosityLevel, pretty bool) *JSONReporter {
	return &JSONReporter{
		stdout:     stdout,
		stderr:     stderr,
		level:      level,
		pretty:     pretty,
		hasErrored: false,
	}
}

func (r *JSONReporter) Errorf(format string, a ...any) {
	fmt.Fprintf(r.stderr, format, a...)
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

func (r *JSONReporter) Infof(format string, a ...any) {
	if InfoLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *JSONReporter) Verbosef(format string, a ...any) {
	if VerboseLevel <= r.level {
		fmt.Fprintf(r.stderr, format, a...)
	}
}

func (r *JSONReporter) PrintResult(context *cli.Context, vulnResult *models.VulnerabilityResults) error {
	return output.PrintJSONResultsWithPretty(vulnResult, r.stdout, r.pretty)
}

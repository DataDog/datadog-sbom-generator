package reporter

import (
	"fmt"
	"io"
)

var format = []string{"json", "cyclonedx-1-5"}

func Format() []string {
	return format
}

// New returns an implementation of the reporter interface depending on the format passed in
// set terminalWidth as 0 to indicate the output is not a terminal and pretty formatting control
func New(format string, stdout, stderr io.Writer, level VerbosityLevel, pretty bool) (Reporter, error) {
	switch format {
	case "json":
		return NewJSONReporterWithPretty(stdout, stderr, level, pretty), nil
	case "cyclonedx-1-5":
		return NewCycloneDXReporterWithPretty(stdout, stderr, level, pretty), nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}

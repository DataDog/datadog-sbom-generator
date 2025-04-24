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
// set terminalWidth as 0 to indicate the output is not a terminal
func New(format string, stdout, stderr io.Writer, level VerbosityLevel) (Reporter, error) {
	switch format {
	case "json":
		return NewJSONReporter(stdout, stderr, level), nil
	case "cyclonedx-1-5":
		return NewCycloneDXReporter(stdout, stderr, level), nil
	default:
		return nil, fmt.Errorf("%v is not a valid format", format)
	}
}

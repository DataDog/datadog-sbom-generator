package reporter_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

func TestCycloneDXReporter_Errorf(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	writer := &bytes.Buffer{}
	r := reporter.NewCycloneDXReporter(io.Discard, writer, reporter.ErrorLevel)

	r.Errorf(text)

	if writer.String() != text {
		t.Error("Error level message should have been printed")
	}
	if !r.HasErrored() {
		t.Error("HasErrored() should have returned true")
	}
}

func TestCycloneDXReporter_Warnf(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.WarnLevel, expectedPrintout: text},
		{lvl: reporter.ErrorLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewCycloneDXReporter(io.Discard, writer, test.lvl)

		r.Warnf(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestCycloneDXReporter_Infof(t *testing.T) {
	t.Parallel()

	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{lvl: reporter.InfoLevel, expectedPrintout: text},
		{lvl: reporter.WarnLevel, expectedPrintout: ""},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewCycloneDXReporter(io.Discard, writer, test.lvl)

		r.Infof(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

func TestCycloneDXReporter_Verbosef(t *testing.T) {
	t.Parallel()
	text := "hello world!"
	tests := []struct {
		lvl              reporter.VerbosityLevel
		expectedPrintout string
	}{
		{
			lvl:              reporter.VerboseLevel,
			expectedPrintout: text,
		},
		{
			lvl:              reporter.InfoLevel,
			expectedPrintout: "",
		},
	}

	for _, test := range tests {
		writer := &bytes.Buffer{}
		r := reporter.NewCycloneDXReporter(io.Discard, writer, test.lvl)

		r.Verbosef(text)

		if writer.String() != test.expectedPrintout {
			t.Errorf("expected \"%s\", got \"%s\"", test.expectedPrintout, writer.String())
		}
	}
}

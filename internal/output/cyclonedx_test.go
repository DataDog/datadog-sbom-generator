package output_test

import (
	"bytes"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/output"
	"github.com/DataDog/datadog-sbom-generator/internal/output/sbom"
	"github.com/DataDog/datadog-sbom-generator/internal/testutility"
)

var defaultTool = sbom.Tool{
	Name:    "datadog-sbom-generator",
	Version: "1.0.1",
}

func TestPrintCycloneDX15Results_WithDependencies(t *testing.T) {
	t.Parallel()

	testOutputWithArtifacts(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintCycloneDXResultsWithPretty(defaultTool, args.vulnResult, outputWriter, true)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintCycloneDX15Results_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintCycloneDXResultsWithPretty(defaultTool, args.vulnResult, outputWriter, true)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintCycloneDX15Results_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintCycloneDXResultsWithPretty(defaultTool, args.vulnResult, outputWriter, true)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

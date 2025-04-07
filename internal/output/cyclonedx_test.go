package output_test

import (
	"bytes"
	"testing"

	"github.com/datadog/datadog-sbom-generator/internal/output"
	"github.com/datadog/datadog-sbom-generator/internal/testutility"
)

func TestPrintCycloneDX15Results_WithDependencies(t *testing.T) {
	t.Parallel()

	testOutputWithArtifacts(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		err := output.PrintCycloneDXResults(args.vulnResult, outputWriter)

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
		err := output.PrintCycloneDXResults(args.vulnResult, outputWriter)

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
		err := output.PrintCycloneDXResults(args.vulnResult, outputWriter)

		if err != nil {
			t.Errorf("%v", err)
		}

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

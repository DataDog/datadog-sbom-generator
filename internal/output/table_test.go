package output_test

import (
	"bytes"
	"testing"

	"github.com/datadog/datadog-sbom-generator/internal/output"
	"github.com/datadog/datadog-sbom-generator/internal/testutility"
	"github.com/jedib0t/go-pretty/v6/text"
)

func TestPrintTableResults_StandardTerminalWidth_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 80)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_StandardTerminalWidth_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 80)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_LongTerminalWidth_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 800)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_LongTerminalWidth_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, 800)

		testutility.NewSnapshot().MatchText(t, text.StripEscape(outputWriter.String()))
	})
}

func TestPrintTableResults_NoTerminalWidth_WithVulnerabilities(t *testing.T) {
	t.Parallel()

	testOutputWithVulnerabilities(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, -1)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

func TestPrintTableResults_NoTerminalWidth_WithMixedIssues(t *testing.T) {
	t.Parallel()

	testOutputWithMixedIssues(t, func(t *testing.T, args outputTestCaseArgs) {
		t.Helper()

		outputWriter := &bytes.Buffer{}
		output.PrintTableResults(args.vulnResult, outputWriter, -1)

		testutility.NewSnapshot().MatchText(t, outputWriter.String())
	})
}

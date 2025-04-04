package output

import (
	"io"
	"path/filepath"
	"strings"

	"github.com/datadog/datadog-sbom-generator/internal/utility/results"
	"github.com/datadog/datadog-sbom-generator/pkg/lockfile"
	"github.com/datadog/datadog-sbom-generator/pkg/models"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// OSVBaseVulnerabilityURL is the base URL for detailed vulnerability views.
// Copied in from osv package to avoid referencing the osv package unnecessarily
const OSVBaseVulnerabilityURL = "https://osv.dev/"

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, terminalWidth int) {
	if terminalWidth <= 0 {
		text.DisableColors()
	}

	// Render the vulnerabilities.
	outputTable := newTable(outputWriter, terminalWidth)
	outputTable = tableBuilder(outputTable, vulnResult)
	if outputTable.Length() != 0 {
		outputTable.Render()
	}

	// Render the licenses if any.
	outputLicenseTable := newTable(outputWriter, terminalWidth)
	if outputLicenseTable.Length() == 0 {
		return
	}
	outputLicenseTable.Render()
}

func newTable(outputWriter io.Writer, terminalWidth int) table.Writer {
	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)

	// use fancy characters if we're outputting to a terminal
	if terminalWidth > 0 {
		outputTable.SetStyle(table.StyleRounded)
		outputTable.SetAllowedRowLength(terminalWidth)
	}

	outputTable.Style().Options.DoNotColorBordersAndSeparators = true
	outputTable.Style().Color.Row = text.Colors{text.Reset, text.BgHiBlack}
	outputTable.Style().Color.RowAlternate = text.Colors{text.Reset, text.BgBlack}

	return outputTable
}

func tableBuilder(outputTable table.Writer, vulnResult *models.VulnerabilityResults) table.Writer {
	outputTable.AppendHeader(table.Row{"OSV URL", "CVSS", "Ecosystem", "Package", "Version", "Source"})
	rows := tableBuilderInner(vulnResult, true)
	for _, elem := range rows {
		outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
	}

	uncalledRows := tableBuilderInner(vulnResult, false)
	if len(uncalledRows) == 0 {
		return outputTable
	}

	outputTable.AppendSeparator()
	outputTable.AppendRow(table.Row{"Uncalled vulnerabilities"})
	outputTable.AppendSeparator()

	for _, elem := range uncalledRows {
		outputTable.AppendRow(elem.row, table.RowConfig{AutoMerge: elem.shouldMerge})
	}

	return outputTable
}

type tbInnerResponse struct {
	row         table.Row
	shouldMerge bool
}

func tableBuilderInner(vulnResult *models.VulnerabilityResults, calledVulns bool) []tbInnerResponse {
	allOutputRows := []tbInnerResponse{}
	workingDir := mustGetWorkingDirectory()

	for _, sourceRes := range vulnResult.Results {
		for _, pkg := range sourceRes.Packages {
			source := sourceRes.Source
			sourcePath, err := filepath.Rel(workingDir, source.Path)
			if err == nil { // Simplify the path if possible
				source.Path = sourcePath
			}

			// Merge groups into the same row
			for _, group := range pkg.Groups {
				if group.IsCalled() != calledVulns {
					continue
				}

				outputRow := table.Row{}
				shouldMerge := false

				var links []string

				for _, vuln := range group.IDs {
					links = append(links, OSVBaseVulnerabilityURL+text.Bold.Sprintf("%s", vuln))
				}

				outputRow = append(outputRow, strings.Join(links, "\n"))
				outputRow = append(outputRow, group.MaxSeverity)

				if pkg.Package.Ecosystem == "" && pkg.Package.Commit != "" {
					pkgCommitStr := results.PkgToString(pkg.Package)
					outputRow = append(outputRow, "GIT", pkgCommitStr, pkgCommitStr)
					shouldMerge = true
				} else {
					name := pkg.Package.Name
					if lockfile.Ecosystem(pkg.Package.Ecosystem).IsDevGroup(pkg.DepGroups) {
						name += " (dev)"
					}
					outputRow = append(outputRow, pkg.Package.Ecosystem, name, pkg.Package.Version)
				}

				outputRow = append(outputRow, source.Path)
				allOutputRows = append(allOutputRows, tbInnerResponse{
					row:         outputRow,
					shouldMerge: shouldMerge,
				})
			}
		}
	}

	return allOutputRows
}

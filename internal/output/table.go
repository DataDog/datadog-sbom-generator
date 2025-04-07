package output

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintTableResults(outputWriter io.Writer, terminalWidth int) {
	if terminalWidth <= 0 {
		text.DisableColors()
	}

	// Render the vulnerabilities.
	outputTable := newTable(outputWriter, terminalWidth)
	outputTable = tableBuilder(outputTable)
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

func tableBuilder(outputTable table.Writer) table.Writer {
	outputTable.AppendHeader(table.Row{"OSV URL", "CVSS", "Ecosystem", "Package", "Version", "Source"})

	outputTable.AppendSeparator()
	outputTable.AppendRow(table.Row{"Uncalled vulnerabilities"})
	outputTable.AppendSeparator()

	return outputTable
}

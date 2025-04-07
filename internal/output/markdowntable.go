package output

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// PrintTableResults prints the osv scan results into a human friendly table.
func PrintMarkdownTableResults(outputWriter io.Writer) {
	text.DisableColors()

	outputTable := table.NewWriter()
	outputTable.SetOutputMirror(outputWriter)
	outputTable = tableBuilder(outputTable)

	if outputTable.Length() != 0 {
		outputTable.RenderMarkdown()
	}

	outputLicenseTable := table.NewWriter()
	outputLicenseTable.SetOutputMirror(outputWriter)

	if outputLicenseTable.Length() == 0 {
		return
	}
	outputLicenseTable.RenderMarkdown()
}

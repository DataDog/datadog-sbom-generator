package parsers

import (
	"io"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/urfave/cli/v2"
)

func ListCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "list",
		Usage:       "list supported lockfile parsers",
		Description: "lists all lockfile parsers currently supported and available for use in SBOM generation",
		Action: func(c *cli.Context) error {
			action(stdout)
			return nil
		},
	}
}

func action(stdout io.Writer) {
	extractorsResult := extractor.ListSupportedExtractors()
	t := table.NewWriter()
	t.SetOutputMirror(stdout)
	t.AppendHeader(table.Row{"Language", "Package Manager", "Lockfile Parsers"})
	for name, extractor := range extractorsResult {
		language := models.PackageManagerToLanguage[extractor.PackageManager()]
		t.AppendRow(table.Row{language, extractor.PackageManager(), name})
	}
	t.SortBy([]table.SortBy{
		{Name: "Language", Mode: table.Asc},
		{Name: "Package Manager", Mode: table.Asc},
		{Name: "Lockfile Parsers", Mode: table.Asc},
	})
	t.Render()
}

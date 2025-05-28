package parsers

import (
	"io"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
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
	extractorsResult := lockfile.ListExtractors()
	t := table.NewWriter()
	t.SetOutputMirror(stdout)
	t.AppendHeader(table.Row{"Parsers"})
	for _, extractor := range extractorsResult {
		t.AppendRow(table.Row{extractor})
	}
	t.Render()
}

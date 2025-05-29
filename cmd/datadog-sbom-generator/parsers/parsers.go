package parsers

import (
	"io"

	"github.com/urfave/cli/v2"
)

func Command(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "parsers",
		Usage:       "inspect parsers used for SBOM generation",
		Description: "provides functionality related to parsers used by the generator, including listing available parsers",
		Subcommands: []*cli.Command{
			ListCommand(stdout),
		},
	}
}

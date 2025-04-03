package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/datadog/datadog-sbom-generator/pkg/lockfile"

	"github.com/datadog/datadog-sbom-generator/pkg/osvscanner"
	"github.com/datadog/datadog-sbom-generator/pkg/reporter"
	"golang.org/x/term"

	"github.com/urfave/cli/v2"
)

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name:        "scan",
		Usage:       "scans various package managers for dependencies and produce an SBOM",
		Description: "scans various package managers for dependencies and produce an SBOM",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:      "lockfile",
				Aliases:   []string{"L"},
				Usage:     "scan package lockfile on this path",
				TakesFile: true,
			},
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "sets the output format; value can be: " + strings.Join(reporter.Format(), ", "),
				Value:   "table",
				Action: func(context *cli.Context, s string) error {
					if slices.Contains(reporter.Format(), s) {
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
				},
			},
			&cli.StringFlag{
				Name:      "output",
				Usage:     "saves the result to the given file path",
				TakesFile: true,
			},
			&cli.BoolFlag{
				Name:  "not-recursive",
				Usage: "do not check subdirectories",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "no-ignore",
				Usage: "also scan files that would be ignored by .gitignore",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "verbosity",
				Usage: "specify the level of information that should be provided during runtime; value can be: " + strings.Join(reporter.VerbosityLevels(), ", "),
				Value: "error",
			},
			&cli.StringSliceFlag{
				Name:  "enable-parsers",
				Usage: fmt.Sprintf("Explicitly define which lockfile to parse. If set, any non-set parsers will be ignored. (Available parsers: %v)", lockfile.ListExtractors()),
			},
		},
		ArgsUsage: "[directory1 directory2...]",
		Action: func(c *cli.Context) error {
			var err error
			*r, err = action(c, stdout, stderr)

			return err
		},
	}
}

func action(context *cli.Context, stdout, stderr io.Writer) (reporter.Reporter, error) {
	format := context.String("format")

	outputPath := context.String("output")

	termWidth := 0
	var err error
	if outputPath != "" { // Output is definitely a file
		stdout, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	} else { // Output might be a terminal
		if stdoutAsFile, ok := stdout.(*os.File); ok {
			termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
			if err != nil { // If output is not a terminal,
				termWidth = 0
			}
		}
	}

	verbosityLevel, err := reporter.ParseVerbosityLevel(context.String("verbosity"))
	if err != nil {
		return nil, err
	}
	r, err := reporter.New(format, stdout, stderr, verbosityLevel, termWidth)
	if err != nil {
		return r, err
	}

	vulnResult, err := osvscanner.DoScan(osvscanner.ScannerActions{
		LockfilePaths:  context.StringSlice("lockfile"),
		Recursive:      !context.Bool("not-recursive"),
		NoIgnore:       context.Bool("no-ignore"),
		DirectoryPaths: context.Args().Slice(),
		EnableParsers:  context.StringSlice("enable-parsers"),
	}, r)

	if err != nil && !errors.Is(err, osvscanner.NoPackagesFoundErr) && !errors.Is(err, osvscanner.VulnerabilitiesFoundErr) {
		return r, err
	}

	if errPrint := r.PrintResult(&vulnResult); errPrint != nil {
		return r, fmt.Errorf("failed to write output: %w", errPrint)
	}

	// This may be nil.
	return r, err
}

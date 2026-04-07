package scan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/DataDog/datadog-sbom-generator/pkg/scanner"
	"github.com/urfave/cli/v2"
)

func Command(stdout, stderr io.Writer, r *reporter.Reporter) *cli.Command {
	return &cli.Command{
		Name: "scan",
		UsageText: `datadog-sbom-generator scan [flags] [directory1 directory2...]

Examples:
	# Scan the current directory
	datadog-sbom-generator scan .

	# Scan a specific directory and specify the output file
	datadog-sbom-generator scan --output "/tmp/sbom.json" /path/to/directory

	# Set verbosity level to verbose
	datadog-sbom-generator scan --verbosity verbose .

	# Exclude specific paths from being scanned
	datadog-sbom-generator scan --exclude "node_modules/**,test/**" .`,
		Description: "scans various package managers for dependencies and produce an SBOM",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "sets the output format; value can be: " + strings.Join(reporter.Format(), ", "),
				Value:   "cyclonedx-1-5",
				Action: func(context *cli.Context, s string) error {
					if slices.Contains(reporter.Format(), s) {
						return nil
					}

					return fmt.Errorf("unsupported output format \"%s\" - must be one of: %s", s, strings.Join(reporter.Format(), ", "))
				},
			},
			&cli.StringFlag{
				Name:      "output",
				Aliases:   []string{"o"},
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
			&cli.BoolFlag{
				Name:  "reachability",
				Usage: "enable reachability analysis",
				Value: false,
			},
			&cli.StringFlag{
				Name:    "verbosity",
				Aliases: []string{"v"},
				Usage:   "specify the level of information that should be provided during runtime; value can be: " + strings.Join(reporter.VerbosityLevels(), ", "),
				Value:   "error",
			},
			&cli.StringSliceFlag{
				Name:  "enable-parsers",
				Usage: "filter lockfiles to parse by lockfile, package manager or language. Use individual lockfile names (e.g., 'package-lock.json', 'pom.xml'), package manager names(e.g., 'gradle', 'poetry') or language names (e.g., 'javascript', 'java'). To list available parsers use the 'parsers list' command.",
			},
			&cli.StringSliceFlag{
				Name:  "exclude",
				Usage: "exclude paths from being scanned using a glob expression (relative to scanned directory)",
			},
			&cli.BoolFlag{
				Name:  "pretty",
				Usage: "format output with indentation and newlines for readability",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "exit-on-config-failure",
				Usage: "stop scanning if the settings API call fails (default: log a warning and continue)",
				Value: false,
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

	var err error
	if outputPath != "" { // Output is definitely a file
		stdout, err = os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	}

	verbosityLevel, err := reporter.ParseVerbosityLevel(context.String("verbosity"))
	if err != nil {
		return nil, err
	}
	pretty := context.Bool("pretty")
	r, err := reporter.New(format, stdout, stderr, verbosityLevel, pretty)
	if err != nil {
		return r, err
	}

	vulnResult, err := scanner.DoScan(scanner.ScannerActions{
		Recursive:           !context.Bool("not-recursive"),
		NoIgnore:            context.Bool("no-ignore"),
		Reachability:        context.Bool("reachability"),
		DirectoryPaths:      context.Args().Slice(),
		ExcludePaths:        context.StringSlice("exclude"),
		EnableParsers:       context.StringSlice("enable-parsers"),
		ExitOnConfigFailure: context.Bool("exit-on-config-failure"),
	}, r)

	if err != nil && !errors.Is(err, scanner.NoPackagesFoundErr) && !errors.Is(err, scanner.VulnerabilitiesFoundErr) {
		return r, err
	}

	if errPrint := r.PrintResult(context, &vulnResult); errPrint != nil {
		return r, fmt.Errorf("failed to write output: %w", errPrint)
	}

	// This may be nil.
	return r, err
}

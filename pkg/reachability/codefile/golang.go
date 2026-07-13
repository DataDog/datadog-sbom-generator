package codefile

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
)

// symbolTypeFunction is the only Go symbol type currently understood.
const symbolTypeFunction = "function"

const tsQueryForGoImports = `
(import_spec
	name: (package_identifier)? @alias
	name: (dot)? @blankOrDotImport
	name: (blank_identifier)? @blankOrDotImport
	path: (interpreted_string_literal (interpreted_string_literal_content) @path))
`

const tsQueryForGoCall = `
(call_expression
	function: (selector_expression
		operand: (identifier) @pkg
		field: (field_identifier) @fn) @selector)
`

var majorVersionSuffixPattern = cachedregexp.MustCompile(`^v[0-9]+$`)
var dottedMajorVersionSuffixPattern = cachedregexp.MustCompile(`\.v[0-9]+$`)

type ReachabilityGo struct {
	tsParser    *treesitter.Parser
	importQuery *treesitter.Query
	callQuery   *treesitter.Query

	aliasCaptureIdx      uint
	blankOrDotCaptureIdx uint
	pathCaptureIdx       uint
	pkgCaptureIdx        uint
	fnCaptureIdx         uint
	selectorCaptureIdx   uint

	reporter reporter.Reporter
}

// NewGoReachableDetector creates a new ReachabilityGo instance that once instantiated can be
// used to parse Go files. You should call Close() on the instance once you're finished parsing.
func NewGoReachableDetector(r reporter.Reporter) (*ReachabilityGo, error) {
	tsLanguage := treesitter.NewLanguage(tree_sitter_go.Language())

	tsParser := treesitter.NewParser()
	if err := tsParser.SetLanguage(tsLanguage); err != nil {
		return nil, fmt.Errorf("failed to set tree-sitter Go language on parser: %w", err)
	}

	importQuery, err := treesitter.NewQuery(tsLanguage, tsQueryForGoImports)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for Go imports: %w", err)
	}

	callQuery, err := treesitter.NewQuery(tsLanguage, tsQueryForGoCall)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for Go calls: %w", err)
	}

	aliasCaptureIdx, _ := importQuery.CaptureIndexForName("alias")
	blankOrDotCaptureIdx, _ := importQuery.CaptureIndexForName("blankOrDotImport")
	pathCaptureIdx, _ := importQuery.CaptureIndexForName("path")
	pkgCaptureIdx, _ := callQuery.CaptureIndexForName("pkg")
	fnCaptureIdx, _ := callQuery.CaptureIndexForName("fn")
	selectorCaptureIdx, _ := callQuery.CaptureIndexForName("selector")

	return &ReachabilityGo{
		tsParser:             tsParser,
		importQuery:          importQuery,
		callQuery:            callQuery,
		aliasCaptureIdx:      aliasCaptureIdx,
		blankOrDotCaptureIdx: blankOrDotCaptureIdx,
		pathCaptureIdx:       pathCaptureIdx,
		pkgCaptureIdx:        pkgCaptureIdx,
		fnCaptureIdx:         fnCaptureIdx,
		selectorCaptureIdx:   selectorCaptureIdx,
		reporter:             reporter.Effective(r),
	}, nil
}

// Close closes all hanging tree-sitter related resources.
// This should only be called once you're finished parsing all Go files.
func (r *ReachabilityGo) Close() {
	r.tsParser.Close()
	r.importQuery.Close()
	r.callQuery.Close()
}

// resolveImportAliases walks all import specs in the parsed tree and returns a map of module
// import path -> local identifiers used to reference that module in this file. Unaliased
// imports are assigned a heuristic identifier: the last path segment, with a trailing
// major-version suffix (e.g. "/v2") stripped, per Go module convention. Dot imports and blank
// imports are skipped entirely: they don't bind a package selector (e.g. "pkg.Func"), so
// defaulting them to an identifier would risk matching an unrelated import that happens to
// resolve to the same default alias.
func (r *ReachabilityGo) resolveImportAliases(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) map[string][]string {
	moduleToAliases := make(map[string][]string)

	matches := queryCursor.Matches(r.importQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var alias, modulePath string
		var isBlankOrDotImport bool

		for _, capture := range match.Captures {
			switch capture.Index {
			case uint32(r.aliasCaptureIdx): //nolint:gosec
				alias = capture.Node.Utf8Text(fileContent)
			case uint32(r.blankOrDotCaptureIdx): //nolint:gosec
				isBlankOrDotImport = true
			case uint32(r.pathCaptureIdx): //nolint:gosec
				modulePath = capture.Node.Utf8Text(fileContent)
			}
		}

		if modulePath == "" || isBlankOrDotImport {
			continue
		}

		if alias == "" {
			alias = defaultIdentifierForModulePath(modulePath)
		}

		moduleToAliases[modulePath] = append(moduleToAliases[modulePath], alias)
	}

	return moduleToAliases
}

// defaultIdentifierForModulePath derives the package identifier Go code would use for an
// unaliased import, using the last path segment and stripping a trailing major-version suffix.
// Two version conventions are handled: the path-segment style (e.g. "github.com/foo/bar/v2" ->
// "bar") and the dotted gopkg.in style (e.g. "gopkg.in/yaml.v3" -> "yaml"). Leading "go-" and
// trailing "-go" repository-naming conventions are also stripped (e.g. "github.com/redis/go-redis/v9"
// -> "redis", "github.com/CycloneDX/cyclonedx-go" -> "cyclonedx"), since Go identifiers can't
// contain hyphens, so a hyphenated segment is never the real package name.
func defaultIdentifierForModulePath(modulePath string) string {
	segments := strings.Split(modulePath, "/")
	identifier := segments[len(segments)-1]

	switch {
	case len(segments) > 1 && majorVersionSuffixPattern.MatchString(identifier):
		identifier = segments[len(segments)-2]
	case dottedMajorVersionSuffixPattern.MatchString(identifier):
		identifier = identifier[:strings.LastIndex(identifier, ".")]
	}

	if rest, ok := strings.CutPrefix(identifier, "go-"); ok && rest != "" {
		identifier = rest
	} else if rest, ok := strings.CutSuffix(identifier, "-go"); ok && rest != "" {
		identifier = rest
	}

	return identifier
}

func (r *ReachabilityGo) Detect(ctx context.Context, dir string, path string, detectionResults models.DetectionResults, advisoriesToCheck []models.AdvisoryToCheck) error {
	fileContent, err := readFileContent(path)
	if err != nil {
		return err
	}

	tree := parseFile(ctx, r.tsParser, fileContent)
	defer tree.Close()

	if len(advisoriesToCheck) == 0 {
		return nil
	}

	importCursor := treesitter.NewQueryCursor()
	defer importCursor.Close()
	moduleToAliases := r.resolveImportAliases(tree, fileContent, importCursor)

	callCursor := treesitter.NewQueryCursor()
	defer callCursor.Close()

	for _, advisoryToCheck := range advisoriesToCheck {
		for _, s := range advisoryToCheck.Symbols {
			if s.Type != symbolTypeFunction {
				r.reporter.Warnf("No Go detection support for symbol type %s", s.Type)
				continue
			}

			aliases, moduleImported := moduleToAliases[s.Value]
			if !moduleImported {
				continue
			}

			matches := callCursor.Matches(r.callQuery, tree.RootNode(), fileContent)
			for match := matches.Next(); match != nil; match = matches.Next() {
				var pkgText, fnText string
				var selectorNode treesitter.Node

				for _, capture := range match.Captures {
					switch capture.Index {
					case uint32(r.pkgCaptureIdx): //nolint:gosec
						pkgText = capture.Node.Utf8Text(fileContent)
					case uint32(r.fnCaptureIdx): //nolint:gosec
						fnText = capture.Node.Utf8Text(fileContent)
					case uint32(r.selectorCaptureIdx): //nolint:gosec
						selectorNode = capture.Node
					}
				}

				if fnText != s.Name || !slices.Contains(aliases, pkgText) {
					continue
				}

				packageLocation, err := buildPackageLocation(dir, path, selectorNode.StartPosition(), selectorNode.EndPosition())
				if err != nil {
					return err
				}

				recordMatch(detectionResults, advisoryToCheck.Purl, advisoryToCheck.AdvisoryID, selectorNode.Utf8Text(fileContent), packageLocation)
			}
		}
	}

	return nil
}

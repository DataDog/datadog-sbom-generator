package golang

import (
	"context"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
)

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

var majorVersionSuffixPattern = cachedregexp.MustCompile(`^v([2-9]|[1-9][0-9]+)$`)
var dottedMajorVersionSuffixPattern = cachedregexp.MustCompile(`\.v[0-9]+$`)

var _ codefile.Detector = (*Detector)(nil)

type Detector struct {
	tsParser    *treesitter.Parser
	importQuery *treesitter.Query
	callQuery   *treesitter.Query

	aliasCaptureIdx      uint
	blankOrDotCaptureIdx uint
	pathCaptureIdx       uint
	pkgCaptureIdx        uint
	fnCaptureIdx         uint
	selectorCaptureIdx   uint

	// prefilterLiterals holds the unique module import paths across all advisories, as raw bytes.
	// A Go file can only match a vulnerable symbol if it imports that symbol's module, which
	// requires the import path to appear literally in the file. It's computed once per detector
	// (lazily, since advisories arrive with the first Detect call) and reused for every file.
	prefilterLiterals [][]byte
	prefilterBuilt    bool

	reporter reporter.Reporter
}

// NewDetector creates a new Detector instance that once instantiated can be
// used to parse Go files. You should call Close() on the instance once you're finished parsing.
func NewDetector(r reporter.Reporter) (*Detector, error) {
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

	return &Detector{
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
func (r *Detector) Close() {
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
func (r *Detector) resolveImportAliases(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) map[string][]string {
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
// "bar") and the dotted gopkg.in style (e.g. "gopkg.in/yaml.v3" -> "yaml"). The path-segment style
// only strips "v2" and above: Go's semantic-import-versioning convention never produces a "v0" or
// "v1" module-major-version suffix, so a trailing "v0"/"v1" segment (e.g. "k8s.io/api/core/v1") is
// always a real package name, not a version marker. Leading "go-" and trailing "-go"
// repository-naming conventions are also stripped (e.g. "github.com/redis/go-redis/v9" -> "redis",
// "github.com/CycloneDX/cyclonedx-go" -> "cyclonedx"), since Go identifiers can't contain hyphens,
// so a hyphenated segment is never the real package name.
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

func (r *Detector) Detect(ctx context.Context, dir string, path string, detectionResults models.DetectionResults, advisoriesToCheck []models.AdvisoryToCheck) error {
	if len(advisoriesToCheck) == 0 {
		return nil
	}

	fileContent, err := codefile.ReadFileContent(path)
	if err != nil {
		return err
	}

	// Cheap pre-filter: skip the expensive tree-sitter parse unless the file textually references
	// at least one vulnerable module. This is correct (no false negatives) because a match always
	// requires the module to be imported, which requires its import path to appear in the file.
	if !codefile.ContainsAnyLiteral(fileContent, r.prefilterForAdvisories(advisoriesToCheck)) {
		return nil
	}

	tree := codefile.ParseFile(ctx, r.tsParser, fileContent)
	defer tree.Close()

	importCursor := treesitter.NewQueryCursor()
	defer importCursor.Close()
	moduleToAliases := r.resolveImportAliases(tree, fileContent, importCursor)

	// Index the advisory symbols whose module this file actually imports by (localIdentifier,
	// functionName). Each call site is then matched by one map lookup instead of a scan over every
	// advisory symbol, keeping detection O(call sites) rather than O(call sites × all symbols).
	candidates := candidatesByCallSite(advisoriesToCheck, moduleToAliases)
	if len(candidates) == 0 {
		return nil
	}

	callCursor := treesitter.NewQueryCursor()
	defer callCursor.Close()

	// Run the call query over the tree once; re-running it per symbol would re-traverse the whole
	// tree needlessly.
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

		matched := candidates[callSiteKey{identifier: pkgText, function: fnText}]
		if len(matched) == 0 {
			continue
		}

		packageLocation, err := codefile.BuildPackageLocation(dir, path, selectorNode.StartPosition(), selectorNode.EndPosition())
		if err != nil {
			return err
		}

		symbolText := selectorNode.Utf8Text(fileContent)
		for _, c := range matched {
			codefile.RecordMatch(detectionResults, c.purl, c.advisoryID, symbolText, packageLocation)
		}
	}

	return nil
}

// callSiteKey identifies a Go call site as the local package identifier and the function name, e.g.
// the call `object.DecodeCommit(...)` has key {identifier: "object", function: "DecodeCommit"}.
type callSiteKey struct {
	identifier string
	function   string
}

// advisoryRef is the minimal advisory identity recorded for a matched call site.
type advisoryRef struct {
	purl       string
	advisoryID string
}

// candidatesByCallSite indexes the advisory function symbols whose module is imported by this file,
// keyed by the (localIdentifier, functionName) a matching call would have. Only imported modules
// contribute, so the index is empty when the file imports none of the vulnerable modules, letting
// Detect skip the call-query traversal entirely.
func candidatesByCallSite(advisoriesToCheck []models.AdvisoryToCheck, moduleToAliases map[string][]string) map[callSiteKey][]advisoryRef {
	candidates := make(map[callSiteKey][]advisoryRef)

	for _, advisoryToCheck := range advisoriesToCheck {
		for _, s := range advisoryToCheck.Symbols {
			if s.Type != codefile.SymbolTypeFunction {
				continue
			}

			aliases, moduleImported := moduleToAliases[s.Value]
			if !moduleImported {
				continue
			}

			for _, alias := range aliases {
				key := callSiteKey{identifier: alias, function: s.Name}
				candidates[key] = append(candidates[key], advisoryRef{purl: advisoryToCheck.Purl, advisoryID: advisoryToCheck.AdvisoryID})
			}
		}
	}

	return candidates
}

// prefilterForAdvisories returns the unique module import paths across all function advisories as
// raw bytes, building them once on first use and caching them for subsequent files. The advisory
// set is fixed for the lifetime of a run, so the literals never change between calls.
func (r *Detector) prefilterForAdvisories(advisoriesToCheck []models.AdvisoryToCheck) [][]byte {
	if !r.prefilterBuilt {
		r.prefilterLiterals = codefile.DistinctLiterals(advisoriesToCheck, func(s models.Symbols) string {
			if s.Type != codefile.SymbolTypeFunction {
				return ""
			}

			return s.Value
		})
		r.prefilterBuilt = true
	}

	return r.prefilterLiterals
}

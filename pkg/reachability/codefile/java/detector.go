package java

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_java "github.com/tree-sitter/tree-sitter-java/bindings/go"
)

var tsQueryForJavaClass = `
(object_creation_expression
	type: (_) @class
)`

var symbolTypeToTSQuery = map[string]string{
	codefile.SymbolTypeClass: tsQueryForJavaClass,
}

var _ codefile.Detector = (*Detector)(nil)

type Detector struct {
	tsParser               *treesitter.Parser
	tsQueriesPerSymbolType map[string]*treesitter.Query
	reporter               reporter.Reporter
}

// NewDetector creates a new Detector instance that once
// instantiated can be used to parse Java files. You should call Close() on the
// instance once you're finished parsing.
func NewDetector(r reporter.Reporter) (*Detector, error) {
	tsLanguage := treesitter.NewLanguage(tree_sitter_java.Language())

	tsParser := treesitter.NewParser()

	err := tsParser.SetLanguage(tsLanguage)
	if err != nil {
		return nil, fmt.Errorf("failed to set tree-sitter Java language on parser: %w", err)
	}

	// Create each once query and place them in a map for quick access during parsing.
	tsQueriesPerSymbolType := make(map[string]*treesitter.Query, len(symbolTypeToTSQuery))
	for symbolType, tsQuery := range symbolTypeToTSQuery {
		query, err := treesitter.NewQuery(tsLanguage, tsQuery)
		if err != nil {
			return nil, fmt.Errorf("failed to create tree-sitter query for %s: %w", symbolType, err)
		}
		tsQueriesPerSymbolType[symbolType] = query
	}

	return &Detector{
		tsParser:               tsParser,
		tsQueriesPerSymbolType: tsQueriesPerSymbolType,
		reporter:               reporter.Effective(r),
	}, nil
}

// Close closes all hanging tree-sitter related resources.
// This should only be called once you're finished parsing all Java files.
func (r *Detector) Close() {
	r.tsParser.Close()
	for _, query := range r.tsQueriesPerSymbolType {
		query.Close()
	}
}

func (r *Detector) Detect(ctx context.Context, dir string, path string, detectionResults models.DetectionResults, advisoriesToCheck []models.AdvisoryToCheck) error {
	fileContent, err := codefile.ReadFileContent(path)
	if err != nil {
		return err
	}

	tree := codefile.ParseFile(ctx, r.tsParser, fileContent)
	defer tree.Close()

	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()

	// Loop over all an advisories symbols; making a TS query for each instance.
	for _, advisoryToCheck := range advisoriesToCheck {
		for _, s := range advisoryToCheck.Symbols {
			query := r.tsQueriesPerSymbolType[s.Type]
			if query == nil {
				continue
			}

			// Run the TS query against the TS tree
			captures := queryCursor.Captures(query, tree.RootNode(), fileContent)

			// Iterate over all the matches from TS; we need to filter out the ones that are not relevant.
			for match, index := captures.Next(); match != nil; match, index = captures.Next() {
				// The class query can have multiple matches, but only one capture (@class).
				matchedText := match.Captures[index].Node.Utf8Text(fileContent)

				/*
					Our TS query can return class creations in two formats that we need to check here:
					1. <name>
					2. <package>.<name>
					Example:
					1. CodebaseAwareObjectInputStream
					2. org.springframework.remoting.rmi.CodebaseAwareObjectInputStream
					Note: This logic is specific to class type and will need to be updated in the future when we build out further symbols.
				*/
				if matchedText == s.Name || matchedText == fmt.Sprintf("%s.%s", s.Value, s.Name) {
					packageLocation, err := codefile.BuildPackageLocation(dir, path, match.Captures[index].Node.StartPosition(), match.Captures[index].Node.EndPosition())
					if err != nil {
						return err
					}

					codefile.RecordMatch(detectionResults, advisoryToCheck.Purl, advisoryToCheck.AdvisoryID, matchedText, packageLocation)
				}
			}
		}
	}

	return nil
}

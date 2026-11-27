package githubactions

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"gopkg.in/yaml.v3"
)

const usesKey = "uses"

var fullCommitSHARegexp = cachedregexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// actionReference is a remote action or reusable workflow referenced by a `uses:` value.
type actionReference struct {
	// name is the "owner/repo" part of the reference, as written
	name string
	// ref is the tag, branch or commit SHA after the "@"
	ref string
}

var (
	errMalformedUses  = errors.New("malformed uses value")
	errUsesExpression = errors.New("expressions are not supported in uses values")
)

// parseUsesValue parses the value of a `uses:` key. It supports the forms
//
//	owner/repo@ref
//	owner/repo/path/to/action@ref
//	owner/repo/.github/workflows/workflow.yml@ref
//
// and returns (_, false, nil) for references that are not remote repositories: local actions or
// workflows ("./path") and docker images ("docker://image"). Values that look like a remote reference
// but cannot be resolved by GitHub (no ref, no repo, several "@") return errMalformedUses. GitHub rejects
// workflows with `${{ }}` expressions in `uses`, and their value is unknown: they return errUsesExpression.
func parseUsesValue(value string) (actionReference, bool, error) {
	if strings.Contains(value, "${{") {
		return actionReference{}, false, errUsesExpression
	}

	if strings.HasPrefix(value, "docker://") || strings.HasPrefix(value, ".") {
		return actionReference{}, false, nil
	}

	// Mirrors the GitHub runner: a remote reference has exactly one "@", and at least an owner and a
	// repository in its path, separated with "/" (or "\").
	parts := strings.Split(value, "@")
	if len(parts) != 2 || parts[1] == "" {
		return actionReference{}, false, errMalformedUses
	}

	segments := strings.FieldsFunc(parts[0], func(r rune) bool { return r == '/' || r == '\\' })
	if len(segments) < 2 {
		return actionReference{}, false, errMalformedUses
	}

	return actionReference{
		name: segments[0] + "/" + segments[1],
		ref:  parts[1],
	}, true, nil
}

// resolve follows YAML aliases (*anchor) to the node they point to.
func resolve(node *yaml.Node) *yaml.Node {
	for node != nil && node.Kind == yaml.AliasNode {
		node = node.Alias
	}

	return node
}

// mappingEntry returns the key and value nodes of the given key in a mapping node. They are returned as
// written: either can be an alias.
func mappingEntry(node *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	node = resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}

	for i := 0; i+1 < len(node.Content); i += 2 {
		keyNode := resolve(node.Content[i])
		if keyNode != nil && keyNode.Kind == yaml.ScalarNode && keyNode.Value == key {
			return node.Content[i], node.Content[i+1]
		}
	}

	return nil, nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	_, value := mappingEntry(node, key)

	return resolve(value)
}

// mappingValues returns the values of a mapping node, in declaration order.
func mappingValues(node *yaml.Node) []*yaml.Node {
	node = resolve(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}

	values := make([]*yaml.Node, 0, len(node.Content)/2)
	for i := 1; i < len(node.Content); i += 2 {
		values = append(values, resolve(node.Content[i]))
	}

	return values
}

// sequenceItems returns the items of a sequence node.
func sequenceItems(node *yaml.Node) []*yaml.Node {
	node = resolve(node)
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}

	items := make([]*yaml.Node, 0, len(node.Content))
	for _, item := range node.Content {
		items = append(items, resolve(item))
	}

	return items
}

// parseYAMLDocument decodes the content into its root node. It returns nil for an empty document.
func parseYAMLDocument(f extractor.DepFile) (*yaml.Node, []string, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	var document yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(content)).Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil, nil
		}

		return nil, nil, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	if len(document.Content) == 0 {
		return nil, nil, nil
	}

	return document.Content[0], fileposition.BytesToLines(content), nil
}

// usesCollector turns the `uses:` entries of a file into packages.
type usesCollector struct {
	path     string
	lines    []string
	context  extractor.ScanContext
	seen     map[*yaml.Node]struct{}
	packages []extractor.PackageDetails
}

func newUsesCollector(path string, lines []string, context extractor.ScanContext) *usesCollector {
	return &usesCollector{
		path:     path,
		lines:    lines,
		context:  context,
		seen:     make(map[*yaml.Node]struct{}),
		packages: []extractor.PackageDetails{},
	}
}

// collect extracts the `uses:` entry of a step or a job mapping, if any.
func (c *usesCollector) collect(node *yaml.Node) {
	keyNode, valueNode := mappingEntry(node, usesKey)
	if keyNode != nil && (keyNode.Kind == yaml.AliasNode || (valueNode != nil && valueNode.Kind == yaml.AliasNode)) {
		// `uses: *anchor` points to a value declared elsewhere: the block is located at that declaration,
		// like the name and version, so it does not span from the key to an unrelated line.
		keyNode = nil
	}
	keyNode, valueNode = resolve(keyNode), resolve(valueNode)
	if valueNode == nil || valueNode.Kind != yaml.ScalarNode {
		return
	}

	// A step defined once with an anchor and reused with aliases is the same declaration: report it once.
	if _, ok := c.seen[valueNode]; ok {
		return
	}
	c.seen[valueNode] = struct{}{}

	reference, ok, err := parseUsesValue(valueNode.Value)
	if err != nil {
		if c.context.Reporter != nil {
			c.context.Reporter.Warnf("Skipping %q in %s at line %d: %s\n", valueNode.Value, c.path, valueNode.Line, err)
		}

		return
	}
	if !ok {
		return
	}

	pkg := extractor.PackageDetails{
		Name:           reference.name,
		Version:        reference.ref,
		PackageManager: githubActionsPackageManager,
		Ecosystem:      models.EcosystemGitHubActions,
		IsDirect:       true,
	}
	if fullCommitSHARegexp.MatchString(reference.ref) {
		pkg.Commit = reference.ref
	}

	c.setLocations(&pkg, keyNode, valueNode, reference)
	c.packages = append(c.packages, pkg)
}

// setLocations sets the block location to the `uses: value` entry, and the name and version locations
// to the "owner/repo" and ref parts of the value, when the value can be found on its line.
func (c *usesCollector) setLocations(pkg *extractor.PackageDetails, keyNode *yaml.Node, valueNode *yaml.Node, reference actionReference) {
	if valueNode.Line < 1 || valueNode.Line > len(c.lines) {
		return
	}

	// yaml.v3 columns are 1-indexed and count runes, while positions are reported in bytes.
	line := c.lines[valueNode.Line-1]
	valueOffset := runeColumnToByteOffset(line, valueNode.Column)
	if valueOffset < 0 {
		return
	}

	index := strings.Index(line[valueOffset:], valueNode.Value)
	if index < 0 {
		// Multi-line or escaped scalars: the raw text differs from the decoded value.
		return
	}
	valueStart := valueOffset + index + 1
	valueEnd := valueStart + len(valueNode.Value)
	// Without a key, the block is the value (not its anchor), quotes included.
	blockStart := valueStart
	if valueNode.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 {
		blockStart--
		valueEnd++
	}
	blockLine := valueNode.Line
	if keyNode != nil && keyNode.Line >= 1 && keyNode.Line <= len(c.lines) {
		if keyOffset := runeColumnToByteOffset(c.lines[keyNode.Line-1], keyNode.Column); keyOffset >= 0 {
			blockLine = keyNode.Line
			blockStart = keyOffset + 1
		}
	}

	pkg.BlockLocation = models.FilePosition{
		Line:     models.Position{Start: blockLine, End: valueNode.Line},
		Column:   models.Position{Start: blockStart, End: valueEnd},
		Filename: c.path,
	}
	pkg.LocationRole = models.LocationRoleManifest

	// The value starts with "owner/repo", the ref follows the only "@".
	if strings.HasPrefix(valueNode.Value, reference.name) {
		pkg.NameLocation = &models.FilePosition{
			Line:     models.Position{Start: valueNode.Line, End: valueNode.Line},
			Column:   models.Position{Start: valueStart, End: valueStart + len(reference.name)},
			Filename: c.path,
		}
	}
	refStart := valueStart + strings.Index(valueNode.Value, "@") + 1
	pkg.VersionLocation = &models.FilePosition{
		Line:     models.Position{Start: valueNode.Line, End: valueNode.Line},
		Column:   models.Position{Start: refStart, End: refStart + len(reference.ref)},
		Filename: c.path,
	}
}

// runeColumnToByteOffset converts a 1-indexed rune column to a 0-indexed byte offset in the line.
func runeColumnToByteOffset(line string, column int) int {
	runeIndex := 0
	for byteOffset := range line {
		if runeIndex == column-1 {
			return byteOffset
		}
		runeIndex++
	}
	if runeIndex == column-1 {
		return len(line)
	}

	return -1
}

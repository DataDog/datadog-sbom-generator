package java

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/filereader"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

// ScopeVersionConstraints re-keys a scanned directory's pins so the backend folder rule matches Maven inheritance.
// Limitation: a non-inheriting pom nested in the folder of a pom with dependencies still gets that pom's pins.
func ScopeVersionConstraints(r reporter.Reporter, pkgs []extractor.PackageDetails) []extractor.PackageDetails {
	scope := newConstraintScope(pkgs)

	dropped := scope.droppedPins()
	copies, err := scope.pinCopies(dropped)
	if err != nil {
		r.Warnf("Keeping Maven version constraints unscoped: %v\n", err)
		return uniquePins(pkgs)
	}

	kept := slices.DeleteFunc(pkgs, func(pkg extractor.PackageDetails) bool {
		return pkg.IsVersionConstraint && !scope.keyedAtDeclaration(pkg, dropped)
	})
	scoped := slices.Concat(kept, copies)
	unique := uniquePins(scoped)

	if removed, collapsed := len(pkgs)-len(kept), len(scoped)-len(unique); removed+len(copies)+collapsed > 0 {
		r.Verbosef("Scoped Maven version constraints: %d removed from their declaring pom, %d keyed under modules, %d duplicates collapsed\n", removed, len(copies), collapsed)
	}

	return unique
}

// pinKey identifies a pin declaration: the pom declaring it and the package it pins.
type pinKey struct {
	file string
	name string
}

// pinOccurrence is everything that ends up in a pin's SBOM occurrence; every inheriting pom emits the same ones.
type pinOccurrence struct {
	name        string
	version     string
	block       models.FilePosition
	nameAt      models.FilePosition
	namespaceAt models.FilePosition
	versionAt   models.FilePosition
}

type constraintScope struct {
	poms     []string                              // scanned poms, by folder depth then path
	depPoms  []string                              // scanned poms whose folder declares dependencies
	pomByDir map[string]string                     // folder -> scanned pom
	pins     map[string][]extractor.PackageDetails // scanned pom -> its effective pins, by name
	pinNames map[string]map[string]bool            // scanned pom -> names of its effective pins
	pinFiles map[string]map[string]bool            // scanned pom -> files declaring its effective pins
	depsDirs map[string]bool                       // folders declaring at least one dependency
	declared map[pinKey]string                     // declaration -> the version its declaring pom resolves itself
}

func newConstraintScope(pkgs []extractor.PackageDetails) constraintScope {
	scope := constraintScope{
		pomByDir: map[string]string{},
		pins:     map[string][]extractor.PackageDetails{},
		pinNames: map[string]map[string]bool{},
		pinFiles: map[string]map[string]bool{},
		depsDirs: map[string]bool{},
		declared: map[pinKey]string{},
	}

	for _, pkg := range pkgs {
		pom := pkg.Source.Path
		if filepath.Base(pom) != models.MavenFilePath.String() {
			continue
		}
		scope.pomByDir[filepath.Dir(pom)] = pom

		if !pkg.IsVersionConstraint {
			if pkg.BlockLocation.Filename != "" {
				scope.depsDirs[filepath.Dir(pkg.BlockLocation.Filename)] = true
			}

			continue
		}
		scope.pins[pom] = append(scope.pins[pom], pkg)
		addToSet(scope.pinNames, pom, pkg.Name)
		addToSet(scope.pinFiles, pom, pkg.BlockLocation.Filename)
	}

	for _, pom := range scope.pomByDir {
		scope.poms = append(scope.poms, pom)
		slices.SortFunc(scope.pins[pom], func(a, b extractor.PackageDetails) int {
			return strings.Compare(a.Name, b.Name)
		})
	}
	slices.SortFunc(scope.poms, func(a, b string) int {
		separator := string(filepath.Separator)
		if depth := strings.Count(a, separator) - strings.Count(b, separator); depth != 0 {
			return depth
		}

		return strings.Compare(a, b)
	})
	for _, pom := range scope.poms {
		if scope.depsDirs[filepath.Dir(pom)] {
			scope.depPoms = append(scope.depPoms, pom)
		}
		// When the declaring pom isn't scanned, the first pom resolving the declaration stands in for it.
		for _, pin := range scope.pins[pom] {
			key := pinKeyOf(pin)
			if _, ok := scope.declared[key]; !ok || pom == key.file {
				scope.declared[key] = pin.Version
			}
		}
	}

	return scope
}

// keyedAtDeclaration reports whether pin stays keyed at its declaration: modules resolving it to another version
// (e.g. by overriding a property) get their own copy instead of a second, ambiguous version in the same folder.
func (s constraintScope) keyedAtDeclaration(pin extractor.PackageDetails, dropped map[pinKey]bool) bool {
	key := pinKeyOf(pin)

	return !dropped[key] && s.declared[key] == pin.Version
}

// droppedPins returns the declarations whose key would pin a nested pom that doesn't inherit them (aggregators).
func (s constraintScope) droppedPins() map[pinKey]bool {
	dropped := map[pinKey]bool{}

	for _, pom := range s.poms {
		for _, pin := range s.pins[pom] {
			key := pinKeyOf(pin)
			if _, decided := dropped[key]; decided {
				continue
			}
			dir := filepath.Dir(key.file)
			dropped[key] = !s.depsDirs[dir] && s.harms(dir, key.file, key.name)
		}
	}

	return dropped
}

// pinCopies keys each effective pin under the top-most pom that can't already resolve it through its folders.
func (s constraintScope) pinCopies(dropped map[pinKey]bool) ([]extractor.PackageDetails, error) {
	keys := map[string]map[string]map[string]bool{} // folder -> package -> versions keyed there
	for _, pom := range s.poms {
		for _, pin := range s.pins[pom] {
			if s.keyedAtDeclaration(pin, dropped) {
				addVersion(keys, filepath.Dir(pin.BlockLocation.Filename), pin.Name, pin.Version)
			}
		}
	}

	var copies []extractor.PackageDetails
	parentBlocks := map[string]models.FilePosition{}
	for _, pom := range s.poms {
		dir := filepath.Dir(pom)
		for _, pin := range s.pins[pom] {
			if resolvedVersions(keys, dir, pin.Name)[pin.Version] {
				continue
			}
			if !s.depsDirs[dir] && s.harms(dir, pin.BlockLocation.Filename, pin.Name) {
				continue
			}

			block, ok := parentBlocks[pom]
			if !ok {
				var err error
				if block, err = parentElementPosition(pom); err != nil {
					return nil, err
				}
				parentBlocks[pom] = block
			}
			copies = append(copies, pinCopy(pin, block))
			addVersion(keys, dir, pin.Name, pin.Version)
		}
	}

	return copies, nil
}

// harms reports whether a pin of package name declared in file, keyed under dir, would reach a pom with dependencies
// in dir or below that doesn't get that package in Maven, and that no closer pom with dependencies shields.
func (s constraintScope) harms(dir string, file string, name string) bool {
	for _, pom := range s.depPoms {
		if pom == file || s.pinNames[pom][name] || s.pinFiles[pom][file] {
			continue
		}
		if !isWithin(filepath.Dir(pom), dir) || s.shielded(dir, pom, name) {
			continue
		}

		return true
	}

	return false
}

// shielded reports whether a pom with dependencies that pins name sits strictly between dir and pom's folder: its own
// key is closer, so dropping the key under dir changes nothing for pom.
func (s constraintScope) shielded(dir string, pom string, name string) bool {
	for current := filepath.Dir(filepath.Dir(pom)); current != dir && isWithin(current, dir); current = filepath.Dir(current) {
		if other, ok := s.pomByDir[current]; ok && s.depsDirs[current] && s.pinNames[other][name] {
			return true
		}
	}

	return false
}

// parentElementPosition returns the block of the top-level <parent> element of a pom.
func parentElementPosition(path string) (models.FilePosition, error) {
	file, err := extractor.OpenLocalDepFile(path)
	if err != nil {
		return models.FilePosition{}, err
	}
	defer file.Close()

	decoder := xml.NewDecoder(file)
	decoder.CharsetReader = filereader.CharsetDecoder
	depth := 0
	for {
		lineStart, columnStart := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return models.FilePosition{}, fmt.Errorf("could not find the <parent> element of %s: %w", path, err)
		}

		switch element := token.(type) {
		case xml.StartElement:
			depth++
			if depth != 2 || element.Name.Local != "parent" {
				continue
			}
			if err := decoder.Skip(); err != nil {
				return models.FilePosition{}, fmt.Errorf("could not read the <parent> element of %s: %w", path, err)
			}
			lineEnd, columnEnd := decoder.InputPos()

			return models.FilePosition{
				Line:     models.Position{Start: lineStart, End: lineEnd},
				Column:   models.Position{Start: columnStart, End: columnEnd},
				Filename: path,
			}, nil
		case xml.EndElement:
			depth--
		}
	}
}

func pinCopy(pin extractor.PackageDetails, block models.FilePosition) extractor.PackageDetails {
	pin.BlockLocation = block
	pin.NameLocation = clonePosition(pin.NameLocation)
	pin.NamespaceLocation = clonePosition(pin.NamespaceLocation)
	pin.VersionLocation = clonePosition(pin.VersionLocation)

	return pin
}

// uniquePins keeps the first of identical pins: CycloneDX output dedupes their occurrences anyway, but the json
// format then lists a shared pin under the first pom only.
func uniquePins(pkgs []extractor.PackageDetails) []extractor.PackageDetails {
	seen := map[pinOccurrence]bool{}

	return slices.DeleteFunc(pkgs, func(pkg extractor.PackageDetails) bool {
		if !pkg.IsVersionConstraint {
			return false
		}
		occurrence := pinOccurrence{
			name:        pkg.Name,
			version:     pkg.Version,
			block:       pkg.BlockLocation,
			nameAt:      positionOf(pkg.NameLocation),
			namespaceAt: positionOf(pkg.NamespaceLocation),
			versionAt:   positionOf(pkg.VersionLocation),
		}
		if seen[occurrence] {
			return true
		}
		seen[occurrence] = true

		return false
	})
}

// resolvedVersions mirrors the backend lookup: the versions keyed at the nearest folder, from dir upward, that pins name.
func resolvedVersions(keys map[string]map[string]map[string]bool, dir string, name string) map[string]bool {
	for {
		if versions, ok := keys[dir][name]; ok {
			return versions
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

func isWithin(path string, dir string) bool {
	separator := string(filepath.Separator)

	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, separator)+separator)
}

func pinKeyOf(pin extractor.PackageDetails) pinKey {
	return pinKey{file: pin.BlockLocation.Filename, name: pin.Name}
}

func addToSet(sets map[string]map[string]bool, key string, value string) {
	if sets[key] == nil {
		sets[key] = map[string]bool{}
	}
	sets[key][value] = true
}

func addVersion(keys map[string]map[string]map[string]bool, dir string, name string, version string) {
	if keys[dir] == nil {
		keys[dir] = map[string]map[string]bool{}
	}
	addToSet(keys[dir], name, version)
}

func positionOf(position *models.FilePosition) models.FilePosition {
	if position == nil {
		return models.FilePosition{}
	}

	return *position
}

func clonePosition(position *models.FilePosition) *models.FilePosition {
	if position == nil {
		return nil
	}
	clone := *position

	return &clone
}

package java

import (
	"bytes"
	"cmp"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"maps"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/filereader"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

var errAPIFailed = errors.New("API query failed")

// SHORTCUT: process-wide and unbounded cache of pom downloads, failed ones included; scope it to a scan if a long-lived
// service embeds the library, as it would never retry a failure.
var remotePoms sync.Map

type remotePom struct {
	body []byte
	err  error
}

func NewMavenRegistryAPIClient(url string) (extractor.DepFile, error) {
	body, err := fetchRemotePom(url)
	if err != nil {
		return nil, err
	}

	return &MavenRegistryProject{
		ReadCloser: io.NopCloser(bytes.NewReader(body)),
		path:       url,
	}, nil
}

func (m *MavenRegistryProject) Open(_ string) (extractor.DepFile, error) {
	panic("Should not be called")
}

func (m *MavenRegistryProject) Path() string {
	return m.path
}

func buildProjectProperties(lockfile MavenLockFile) map[string]models.StringWithPosition {
	return map[string]models.StringWithPosition{
		"project.version":      lockfile.Version,
		"project.modelVersion": lockfile.ModelVersion,
		"project.groupId":      lockfile.GroupID,
		"project.artifactId":   lockfile.ArtifactID,
	}
}

/*
 * You can see the interpolationReg working here : https://regex101.com/r/inAPiN/2
 * You can see the isMixedReg working here : https://regex101.com/r/KG4tS6/1
 */
func (mld MavenLockDependency) resolvePropertiesValue(lockfile MavenLockFile, fieldToResolve string, context extractor.ScanContext) (string, models.FilePosition) {
	var position models.FilePosition
	variablesCount := 0

	interpolationReg := cachedregexp.MustCompile(`\${([^}]+)}`)
	isMixedReg := cachedregexp.MustCompile(`.+\${[^}]+}|\$[^}]+}.+`)
	projectProperties := buildProjectProperties(lockfile)
	isMixed := isMixedReg.MatchString(fieldToResolve)

	result := interpolationReg.ReplaceAllFunc([]byte(fieldToResolve), func(bytes []byte) []byte {
		variablesCount += 1
		propStr := string(bytes)
		propName := propStr[2 : len(propStr)-1]

		var lockProperty MavenLockProperty
		var property models.StringWithPosition
		var ok bool

		if strings.HasPrefix(propName, "pom.") {
			// the pom. prefix is the legacy Value of project. prefix even if it is deprecated, it is still supported
			propName = "project" + strings.TrimPrefix(propName, "pom")
		}

		// If the fieldToResolve is the internal version fieldToResolve, then lets use the one declared
		if strings.HasPrefix(propName, "project.") {
			property, ok = projectProperties[propName]
			// The property is located in the main source File...
			projectPropertySourceFile := lockfile.MainSourceFile
			// Except if it is the version -> It could be located in some parent File
			if strings.HasSuffix(propName, "version") {
				projectPropertySourceFile = lockfile.ProjectVersionSourceFile
			}
			position = property.FilePosition
			if position != (models.FilePosition{}) {
				position.Filename = projectPropertySourceFile
			}
		} else {
			lockProperty, ok = lockfile.Properties.m[propName]
			if ok {
				property = lockProperty.Property
				if interpolationReg.MatchString(property.Value) {
					// Property uses other properties
					var propertyStr string
					propertyStr, position = mld.resolvePropertiesValue(lockfile, property.Value, context)
					property = models.StringWithPosition{
						Value: propertyStr,
					}
					if position != (models.FilePosition{}) {
						property.FilePosition = position
					}
				} else {
					position = lockProperty.Property.FilePosition
					if position != (models.FilePosition{}) {
						position.Filename = lockProperty.SourceFile
					}
				}
			}
		}

		if !ok {
			context.Reporter.Warnf(
				"Failed to resolve a property. fieldToResolve \"%s\" could not be found for \"%s\" (%s)\n",
				string(bytes),
				lockfile.GroupID.Value+":"+lockfile.ArtifactID.Value,
				mld.SourceFile,
			)

			return []byte("")
		}

		return []byte(property.Value)
	})

	if variablesCount > 1 || isMixed {
		position = models.FilePosition{}
	}

	return string(result), position
}

func (mld MavenLockDependency) ResolveVersion(lockfile MavenLockFile, context extractor.ScanContext) (string, models.FilePosition) {
	return requirementVersion(mld.resolvePropertiesValue(lockfile, mld.Version.Value, context))
}

// requirementVersion returns the version a requirement such as `1.0`, `[1.0]` or `[1.0,2.0)` starts with.
func requirementVersion(requirement string, position models.FilePosition) (string, models.FilePosition) {
	versionRequirementReg := cachedregexp.MustCompile(`[[(]?(.*?)(?:,|[)\]]|$)`)
	results := versionRequirementReg.FindStringSubmatch(requirement)

	if results == nil || results[1] == "" {
		return "", models.FilePosition{}
	}

	return results[1], position
}

// isVersionPlaceholder reports whether version is LATEST or RELEASE, which Maven resolves from repository metadata.
func isVersionPlaceholder(version string) bool {
	return version == "LATEST" || version == "RELEASE"
}

func (mld MavenLockDependency) ResolveArtifactID(lockfile MavenLockFile, context extractor.ScanContext) (string, models.FilePosition) {
	return mld.resolvePropertiesValue(lockfile, mld.ArtifactID.Value, context)
}

func (mld MavenLockDependency) ResolveGroupID(lockfile MavenLockFile, context extractor.ScanContext) (string, models.FilePosition) {
	return mld.resolvePropertiesValue(lockfile, mld.GroupID.Value, context)
}

// mavenCoordinates is a dependency entry resolved against its lockfile, with the locations of each part.
type mavenCoordinates struct {
	groupID          string
	artifactID       string
	version          string
	isDynamicVersion bool
	block            models.FilePosition
	namespaceAt      *models.FilePosition
	nameAt           models.FilePosition
	versionAt        models.FilePosition
}

func (c mavenCoordinates) name() string {
	return c.groupID + ":" + c.artifactID
}

func (c mavenCoordinates) isExact() bool {
	return c.groupID != "" && c.artifactID != "" && c.version != "" && !c.isDynamicVersion
}

func (mld MavenLockDependency) resolveCoordinates(lockfile MavenLockFile, context extractor.ScanContext) mavenCoordinates {
	groupID, groupIDPosition := mld.ResolveGroupID(lockfile, context)
	artifactID, artifactPosition := mld.ResolveArtifactID(lockfile, context)
	requirement, requirementPosition := mld.resolvePropertiesValue(lockfile, mld.Version.Value, context)
	version, versionPosition := requirementVersion(requirement, requirementPosition)

	// A position is null after resolving the Value in case the Value is directly defined in the block
	if artifactPosition == (models.FilePosition{}) {
		artifactPosition = mld.ArtifactID.FilePosition
		artifactPosition.Filename = mld.SourceFile
	}
	if versionPosition == (models.FilePosition{}) {
		versionPosition = mld.Version.FilePosition
		versionPosition.Filename = mld.SourceFile
	}
	if groupIDPosition == (models.FilePosition{}) {
		groupIDPosition = mld.GroupID.FilePosition
		groupIDPosition.Filename = mld.SourceFile
	}

	coordinates := mavenCoordinates{
		groupID:          groupID,
		artifactID:       artifactID,
		version:          version,
		isDynamicVersion: strings.Contains(requirement, ",") || isVersionPlaceholder(requirement),
		block:            models.FilePosition{Line: mld.Line, Column: mld.Column, Filename: mld.SourceFile},
		nameAt:           artifactPosition,
		versionAt:        versionPosition,
	}

	// Skip namespace location when groupId is inherited via ${project.*} or ${pom.*}
	// property: the resolved position carries the parent POM's line/column mapped onto
	// the child file, which would point to the wrong text. ${pom.*} is a deprecated
	// alias for ${project.*} and behaves identically.
	if !strings.HasPrefix(mld.GroupID.Value, "${project.") && !strings.HasPrefix(mld.GroupID.Value, "${pom.") {
		coordinates.namespaceAt = &groupIDPosition
	}

	return coordinates
}

func (p *MavenLockProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.m = map[string]MavenLockProperty{}

	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch tt := t.(type) {
		case xml.StartElement:
			var s models.StringWithPosition

			if err := d.DecodeElement(&s, &tt); err != nil {
				return fmt.Errorf("%w", err)
			}

			p.m[tt.Name.Local] = MavenLockProperty{
				Property: s,
			}

		case xml.EndElement:
			if tt.Name == start.Name {
				return nil
			}
		}
	}
}

func (dependencyHolder *MavenLockDependencyHolder) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	dependencyHolder.Dependencies = make([]MavenLockDependency, 0)
DecodingLoop:
	for {
		lineStart, columnStart := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch elem := token.(type) {
		case xml.StartElement:
			dependency := MavenLockDependency{}
			dependency.SetLineStart(lineStart)
			dependency.SetColumnStart(columnStart)
			err := decoder.DecodeElement(&dependency, &elem)
			if err != nil {
				return err
			}
			lineEnd, columnEnd := decoder.InputPos()
			dependency.SetLineEnd(lineEnd)
			dependency.SetColumnEnd(columnEnd)
			dependencyHolder.Dependencies = append(dependencyHolder.Dependencies, dependency)
		case xml.EndElement:
			if elem.Name == start.Name {
				break DecodingLoop
			}
		}
	}

	return nil
}

func (e MavenLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.MavenFilePath.String()
}

func (e MavenLockExtractor) IsOfficiallySupported() bool {
	return mavenOfficiallySupported
}

func (e MavenLockExtractor) PackageManager() models.PackageManager {
	return mavenPackageManager
}

/**
** This function merge a child lockfile into the parent one.
** It copies all information originating from the child in it, overriding any common properties/dependencies
**/
func (e MavenLockExtractor) mergeLockfiles(childLockfile *MavenLockFile, parentLockfile *MavenLockFile) *MavenLockFile {
	// We set the parent back to the definition inherited from the child
	// As the child have no restriction on putting valid information outside of the relative path, we keep the artifact / group id set by the parent
	parentLockfile.Parent = MavenLockParent{
		XMLName:      childLockfile.Parent.XMLName,
		RelativePath: childLockfile.Parent.RelativePath,
		GroupID:      parentLockfile.GroupID.Value,
		ArtifactID:   parentLockfile.ArtifactID.Value,
		Version:      parentLockfile.Version.Value,
	}
	// The following fields are not mandatory, in case they are not defined in the child, the one from the parent should be kept
	if len(childLockfile.ArtifactID.Value) > 0 {
		parentLockfile.ArtifactID = childLockfile.ArtifactID
	}
	if len(childLockfile.GroupID.Value) > 0 {
		parentLockfile.GroupID = childLockfile.GroupID
	}
	if len(childLockfile.ModelVersion.Value) > 0 {
		parentLockfile.ModelVersion = childLockfile.ModelVersion
	}

	// If child lockfile overrides the project version, let's use it instead
	if len(childLockfile.Version.Value) > 0 {
		parentLockfile.Version = childLockfile.Version
		parentLockfile.ProjectVersionSourceFile = childLockfile.ProjectVersionSourceFile
	}

	// Keep track of the main source File
	parentLockfile.MainSourceFile = childLockfile.MainSourceFile

	// Child properties take precedence over parent defined ones
	for key, value := range childLockfile.Properties.m {
		parentLockfile.Properties.m[key] = value
	}
	// We add child dependency at the end, this way they will override the parent ones during transformation to a map
	parentLockfile.Dependencies.Dependencies = append(parentLockfile.Dependencies.Dependencies, childLockfile.Dependencies.Dependencies...)
	parentLockfile.ManagedDependencies.Dependencies = append(parentLockfile.ManagedDependencies.Dependencies, childLockfile.ManagedDependencies.Dependencies...)

	return parentLockfile
}

func (e MavenLockExtractor) enrichDependencies(path string, dependencies []MavenLockDependency) MavenLockDependencyHolder {
	result := make([]MavenLockDependency, len(dependencies))
	// We don't want to have location kept if it has been found outside the repository
	shouldEnrich := !strings.HasPrefix(path, "https")
	for index, dependency := range dependencies {
		if len(dependency.SourceFile) == 0 && shouldEnrich {
			dependency.SourceFile = path
		} else if !shouldEnrich {
			dependency.FilePosition = models.FilePosition{}
			dependency.Version.FilePosition = models.FilePosition{}
			dependency.ArtifactID.FilePosition = models.FilePosition{}
			dependency.GroupID.FilePosition = models.FilePosition{}
		}
		result[index] = dependency
	}

	return MavenLockDependencyHolder{Dependencies: result}
}

func (e MavenLockExtractor) enrichProperties(path string, properties map[string]MavenLockProperty) MavenLockProperties {
	shouldEnrich := !strings.HasPrefix(path, "https")
	for key, property := range properties {
		if len(property.SourceFile) == 0 && shouldEnrich {
			property.SourceFile = path
		} else if !shouldEnrich {
			property.Property.FilePosition = models.FilePosition{}
			property.SourceFile = ""
		}
		properties[key] = property
	}

	return MavenLockProperties{m: properties}
}

func (e MavenLockExtractor) resolveParentFilename(parent MavenLockParent, currentPath string, context extractor.ScanContext) string {
	buildRemoteURL := func() string {
		u, err := remotePomURL(parent.GroupID, parent.ArtifactID, parent.Version)
		if err != nil {
			context.Reporter.Warnf("Failed to construct remote path: %s\n", err)
			return ""
		}

		return u
	}

	// relativePath only makes sense against a local checkout. Once currentPath is itself a
	// remote pom (e.g. a parent fetched one level up from Maven Central), resolve the next
	// parent by its groupId/artifactId/version instead of joining relativePath onto the URL,
	// which filepath.Join would corrupt (it collapses "https://" into "https:/").
	if strings.HasPrefix(currentPath, "https") {
		return buildRemoteURL()
	}

	// If a parent is defined, use its relative path to find the File, then recurse to decode it properly and enrich its dependencies
	// If the relativePath is not defined, default to ../pom.xml
	parentRelativePath := parent.RelativePath
	if len(parentRelativePath) == 0 {
		parentRelativePath = "../" + models.MavenFilePath.String()

		localPath := filepath.Join(filepath.Dir(currentPath), parentRelativePath)
		if _, err := os.Stat(localPath); errors.Is(err, os.ErrNotExist) {
			return buildRemoteURL()
		}
	} else if !strings.HasSuffix(parentRelativePath, ".xml") {
		// It means we only have a path, we should append the default pom.xml
		parentRelativePath = path.Join(parentRelativePath, models.MavenFilePath.String())
	}

	return filepath.FromSlash(filepath.Join(filepath.Dir(currentPath), parentRelativePath))
}

func (e MavenLockExtractor) decodeMavenFile(f extractor.DepFile, depth int, visitedPath map[string]bool, context extractor.ScanContext) (*MavenLockFile, error) {
	var parsedLockfile *MavenLockFile

	// Decoding the original lockfile and enrich its dependencies
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	decoder := xml.NewDecoder(bytes.NewReader(b))
	decoder.CharsetReader = filereader.CharsetDecoder
	err = decoder.Decode(&parsedLockfile)
	if err != nil {
		return nil, err
	}

	parsedLockfile.MainSourceFile = f.Path()
	parsedLockfile.ProjectVersionSourceFile = f.Path()
	for i := range parsedLockfile.ManagedDependencies.Dependencies {
		parsedLockfile.ManagedDependencies.Dependencies[i].InheritanceDepth = depth
	}

	if parsedLockfile.Properties.m == nil {
		parsedLockfile.Properties.m = map[string]MavenLockProperty{}
	}
	parsedLockfile.Properties = e.enrichProperties(f.Path(), parsedLockfile.Properties.m)
	parsedLockfile.Dependencies = e.enrichDependencies(f.Path(), parsedLockfile.Dependencies.Dependencies)
	parsedLockfile.ManagedDependencies = e.enrichDependencies(f.Path(), parsedLockfile.ManagedDependencies.Dependencies)
	if parsedLockfile.Parent == (MavenLockParent{}) {
		return parsedLockfile, nil
	}

	parentPath := e.resolveParentFilename(parsedLockfile.Parent, f.Path(), context)

	if ok := visitedPath[parentPath]; ok || parentPath == "" {
		// Parent has already been visited or is empty, lets stop there
		context.Reporter.Verbosef("Already visited parent path, stopping there to avoid a circular dependency %s\n", parentPath)
		return parsedLockfile, nil
	}

	visitedPath[parentPath] = true

	var parentLockfile *MavenLockFile
	var parentFilePath string
	var parentErr error

	// If the parent pom does not exist, it still can be in an external repository
	if strings.HasPrefix(parentPath, "https") {
		mavenRegistryClient, clientErr := openRemotePom(parentPath, context)
		// If the remote pom does not exist, we can't do anything.
		if clientErr != nil {
			context.Reporter.Warnf("Failed to fetch parent pom from remote repository: %s\n", parentPath)
			//nolint:nilerr // we don't want to consider a network request failing for the parent as being unable to handle the lockfile
			return parsedLockfile, nil
		}

		parentLockfile, err = e.decodeMavenFile(mavenRegistryClient, depth+1, visitedPath, context)
		if err != nil {
			return nil, err
		}

		parentFilePath = parentPath
		if context.MavenExpandBOMs && !strings.HasPrefix(f.Path(), "https") {
			block, blockErr := parentElementPosition(f.Path())
			if blockErr != nil {
				context.Reporter.Warnf("Failed to locate the parent of %s: %v\n", f.Path(), blockErr)
			}
			parentLockfile.RemoteParentBlock = block
		}
	} else if _, err = os.Stat(parentPath); errors.Is(err, os.ErrNotExist) {
		// If the parent pom does not exist and is not a remote file, we can't do anything.
		context.Reporter.Warnf("Maven lockfile parser couldn't reach the parent because it is not locally defined: %s\n", parentPath)

		return parsedLockfile, nil
	} else {
		parentFile, err := extractor.OpenLocalDepFile(parentPath)
		if err != nil {
			return nil, err
		}
		parentLockfile, parentErr = e.decodeMavenFile(parentFile, depth+1, visitedPath, context)
		if parentErr != nil {
			return nil, parentErr
		}

		parentFilePath = parentFile.Path()
	}

	parentLockfile.Properties = e.enrichProperties(f.Path(), parentLockfile.Properties.m)
	parentLockfile.Dependencies = e.enrichDependencies(parentFilePath, parentLockfile.Dependencies.Dependencies)
	parentLockfile.ManagedDependencies = e.enrichDependencies(parentFilePath, parentLockfile.ManagedDependencies.Dependencies)

	// Once everything is decoded and enriched, merge them together
	return e.mergeLockfiles(parsedLockfile, parentLockfile), nil
}

func (e MavenLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	visitedPath := make(map[string]bool)
	visitedPath[f.Path()] = true
	parsedLockfile, err := e.decodeMavenFile(f, 0, visitedPath, context)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	details := map[string]extractor.PackageDetails{}

	for _, lockPackage := range parsedLockfile.Dependencies.Dependencies {
		coordinates := lockPackage.resolveCoordinates(*parsedLockfile, context)
		finalName := coordinates.name()

		var exclusions []string
		if len(lockPackage.Exclusions) > 0 {
			exclusions = make([]string, 0, len(lockPackage.Exclusions))
			for _, exclusion := range lockPackage.Exclusions {
				exclusions = append(exclusions, exclusion.GroupID.Value+":"+exclusion.ArtifactID.Value)
			}
		}

		pkgDetails := extractor.PackageDetails{
			Name:              finalName,
			Version:           coordinates.version,
			Ecosystem:         models.EcosystemMaven,
			BlockLocation:     coordinates.block,
			LocationRole:      models.LocationRoleManifest,
			NameLocation:      &coordinates.nameAt,
			NamespaceLocation: coordinates.namespaceAt,
			VersionLocation:   &coordinates.versionAt,
			PackageManager:    mavenPackageManager,
			IsDirect:          true,
			Exclusions:        exclusions,
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, strings.ToLower(scope))
		}
		details[finalName] = pkgDetails
	}

	// Managed dependencies are merged parent-first (see mergeLockfiles), so the last resolvable entry for a name is
	// the closest one: it sets the version of a dependency declared without one, and it is the pin emitted.
	needsManagedVersion := map[string]bool{}
	for name, pkgDetails := range details {
		needsManagedVersion[name] = pkgDetails.IsVersionEmpty()
	}

	constraints := map[string]extractor.PackageDetails{}
	explicitlyManaged := map[string]bool{}
	for _, lockPackage := range parsedLockfile.ManagedDependencies.Dependencies {
		if isImport(lockPackage) {
			continue
		}

		coordinates := lockPackage.resolveCoordinates(*parsedLockfile, context)
		finalName := coordinates.name()
		explicitlyManaged[finalName] = true
		if pin, ok := versionConstraintPackage(coordinates, parsedLockfile.RemoteParentBlock); ok {
			constraints[finalName] = pin
		} else if coordinates.isDynamicVersion {
			// A dynamic version overrides the inherited pins without being one itself.
			delete(constraints, finalName)
		}

		pkgDetails, pkgExists := details[finalName]
		if !pkgExists {
			continue
		}
		if needsManagedVersion[finalName] && coordinates.version != "" && !isVersionPlaceholder(coordinates.version) {
			pkgDetails.Version = coordinates.version
			pkgDetails.VersionLocation = &coordinates.versionAt
		}
		if scope := strings.TrimSpace(lockPackage.Scope); scope != "" && scope != "compile" {
			// Only append non-default scope (compile is the default scope).
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, scope)
		}
		details[finalName] = pkgDetails
	}

	// Imported BOMs also set the version of a dependency declared without one, but an entry declared in a
	// dependencyManagement section wins over all of them.
	for name, pin := range e.importedPins(*parsedLockfile, context) {
		if explicitlyManaged[name] {
			continue
		}
		constraints[name] = pin

		if pkgDetails, ok := details[name]; ok && pkgDetails.IsVersionEmpty() {
			pkgDetails.Version = pin.Version
			pkgDetails.VersionLocation = clonePosition(pin.VersionLocation)
			details[name] = pkgDetails
		}
	}

	return append(slices.Collect(maps.Values(details)), slices.Collect(maps.Values(constraints))...), nil
}

func (e MavenLockExtractor) GetArtifact(f extractor.DepFile, context extractor.ScanContext) (*models.ScannedArtifact, error) {
	visitedPath := make(map[string]bool)
	visitedPath[f.Path()] = true
	parsedLockfile, err := e.decodeMavenFile(f, 0, visitedPath, context)
	if err != nil {
		return nil, err
	}

	artifactName := parsedLockfile.GroupID.Value + ":" + parsedLockfile.ArtifactID.Value

	artifact := models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      artifactName,
			Version:   parsedLockfile.Version.Value,
			Filename:  f.Path(),
			Ecosystem: models.EcosystemMaven,
		},
	}

	if parsedLockfile.Parent != (MavenLockParent{}) {
		parentArtifact := parsedLockfile.Parent.GroupID + ":" + parsedLockfile.Parent.ArtifactID
		artifact.DependsOn = &models.ArtifactDetail{
			Name:      parentArtifact,
			Version:   parsedLockfile.Parent.Version,
			Filename:  e.resolveParentFilename(parsedLockfile.Parent, f.Path(), context),
			Ecosystem: models.EcosystemMaven,
		}
	}

	return &artifact, nil
}

var _ extractor.Extractor = MavenLockExtractor{}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.MavenFilePath, MavenLockExtractor{})
}

func ParseMavenLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, MavenLockExtractor{})
}

// versionConstraintPackage returns the pin of a managed entry whose coordinates fully resolve to an exact version. A remote
// parent's entry is pinned at the repository property that sets its version, or else at the <parent> element.
func versionConstraintPackage(coordinates mavenCoordinates, remoteParentBlock models.FilePosition) (extractor.PackageDetails, bool) {
	if !coordinates.isExact() {
		return extractor.PackageDetails{}, false
	}

	block, nameAt, namespaceAt, versionAt := coordinates.block, &coordinates.nameAt, coordinates.namespaceAt, &coordinates.versionAt
	if !block.IsStartSet() {
		block, nameAt, namespaceAt = coordinates.versionAt, nil, nil
	}
	// A version set in a downloaded pom, such as an inherited ${project.version}, is not located in the repository.
	if !block.IsStartSet() || strings.HasPrefix(block.Filename, "https") {
		block, versionAt = remoteParentBlock, nil
	}
	if !block.IsStartSet() {
		return extractor.PackageDetails{}, false
	}

	return extractor.PackageDetails{
		Name:                coordinates.name(),
		Version:             coordinates.version,
		Ecosystem:           models.EcosystemMaven,
		BlockLocation:       block,
		LocationRole:        models.LocationRoleManifest,
		NameLocation:        nameAt,
		NamespaceLocation:   namespaceAt,
		VersionLocation:     versionAt,
		PackageManager:      mavenPackageManager,
		IsVersionConstraint: true,
	}, true
}

// importedPins returns a pin for every version the BOMs imported by lockfile manage, located where versionConstraintPackage
// locates each import. The first BOM managing a package wins.
func (e MavenLockExtractor) importedPins(lockfile MavenLockFile, context extractor.ScanContext) map[string]extractor.PackageDetails {
	if !context.MavenExpandBOMs {
		return nil
	}

	pins := map[string]extractor.PackageDetails{}
	for _, bom := range orderedImports(lockfile, context) {
		anchor, ok := versionConstraintPackage(bom, lockfile.RemoteParentBlock)
		if !ok {
			continue
		}

		for name, version := range e.bomVersions(bom, map[string]bool{}, context) {
			if _, ok := pins[name]; ok {
				continue
			}
			pin := anchor
			pin.Name, pin.Version = name, version
			pin.NameLocation, pin.NamespaceLocation, pin.VersionLocation = nil, nil, clonePosition(anchor.VersionLocation)
			pins[name] = pin
		}
	}

	return pins
}

// bomVersions returns the versions a BOM manages, resolved in its own context: its own entries win over the BOMs it
// imports, and an earlier import wins over a later one.
func (e MavenLockExtractor) bomVersions(bom mavenCoordinates, visited map[string]bool, context extractor.ScanContext) map[string]string {
	pomURL, err := remotePomURL(bom.groupID, bom.artifactID, bom.version)
	if err != nil || visited[pomURL] {
		return nil
	}
	visited[pomURL] = true
	lockfile, ok := e.fetchBOM(pomURL, context)
	if !ok {
		return nil
	}

	versions := map[string]string{}
	for _, managed := range lockfile.ManagedDependencies.Dependencies {
		if isImport(managed) {
			continue
		}
		if coordinates := managed.resolveCoordinates(*lockfile, context); coordinates.isExact() {
			versions[coordinates.name()] = coordinates.version
		}
	}
	for _, imported := range orderedImports(*lockfile, context) {
		for name, version := range e.bomVersions(imported, visited, context) {
			if _, ok := versions[name]; !ok {
				versions[name] = version
			}
		}
	}

	return versions
}

// orderedImports resolves the BOMs a merged lockfile imports in the order Maven reads them: the closest pom's first, each
// pom's in declaration order. Only the closest import of a BOM counts, as Maven's inheritance replaces the farther ones.
func orderedImports(lockfile MavenLockFile, context extractor.ScanContext) []mavenCoordinates {
	var imports []MavenLockDependency
	for _, managed := range lockfile.ManagedDependencies.Dependencies {
		if isImport(managed) {
			imports = append(imports, managed)
		}
	}
	slices.SortStableFunc(imports, func(a, b MavenLockDependency) int {
		return cmp.Compare(a.InheritanceDepth, b.InheritanceDepth)
	})

	boms := make([]mavenCoordinates, 0, len(imports))
	seen := map[string]bool{}
	for _, imported := range imports {
		bom := imported.resolveCoordinates(lockfile, context)
		if seen[bom.name()] {
			continue
		}
		seen[bom.name()] = true
		boms = append(boms, bom)
	}

	return boms
}

func (e MavenLockExtractor) fetchBOM(pomURL string, context extractor.ScanContext) (*MavenLockFile, bool) {
	file, err := openRemotePom(pomURL, context)
	if err != nil {
		context.Reporter.Warnf("Failed to fetch imported BOM from remote repository: %s: %v\n", pomURL, err)
		return nil, false
	}
	lockfile, err := e.decodeMavenFile(file, 0, map[string]bool{pomURL: true}, context)
	if err != nil {
		context.Reporter.Warnf("Failed to decode imported BOM %s: %v\n", pomURL, err)
		return nil, false
	}

	return lockfile, true
}

func isImport(dependency MavenLockDependency) bool {
	return strings.EqualFold(strings.TrimSpace(dependency.Scope), "import")
}

func remotePomURL(groupID string, artifactID string, version string) (string, error) {
	return url.JoinPath(MavenCentral, strings.ReplaceAll(groupID, ".", "/"), artifactID, version, fmt.Sprintf("%s-%s.pom", artifactID, version))
}

// openRemotePom downloads a pom from Maven central, once per process when BOM expansion is on.
func openRemotePom(url string, context extractor.ScanContext) (extractor.DepFile, error) {
	if !context.MavenExpandBOMs {
		return NewMavenRegistryAPIClient(url)
	}

	cached, ok := remotePoms.Load(url)
	if !ok {
		body, err := fetchRemotePom(url)
		cached, _ = remotePoms.LoadOrStore(url, remotePom{body: body, err: err})
	}
	pom := cached.(remotePom)
	if pom.err != nil {
		return nil, pom.err
	}

	return &MavenRegistryProject{
		ReadCloser: io.NopCloser(bytes.NewReader(pom.body)),
		path:       url,
	}, nil
}

func fetchRemotePom(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to make new request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: Maven registry query failed: %w", errAPIFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: Maven registry query status: %s", errAPIFailed, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response body: %w", errAPIFailed, err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty response body", errAPIFailed)
	}

	return body, nil
}

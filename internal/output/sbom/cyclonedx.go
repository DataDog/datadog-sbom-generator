package sbom

import (
	"slices"
	"strings"
	"time"

	"github.com/datadog/datadog-sbom-generator/internal/utility/purl"

	"golang.org/x/exp/maps"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/datadog/datadog-sbom-generator/pkg/models"
)

type PackageProcessingHook = func(component *cyclonedx.Component, details models.PackageVulns)

func BuildCycloneDXBom(uniquePackages map[string]models.PackageVulns, artifacts []models.ScannedArtifact) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	bom.JSONSchema = cycloneDx15Schema
	bom.SpecVersion = cyclonedx.SpecVersion1_5

	components := make([]cyclonedx.Component, 0)
	bomVulnerabilities := make([]cyclonedx.Vulnerability, 0)
	vulnerabilities := make(map[string]cyclonedx.Vulnerability)
	uniqueAdvisoryIdsAndUniquePurls := make(map[string]map[string]struct{})

	fileComponents, dependsOn := addFileDependencies(artifacts)
	for packageURL, packageDetail := range uniquePackages {
		libraryComponent := createLibraryComponent(packageURL, packageDetail)
		artifact := findArtifact(packageDetail.Package.Name, packageDetail.Package.Version, artifacts)
		createFileComponents(packageDetail, artifact, dependsOn)

		addLocations(&libraryComponent, packageDetail)
		addVulnerabilities(vulnerabilities, packageDetail)
		addToUniqueAdvisoryAndPurls(uniqueAdvisoryIdsAndUniquePurls, packageDetail)

		components = append(components, libraryComponent)
	}
	components = append(components, maps.Values(fileComponents)...)
	slices.SortFunc(components, func(a, b cyclonedx.Component) int {
		return strings.Compare(a.BOMRef, b.BOMRef)
	})

	combineReachableVulnerability(vulnerabilities, uniqueAdvisoryIdsAndUniquePurls)

	for _, vulnerability := range vulnerabilities {
		bomVulnerabilities = append(bomVulnerabilities, vulnerability)
	}

	slices.SortFunc(bomVulnerabilities, func(a, b cyclonedx.Vulnerability) int {
		return strings.Compare(a.ID, b.ID)
	})

	dependencies := maps.Values(dependsOn)
	slices.SortFunc(dependencies, func(a, b cyclonedx.Dependency) int {
		return strings.Compare(a.Ref, b.Ref)
	})

	bom.Components = &components
	bom.Dependencies = &dependencies
	bom.Vulnerabilities = &bomVulnerabilities

	return bom
}

func addLocations(component *cyclonedx.Component, details models.PackageVulns) {
	occurrences := make([]cyclonedx.EvidenceOccurrence, 0)

	for _, packageLocations := range details.Locations {
		cleanedLocation := packageLocations.Clean()

		if cleanedLocation == nil {
			continue
		}
		jsonLocation, err := packageLocations.MarshalToJSONString()

		if err != nil {
			continue
		}
		occurrence := cyclonedx.EvidenceOccurrence{
			Location: jsonLocation,
		}
		occurrences = append(occurrences, occurrence)
	}
	if len(occurrences) > 0 {
		component.Evidence = &cyclonedx.Evidence{Occurrences: &occurrences}
	}
}

func buildProperties(metadatas models.PackageMetadata) []cyclonedx.Property {
	properties := make([]cyclonedx.Property, 0)

	for metadataType, value := range metadatas {
		if len(value) == 0 {
			continue
		}
		// TODO(daniel.strong) Remove this conditional when we support datadog-sbom-generator prefixes in all metadata keys.
		if strings.HasPrefix(string(metadataType), string(models.ReachableSymbolLocationMetadata)) {
			properties = append(properties, cyclonedx.Property{
				Name:  "datadog-sbom-generator:" + string(metadataType),
				Value: value,
			})
		} else {
			properties = append(properties, cyclonedx.Property{
				Name:  "osv-scanner:" + string(metadataType),
				Value: value,
			})
		}
	}

	slices.SortFunc(properties, func(a, b cyclonedx.Property) int {
		return strings.Compare(a.Name, b.Name)
	})

	return properties
}

func findArtifact(name string, version string, artifacts []models.ScannedArtifact) *models.ScannedArtifact {
	for _, artifact := range artifacts {
		if artifact.Name == name && artifact.Version == version {
			return &artifact
		}
	}

	return nil
}

func createFileComponents(packageDetail models.PackageVulns, artifact *models.ScannedArtifact, dependsOn map[string]cyclonedx.Dependency) {
	for _, location := range packageDetail.Locations {
		if artifact != nil {
			// The current component is a repository artifact, meaning it is an internal dependency, we should report a dependsOn on the location
			if dependency, ok := dependsOn[location.Block.Filename]; !ok {
				dependencies := make([]string, 1)
				dependencies[0] = artifact.Filename
				dependsOn[location.Block.Filename] = cyclonedx.Dependency{
					Ref:          location.Block.Filename,
					Dependencies: &dependencies,
				}
			} else {
				dependencies := append(*dependency.Dependencies, artifact.Filename)
				slices.Sort(dependencies)
				dependency.Dependencies = &dependencies
				dependsOn[location.Block.Filename] = dependency
			}
		}
	}
}

func createLibraryComponent(packageURL string, packageDetail models.PackageVulns) cyclonedx.Component {
	component := cyclonedx.Component{}

	component.Type = libraryComponentType
	component.BOMRef = packageURL
	component.PackageURL = packageURL
	component.Name = packageDetail.Package.Name
	component.Version = packageDetail.Package.Version

	properties := buildProperties(packageDetail.Metadata)
	component.Properties = &properties

	return component
}

func addVulnerabilities(vulnerabilities map[string]cyclonedx.Vulnerability, packageDetail models.PackageVulns) {
	for _, vulnerability := range packageDetail.Vulnerabilities {
		if _, exists := vulnerabilities[vulnerability.ID]; exists {
			continue
		}

		// It doesn't exists yet, lets add it
		vulnerabilities[vulnerability.ID] = cyclonedx.Vulnerability{
			ID:          vulnerability.ID,
			Updated:     formatDateIfExists(vulnerability.Modified),
			Published:   formatDateIfExists(vulnerability.Published),
			Rejected:    formatDateIfExists(vulnerability.Withdrawn),
			References:  buildReferences(vulnerability),
			Description: vulnerability.Summary,
			Detail:      vulnerability.Details,
			Affects:     buildAffectedPackages(vulnerability),
			Ratings:     buildRatings(vulnerability),
			Advisories:  buildAdvisories(vulnerability),
			Credits:     buildCredits(vulnerability),
		}
	}
}

// addToUniqueAdvisoryAndPurls is used to continuously add unique advisory IDs and their affected PURLs
func addToUniqueAdvisoryAndPurls(uniqueAdvisoryIdsAndUniquePurls map[string]map[string]struct{}, packageDetail models.PackageVulns) {
	for _, advisoryID := range packageDetail.AdvisoriesForReachability {
		if _, ok := uniqueAdvisoryIdsAndUniquePurls[advisoryID]; !ok {
			uniqueAdvisoryIdsAndUniquePurls[advisoryID] = make(map[string]struct{})
		}

		if _, exists := packageDetail.Metadata[models.ReachableSymbolLocationMetadata.WithValue(advisoryID)]; exists {
			uniqueAdvisoryIdsAndUniquePurls[advisoryID][packageDetail.Package.Purl] = struct{}{}
		}
	}
}

// combineReachableVulnerability converts a map of unique advisory IDs and their affected PURLs into a map of vulnerabilities
func combineReachableVulnerability(vulnerabilities map[string]cyclonedx.Vulnerability, uniqueAdvisoriesToPurls map[string]map[string]struct{}) {
	for advisoryID, purlsMap := range uniqueAdvisoriesToPurls {
		if len(purlsMap) == 0 {
			vulnerabilities[advisoryID] = cyclonedx.Vulnerability{
				ID:     advisoryID,
				BOMRef: advisoryID,
			}

			continue
		}

		affects := make([]cyclonedx.Affects, 0, len(purlsMap))
		for uniquePurl := range purlsMap {
			affects = append(affects, cyclonedx.Affects{
				Ref: uniquePurl,
			})
		}

		vulnerabilities[advisoryID] = cyclonedx.Vulnerability{
			ID:      advisoryID,
			BOMRef:  advisoryID,
			Affects: &affects,
		}
	}
}

func addFileDependencies(artifacts []models.ScannedArtifact) (map[string]cyclonedx.Component, map[string]cyclonedx.Dependency) {
	components := make(map[string]cyclonedx.Component)
	dependsOn := make(map[string]cyclonedx.Dependency)

	for _, artifact := range artifacts {
		artifactPURL, err := purl.From(models.PackageInfo{
			Name:      artifact.Name,
			Version:   artifact.Version,
			Ecosystem: string(artifact.Ecosystem),
		})
		if err != nil {
			continue
		}

		component := cyclonedx.Component{}
		properties := make([]cyclonedx.Property, 1)
		component.Name = artifact.Filename
		component.BOMRef = artifact.Filename
		component.Type = fileComponentType
		properties[0] = cyclonedx.Property{
			Name:  "osv-scanner:package",
			Value: artifactPURL.String(),
		}
		component.Properties = &properties
		components[component.BOMRef] = component

		// Computing parent dependency
		if artifact.DependsOn != nil {
			if dependency, ok := dependsOn[artifact.Filename]; ok {
				dependencies := append(*dependency.Dependencies, artifact.DependsOn.Filename)
				slices.Sort(dependencies)

				dependency.Dependencies = &dependencies
				dependsOn[artifact.Filename] = dependency
			} else {
				dependsOn[artifact.Filename] = cyclonedx.Dependency{
					Ref: component.BOMRef,
					Dependencies: &[]string{
						artifact.DependsOn.Filename,
					},
				}
			}
		}
	}

	return components, dependsOn
}

func formatDateIfExists(date time.Time) string {
	if date.IsZero() {
		return ""
	}

	return date.Format(time.RFC3339)
}

func buildCredits(vulnerability models.Vulnerability) *cyclonedx.Credits {
	organizations := make([]cyclonedx.OrganizationalEntity, len(vulnerability.Credits))

	for index, credit := range vulnerability.Credits {
		organizations[index] = cyclonedx.OrganizationalEntity{
			Name: credit.Name,
			URL:  &vulnerability.Credits[index].Contact,
		}
	}

	return &cyclonedx.Credits{
		Organizations: &organizations,
	}
}

func buildAffectedPackages(vulnerability models.Vulnerability) *[]cyclonedx.Affects {
	affectedPackages := make([]cyclonedx.Affects, len(vulnerability.Affected))

	for index, affected := range vulnerability.Affected {
		affectedPackages[index] = cyclonedx.Affects{
			Ref: affected.Package.Purl,
		}
	}

	return &affectedPackages
}

func buildRatings(vulnerability models.Vulnerability) *[]cyclonedx.VulnerabilityRating {
	ratings := make([]cyclonedx.VulnerabilityRating, len(vulnerability.Severity))
	for index, severity := range vulnerability.Severity {
		ratings[index] = cyclonedx.VulnerabilityRating{
			Method: SeverityMapper[severity.Type],
			Vector: severity.Score,
		}
	}

	return &ratings
}

func buildReferences(vulnerability models.Vulnerability) *[]cyclonedx.VulnerabilityReference {
	references := make([]cyclonedx.VulnerabilityReference, len(vulnerability.Aliases))

	for index, alias := range vulnerability.Aliases {
		references[index] = cyclonedx.VulnerabilityReference{
			ID:     alias,
			Source: &cyclonedx.Source{},
		}
	}

	return &references
}

func buildAdvisories(vulnerability models.Vulnerability) *[]cyclonedx.Advisory {
	advisories := make([]cyclonedx.Advisory, 0)
	for _, reference := range vulnerability.References {
		if reference.Type != models.ReferenceAdvisory {
			continue
		}
		advisories = append(advisories, cyclonedx.Advisory{
			URL: reference.URL,
		})
	}

	return &advisories
}

package location

import (
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func NewPackageLocations(block models.FilePosition, name *models.FilePosition, version *models.FilePosition, role string) models.PackageLocations {
	result := models.PackageLocations{
		Block: models.PackageLocation{
			Filename:    block.Filename,
			LineStart:   block.Line.Start,
			LineEnd:     block.Line.End,
			ColumnStart: block.Column.Start,
			ColumnEnd:   block.Column.End,
			Role:        role,
		},
	}

	if name != nil && fileposition.IsFilePositionExtractedSuccessfully(*name) {
		result.Name = &models.PackageLocation{
			Filename:    name.Filename,
			LineStart:   name.Line.Start,
			LineEnd:     name.Line.End,
			ColumnStart: name.Column.Start,
			ColumnEnd:   name.Column.End,
			Role:        role,
		}
	}
	if version != nil && fileposition.IsFilePositionExtractedSuccessfully(*version) {
		result.Version = &models.PackageLocation{
			Filename:    version.Filename,
			LineStart:   version.Line.Start,
			LineEnd:     version.Line.End,
			ColumnStart: version.Column.Start,
			ColumnEnd:   version.Column.End,
			Role:        role,
		}
	}

	return result
}

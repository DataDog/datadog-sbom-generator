package fileposition

import "github.com/datadog/datadog-sbom-generator/pkg/models"

func IsFilePositionExtractedSuccessfully(filePosition models.FilePosition) bool {
	return filePosition.Line.Start > 0 && filePosition.Line.End > 0 && filePosition.Column.Start > 0 && filePosition.Column.End > 0 && filePosition.Filename != ""
}

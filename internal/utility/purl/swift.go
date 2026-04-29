package purl

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func FromSwift(packageInfo models.PackageInfo) (namespace string, name string, err error) {
	nameParts := strings.Split(packageInfo.Name, "/")
	if len(nameParts) < 2 || len(packageInfo.Name) == 0 {
		err = fmt.Errorf("invalid swift package_name (%s)", packageInfo.Name)

		return
	}

	namespace = strings.Join(nameParts[:len(nameParts)-1], "/")
	name = strings.TrimSuffix(nameParts[len(nameParts)-1], ".git")

	return
}

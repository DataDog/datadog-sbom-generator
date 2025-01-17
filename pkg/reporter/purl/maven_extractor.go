package purl

import (
	"log"
	"strings"

	"github.com/datadog/datadog-sbom-generator/pkg/models"
)

func ExtractPURLFromMaven(packageInfo models.PackageInfo) (namespace string, name string, ok bool) {
	nameParts := strings.Split(packageInfo.Name, ":")
	if len(nameParts) != 2 {
		log.Printf("invalid maven package_name=%s", packageInfo.Name)
		return
	}
	ok = true
	namespace = nameParts[0]
	name = nameParts[1]

	return
}

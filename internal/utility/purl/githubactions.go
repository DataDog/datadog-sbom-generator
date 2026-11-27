package purl

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// FromGitHubActions splits an "owner/repo" action name into the purl namespace (owner) and name (repo).
func FromGitHubActions(packageInfo models.PackageInfo) (namespace string, name string, err error) {
	nameParts := strings.Split(packageInfo.Name, "/")
	if len(nameParts) != 2 || nameParts[0] == "" || nameParts[1] == "" {
		err = fmt.Errorf("invalid github action name (%s)", packageInfo.Name)

		return
	}
	namespace = nameParts[0]
	name = nameParts[1]

	return
}

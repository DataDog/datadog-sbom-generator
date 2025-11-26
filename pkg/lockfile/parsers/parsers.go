package parsers

// Package "parsers" imports all lockfile parser subpackages to ensure their init() functions
// are called and extractors are registered.
//
// Import this package (with a blank import) in your main package or test setup to
// ensure all lockfile parsers are available:
//
//	import _ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/parsers"

import (
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/cpp"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/dart"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/dotnet"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/elixir"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/golang"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/java"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/javascript"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/php"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/renv"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/ruby"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/rust"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/lockfile/system"
)

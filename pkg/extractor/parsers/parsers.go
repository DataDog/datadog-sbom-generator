package parsers

// Package "parsers" imports all lockfile parser subpackages to ensure their init() functions
// are called and extractors are registered.
//
// Import this package (with a blank import) in your main package or test setup to
// ensure all lockfile parsers are available:
//
//	import _ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/parsers"

import (
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/cpp"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/dart"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/dotnet"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/elixir"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/golang"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/javascript"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/php"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/renv"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/ruby"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/rust"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/swift"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/system"
)

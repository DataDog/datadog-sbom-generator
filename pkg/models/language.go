package models

type Language string

// These constants are only used for display purposes.
// For language constants used by our backend, follow this pattern:
// https://github.com/DataDog/datadog-ci/blob/master/src/commands/sbom/types.ts#L1-L10
const (
	Cpp        Language = "C++"
	Dart       Language = "Dart"
	Dotnet     Language = ".NET"
	Elixir     Language = "Elixir"
	Go         Language = "Go"
	Java       Language = "Java"
	Javascript Language = "Javascript"
	PHP        Language = "PHP"
	Python     Language = "Python"
	R          Language = "R"
	Ruby       Language = "Ruby"
	Rust       Language = "Rust"
)

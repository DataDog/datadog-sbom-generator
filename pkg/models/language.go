package models

type Language string

// These constants are only used for display purposes.
// For language constants used by our backend, follow this pattern:
// https://github.com/DataDog/datadog-ci/blob/master/src/commands/sbom/types.ts#L1-L10
const (
	Java       Language = "Java"
	Python     Language = "Python"
	Dotnet     Language = ".NET"
	Javascript Language = "Javascript"
	Ruby       Language = "Ruby"
	Go         Language = "Go"
	PHP        Language = "PHP"
	Cpp        Language = "C++"
	Elixir     Language = "Elixir"
	Dart       Language = "Dart"
	R          Language = "R"
	Rust       Language = "Rust"
	Swift      Language = "Swift"
)

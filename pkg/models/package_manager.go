package models

type PackageManager string

const (
	Bazel        PackageManager = "Bazel"
	Bun          PackageManager = "Bun"
	Bundler      PackageManager = "Bundler"
	Composer     PackageManager = "Composer"
	Conan        PackageManager = "Conan"
	Crates       PackageManager = "Crates"
	Golang       PackageManager = "Golang"
	Gradle       PackageManager = "Gradle"
	Hex          PackageManager = "Hex"
	Maven        PackageManager = "Maven"
	NPM          PackageManager = "NPM"
	NuGet        PackageManager = "NuGet"
	Pdm          PackageManager = "Pdm"
	Pipfile      PackageManager = "Pipfile"
	Pnpm         PackageManager = "Pnpm"
	Poetry       PackageManager = "Poetry"
	Pub          PackageManager = "Pub"
	Renv         PackageManager = "Renv"
	Requirements PackageManager = "Requirements"
	SwiftPM      PackageManager = "SwiftPM"
	Unknown      PackageManager = "Unknown"
	Uv           PackageManager = "uv"
	Yarn         PackageManager = "Yarn"
)

var PackageManagerToLanguage = map[PackageManager]Language{
	Bazel:        Java,
	Maven:        Java,
	Gradle:       Java,
	NPM:          Javascript,
	Yarn:         Javascript,
	Pnpm:         Javascript,
	Bun:          Javascript,
	Requirements: Python,
	Pipfile:      Python,
	Pdm:          Python,
	Poetry:       Python,
	Uv:           Python,
	NuGet:        Dotnet,
	Bundler:      Ruby,
	Golang:       Go,
	Composer:     PHP,
	Crates:       Rust,
	Conan:        Cpp,
	Hex:          Elixir,
	Pub:          Dart,
	Renv:         R,
	SwiftPM:      Swift,
}

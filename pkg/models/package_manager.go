package models

type PackageManager string

const (
	Maven        PackageManager = "Maven"
	Gradle       PackageManager = "Gradle"
	NPM          PackageManager = "NPM"
	Yarn         PackageManager = "Yarn"
	Pnpm         PackageManager = "Pnpm"
	Requirements PackageManager = "Requirements"
	Pipfile      PackageManager = "Pipfile"
	Pdm          PackageManager = "Pdm"
	Poetry       PackageManager = "Poetry"
	Uv           PackageManager = "uv"
	NuGet        PackageManager = "NuGet"
	Bundler      PackageManager = "Bundler"
	Golang       PackageManager = "Golang"
	Composer     PackageManager = "Composer"
	Crates       PackageManager = "Crates"
	Conan        PackageManager = "Conan"
	Hex          PackageManager = "Hex"
	Pub          PackageManager = "Pub"
	Renv         PackageManager = "Renv"
	Unknown      PackageManager = "Unknown"
)

var PackageManagerToLanguage = map[PackageManager]Language{
	Maven:        Java,
	Gradle:       Java,
	NPM:          Javascript,
	Yarn:         Javascript,
	Pnpm:         Javascript,
	Requirements: Python,
	Pipfile:      Python,
	Pdm:          Python,
	Poetry:       Python,
	Uv:           Python,
	NuGet:        Dotnet,
	Bundler:      Ruby,
	Golang:       Go,
	Composer:     PHP,
	Crates:       Cpp,
	Conan:        Cpp,
	Hex:          Elixir,
	Pub:          Dart,
	Renv:         R,
}

package models

type PackageManager string

const (
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
	Unknown      PackageManager = "Unknown"
	Uv           PackageManager = "uv"
	Yarn         PackageManager = "Yarn"
)

const (
	ApkFilePath               string = "/lib/apk/db/installed"
	BundlerFilePath           string = "Gemfile.lock"
	ComposerFilePath          string = "composer.lock"
	ConanFilePath             string = "conan.lock"
	CratesFilePath            string = "Cargo.lock"
	DpkgFilePath              string = "/var/lib/dpkg/status"
	GolangFilePath            string = "go.mod"
	GradleBuildScriptFilePath string = "buildscript-gradle.lockfile"
	GradleFilePath            string = "gradle.lockfile"
	HexFilePath               string = "mix.lock"
	MavenFilePath             string = "pom.xml"
	NpmFilePath               string = "package-lock.json"
	NuGetFilePath             string = "packages.lock.json"
	PdmFilePath               string = "pdm.lock"
	PipfileFilePath           string = "Pipfile.lock"
	PnpmFilePath              string = "pnpm-lock.yaml"
	PoetryFilePath            string = "poetry.lock"
	PubFilePath               string = "pubspec.lock"
	RenvFilePath              string = "renv.lock"
	RequirementsFilePath      string = "requirements.txt"
	UvFilePath                string = "uv.lock"
	YarnFilePath              string = "yarn.lock"
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

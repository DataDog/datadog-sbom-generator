package models

type ParsedFilePath string

// String returns the string representation of the ParsedFilePath
func (p ParsedFilePath) String() string {
	return string(p)
}

// Standard lockfile names used by extractors
const (
	ApkFilePath                ParsedFilePath = "/lib/apk/db/installed"
	BundlerFilePath            ParsedFilePath = "Gemfile.lock"
	ComposerFilePath           ParsedFilePath = "composer.lock"
	ConanFilePath              ParsedFilePath = "conan.lock"
	CratesFilePath             ParsedFilePath = "Cargo.lock"
	DpkgFilePath               ParsedFilePath = "/var/lib/dpkg/status"
	GolangFilePath             ParsedFilePath = "go.mod"
	GolangBinaryFilePath       ParsedFilePath = "go-binary"
	GradleBuildScriptFilePath  ParsedFilePath = "buildscript-gradle.lockfile"
	GradleVerificationFilePath ParsedFilePath = "gradle/verification-metadata.xml"
	GradleFilePath             ParsedFilePath = "gradle.lockfile"
	HexFilePath                ParsedFilePath = "mix.lock"
	MavenFilePath              ParsedFilePath = "pom.xml"
	NodeModulesPath            ParsedFilePath = "node_modules"
	NpmFilePath                ParsedFilePath = "package-lock.json"
	NuGetCsProjFilePath        ParsedFilePath = "csproj"
	NugetLockFilePath          ParsedFilePath = "packages.lock.json"
	PdmFilePath                ParsedFilePath = "pdm.lock"
	PipfileFilePath            ParsedFilePath = "Pipfile.lock"
	PnpmFilePath               ParsedFilePath = "pnpm-lock.yaml"
	PoetryFilePath             ParsedFilePath = "poetry.lock"
	PubFilePath                ParsedFilePath = "pubspec.lock"
	RenvFilePath               ParsedFilePath = "renv.lock"
	RequirementsFilePath       ParsedFilePath = "requirements.txt"
	UvFilePath                 ParsedFilePath = "uv.lock"
	YarnFilePath               ParsedFilePath = "yarn.lock"
)

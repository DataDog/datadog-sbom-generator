# Datadog-Sbom-Generator

This repository contains the source code of Datadog's SBOM Generator.
Its goal is to scan a cloned repository folder to extract dependencies which would
be installed on your systems and produce a CycloneDX SBOM out of it.

If you're interested in this repository, you might be interested in [Setting up Software Composition Analysis in your repositories](https://docs.datadoghq.com/security/code_security/software_composition_analysis/setup_static/).

## How to install

1. Go to the [release page](https://github.com/DataDog/datadog-sbom-generator/releases)
2. Select the version you want to use (or use the [latest version](https://github.com/DataDog/datadog-sbom-generator/releases/latest))
3. Download the asset depending on your operating system and your CPU architecture
4. Unzip the asset

## Running the scanner

To scan a repository folder and generate a SBOM, you can use this command:

```bash
datadog-sbom-generator scan -o "/tmp/sbom.json" "/path/to/directory"
```

For detailed documentation on all commands and options, see [USAGE.md](USAGE.md).

You can also get help directly from the command line:

```bash
datadog-sbom-generator --help
datadog-sbom-generator scan --help
```

## Supported package managers

This tool sources all dependencies by parsing package manager files. As new package managers appears everyday, we do not support all of them. Here's a list of supported package managers:

| Language   | Package Manager                           |
| ---------- | ----------------------------------------- |
| .NET       | Nuget                                     |
| C++        | Conan                                     |
| Go         | Golang                                    |
| Java       | Gradle, Maven, Bazel (rules_jvm_external) |
| JavaScript | NPM, PNPM, Yarn                           |
| PHP        | Composer                                  |
| Python     | Pdm, Pipenv, Poetry, Requirements, uv     |
| Ruby       | Bundler                                   |
| Rust       | Crates                                    |
| Swift      | Swift Package Manager                     |

## Limitations

Datadog SBOM Generator reads package manager dependencies declaration files or their lock files. It means it can only scan
dependencies which are declared in a standard and enforced way by each supported dependency manager.

We will detail here any known limitations by language.

### Python

This tool only supports extracting packages from:

- `requirements*.txt`
- `Pipfile.lock`
- `poetry.lock`
- `pdm.lock`
- `uv.lock`

This tool only supports enriching information from the following package manager declaration files:

- `Pipfile`
- `pyproject.toml`

### Java

#### Maven

- This tool only supports extracting packages and locations from `pom.xml`.
- It can only scan `pom.xml` files which are stored in the same repository.
- If a pom file defines a parent that is not stored in the repository or is an artifact hosted by an artifact registry, the scanner will try to download it from Maven central. If the scanner cannot locate it there, or cannot access it, it won't be able to resolve the version.

#### Gradle

- This tool only supports extracting packages from `gradle.lockfile`.
- This tool only supports package information enrichment from `build.gradle` and `gradle/verification-metadata.xml` files.

#### Bazel

- This tool supports extracting packages from `maven_install.json` (and any `{name}_maven_install.json` variant) produced by [`rules_jvm_external`](https://github.com/bazel-contrib/rules_jvm_external).
- Both the v1 `dependency_tree` format (rules_jvm_external < 5.1) and the v2/v3 `artifacts` map format (rules_jvm_external ≥ 5.1) are supported.
- `IsDirect` is not set; distinguishing direct from transitive dependencies would require parsing the Bazel workspace files.

### Javascript and Typescript

NPM, Yarn and PNPM have workspace support

#### NPM

- This tool only supports extracting packages from `package-lock.json`.
- This tool only supports package information enrichment from `package.json`.

#### Yarn

- This tool only supports extracting packages from `yarn.lock`.
- This tool only supports package information enrichment from `package.json`.

#### PNPM

- This tool only supports extracting packages from `pnpm-lock.yaml`.
- This tool only supports package information enrichment from `package.json`.

### .Net

#### Nuget

- This tool supports extracting packages from `packages.lock.json` and `*.csproj`.
- This tool only supports package information enrichment from `*.csproj` when parsing `packages.lock.json`.
- Central and build configuration discovery:
  - The tool automatically discovers `Directory.Packages.props` and `Directory.Build.props`.
  - Discovery is performed in the limit of the scanned directory.
  - Only configuration files found within the scan scope are considered; parent directories outside the scan root are intentionally ignored.

### Ruby

#### Bundler

- This tool only supports extracting packages from `Gemfile.lock`.
- This tool only supports package information enrichment from `Gemfile` and `*.gemspec`.
- If the version of a package is defined in a variable, the location reported by the scanner will be the usage of the variable.
- Dependencies sourced from Git repositories won't have any version reported.

### C++

#### Conan

- This tool only supports extracting packages from `conan.lock`.

### Rust

#### Crates

- This tool only supports extracting packages from `Cargo.lock`.
- This tool supports package information enrichment from `Cargo.toml`, including dependencies declared in `[dependencies]`, `[dev-dependencies]`, and `[build-dependencies]` sections.
- Workspace support is not currently available.
- Renaming dependencies is not supported.

### Swift

#### Swift Package Manager

- This tool only supports extracting packages from `Package.resolved` (v1, v2, and v3 formats).
- This tool only supports package information enrichment from `Package.swift`.
- When Xcode writes the lockfile at `.swiftpm/configuration/Package.resolved`, `Package.swift` enrichment is not available because the manifest is two directory levels above the lockfile.
- `IsDirect` is only set for packages declared with a URL in `Package.swift`. Registry-based dependencies (`.package(id: ...)`) are always reported as transitive.

## Contributing

Contributions are welcome! You can contribute by:

- Reporting issues or requesting features via [GitHub Issues](https://github.com/DataDog/datadog-sbom-generator/issues)
- Submitting pull requests with improvements or bug fixes

For detailed information on building, testing, and developing the project, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

The Datadog version of datadog-sbom-generator is licensed under the [Apache License, Version 2.0](LICENSE).

## Acknowledgement

This project builds upon portions of the osv-scanner project originally developed by Google and released under the Apache License 2.0.
We thank the original authors for their foundational work.

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
datadog-sbom-generator -o "/tmp/sbom.json" "/path/of/the/directory/to/scan"
```

If you want to know more about available options, you can run the following:

```bash
datadog-sbom-generator scan help
```

## Supported package managers

This tool sources all dependencies by parsing package manager files. As new package managers appears everyday, we do not support all of them. Here's a list of supported package managers:

| Language                | Package Manager  |
| ----------------------- | ---------------- |
| Ruby                    | Bundler          |
| .NET                    | Nuget            |
| PHP                     | Composer         |
| Java                    | Maven            |
| Java                    | Gradle           |
| Python                  | requirements.txt |
| Python                  | pipenv           |
| Python                  | Poetry           |
| JavaScript / TypeScript | NPM              |
| JavaScript / TypeScript | Yarn             |
| JavaScript / TypeScript | PNPM             |
| Go                      | Go               |

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

### Javascript and Typescript

#### NPM

- This tool only supports extracting packages from `package-lock.json`.
- This tool only supports package information enrichment from `package.json`.
- This tool does not support Workspaces.

#### Yarn

- This tool only supports extracting packages from `yarn.lock`.
- This tool only supports package information enrichment from `package.json`.
- This tool does not support Workspaces.

#### PNPM

- This tool only supports extracting packages from `pnpm-lock.yaml`.
- This tool only supports package information enrichment from `package.json`.
- This tool does not support Workspaces.

### .Net

#### Nuget

- This tool only supports extracting packages from `packages.lock.json`.
- This tool only supports package information enrichment from `*.csproj`.
- Inside a `.csproj` file:
  - Templatization is not supported.
  - Including other csproj is not supported.

### Ruby

#### Bundler

- This tool only supports extracting packages from `Gemfile.lock`.
- This tool only supports package information enrichment from `Gemfile` and `*.gemspec`.
- If the version of a package is defined in a variable, the location reported by the scanner will be the usage of the variable.
- Dependencies sourced from Git repositories won't have any version reported.

## License

The Datadog version of datadog-sbom-generator is licensed under the [Apache License, Version 2.0](LICENSE).


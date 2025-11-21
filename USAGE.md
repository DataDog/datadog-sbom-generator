# Usage Guide

## Quick Start

```bash
# Scan current directory
datadog-sbom-generator scan .

# Scan with output file
datadog-sbom-generator scan -o sbom.json /path/to/directory

# Scan is the default command, so this is equivalent
datadog-sbom-generator -o sbom.json /path/to/directory

# List supported parsers
datadog-sbom-generator parsers list
```

## Commands

### scan (default)

Scans directories for package manager files and generates a Software Bill of Materials (SBOM) in CycloneDX format.

**Usage:**

```
datadog-sbom-generator scan [flags] [directory1 directory2...]
```

#### Flags

| Flag               | Aliases | Default         | Description                                                       |
| ------------------ | ------- | --------------- | ----------------------------------------------------------------- |
| `--format`         | `-f`    | `cyclonedx-1-5` | Output format. Supported: `cyclonedx-1-5`, `json`                 |
| `--output`         | `-o`    | stdout          | Save output to specified file path                                |
| `--verbosity`      | `-v`    | `error`         | Logging level. Values: `error`, `warn`, `info`, `verbose`         |
| `--not-recursive`  |         | `false`         | Do not scan subdirectories                                        |
| `--no-ignore`      |         | `false`         | Scan files normally ignored by .gitignore                         |
| `--reachability`   |         | `false`         | Enable reachability analysis                                      |
| `--enable-parsers` |         | (all)           | Filter by lockfile name, package manager, or language (see below) |
| `--exclude`        |         | (none)          | Exclude paths using glob patterns (comma-separated)               |
| `--pretty`         |         | `false`         | Format JSON output with indentation                               |

#### Examples

**Basic scanning:**

```bash
# Scan current directory with verbose output
datadog-sbom-generator scan --verbosity verbose .

# Scan specific directory
datadog-sbom-generator scan /path/to/project
```

**Output control:**

```bash
# Save to file with pretty formatting
datadog-sbom-generator scan --output sbom.json --pretty .
```

**Filtering and exclusions:**

```bash
# Exclude paths (relative to scanned directory)
datadog-sbom-generator scan --exclude "node_modules/**,test/**" .

# Only scan specific parsers by language
datadog-sbom-generator scan --enable-parsers javascript,python .

# Only scan specific package managers
datadog-sbom-generator scan --enable-parsers npm,poetry .

# Only scan specific lockfiles
datadog-sbom-generator scan --enable-parsers "package-lock.json,yarn.lock" .
```

**Advanced options:**

```bash
# Non-recursive scan (current directory only)
datadog-sbom-generator scan --not-recursive .

# Include gitignored files
datadog-sbom-generator scan --no-ignore .

# Enable reachability analysis
datadog-sbom-generator scan --reachability .
```

**Multiple directories:**

```bash
# Scan multiple directories in one run
datadog-sbom-generator scan /path/to/project1 /path/to/project2
```

### parsers

Inspect parsers used for SBOM generation.

#### parsers list

Lists all supported lockfile parsers with their associated languages and package managers.

**Usage:**

```
datadog-sbom-generator parsers list
```

**Output format:**
Displays a table with columns: Language, Package Manager, Lockfile Parsers

**Example output:**

```
+------------+------------------+----------------------+
| LANGUAGE   | PACKAGE MANAGER  | LOCKFILE PARSERS     |
+------------+------------------+----------------------+
| Go         | Golang           | go.mod               |
| Java       | Gradle           | gradle.lockfile      |
| Java       | Maven            | pom.xml              |
| Javascript | NPM              | package-lock.json    |
...
```

## Notes

- The `scan` command is the default, so `datadog-sbom-generator <path>` is equivalent to `datadog-sbom-generator scan <path>`
- When using `--enable-parsers`, you can filter by:
  - **Lockfile name**: `package-lock.json`, `pom.xml`, etc.
  - **Package manager**: `npm`, `maven`, `gradle`, `poetry`, etc.
  - **Language**: `javascript`, `java`, `python`, etc.
- Use `parsers list` to see all available parser names
- Glob patterns in `--exclude` are relative to the scanned directory
- Multiple `--enable-parsers` or `--exclude` values can be specified by repeating the flag or using comma separation

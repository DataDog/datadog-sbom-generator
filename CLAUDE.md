# datadog-sbom-generator

SBOM (Software Bill of Materials) generator that scans repositories, parses lockfiles across 20+ package managers, and outputs CycloneDX SBOMs. Built in Go.

## Build & Test

```bash
./scripts/build.sh                      # Build binary
./scripts/run_tests.sh                  # Run tests with coverage
UPDATE_SNAPS=true ./scripts/run_tests.sh # Update snapshots
./scripts/run_lints.sh                  # Lint (add --fix to auto-fix)
./scripts/run_formatters.sh             # Prettier check (CI) / write (local)
```

Pre-commit hooks run build, lint, and test on every commit (`pre-commit install` to set up).

## Architecture

```
cmd/datadog-sbom-generator/       CLI entry point (urfave/cli/v2)
  scan/                           scan command implementation
  parsers/                        parsers list command
pkg/
  lockfile/                       Core extraction layer
    parsers/parsers.go            Blank imports to register all extractors
    {language}/                   Per-language extractor + matcher implementations
    internal/testutil/            Lockfile-specific test helpers
  models/                         Domain types (Ecosystem, PackageManager, PackageDetails)
  scanner/                        Orchestration: filesystem walk, extractor dispatch, matching
  reporter/                       Output formatting (CycloneDX, JSON, verbosity)
  reachability/                   Optional reachability analysis
internal/
  output/sbom/                    CycloneDX SBOM model & serialization
  cachedregexp/                   Cached regexp (mandatory - raw regexp package is forbidden by linter)
  customgitignore/                .gitignore parsing
  utility/fileposition/           Source file position extraction for lockfile locations
  utility/purl/                   Package URL (purl) generation
  testutility/                    General test helpers (snapshots, fixtures, normalization)
```

## Key Abstractions

### Extractor (required)

Parses a lockfile and returns packages. Interface: `ShouldExtract(path) bool`, `Extract(DepFile, ScanContext) ([]PackageDetails, error)`, `IsOfficiallySupported() bool`, `PackageManager() PackageManager`.

### Matcher (optional)

Enriches extracted packages from a source file (e.g., `Cargo.toml` enriches `Cargo.lock` results). Sets `IsDirect`, `DepGroups`, and file position fields. Interface: `GetSourceFile(DepFile) (DepFile, error)`, `Match(DepFile, []PackageDetails, ScanContext) error`.

### Registration

Extractors self-register via `init()` calling `lockfile.RegisterExtractor()`. The `pkg/extractor/parsers/parsers.go` file blank-imports all language packages.

## Adding a New Parser

1. Create `pkg/extractor/{language}/` with:
   - `types.go` - struct definitions, constants
   - `parse-{lockfile}.go` - Extractor implementation + `init()` registration
   - `match-{source}.go` - Matcher implementation (if enrichment from source file is needed)
   - `parse-{lockfile}_test.go` - Tests
2. Add constants in `pkg/models/`:
   - `lockfile.go` - `ParsedFilePath` constant for the lockfile name
   - `package_manager.go` - `PackageManager` constant + entry in `PackageManagerToLanguage`
   - `ecosystem.go` - `Ecosystem` constant if new ecosystem
3. Add blank import in `pkg/extractor/parsers/parsers.go`
4. Add test fixtures in `pkg/extractor/fixtures/`

Reference implementation: `pkg/extractor/rust/` (simple, clean, has both extractor and matcher).

## Testing Patterns

- **Snapshot testing**: `go-snaps` via `testutility.NewSnapshot().MatchText(t, output)` / `.MatchJSON(t, data)`
- **Snapshot updates**: `UPDATE_SNAPS=true ./scripts/run_tests.sh`
- **Snapshot cleanup**: `testutility.CleanSnapshots(m)` in `TestMain`
- **Package assertions**: `testutil.ExpectPackages(t, actual, expected)` or `ExpectPackagesWithoutLocations`
- **Fixtures**: JSON fixtures loaded with `testutility.LoadJSONFixture[T](t, path)`
- **Parallel tests**: Use `t.Parallel()` in all tests (except when mocking global state)
- **Table-driven tests**: Standard Go pattern with `t.Run(tt.name, ...)`
- **Acceptance tests**: Gated behind `TEST_ACCEPTANCE=true` env var

## Conventions

- Use `internal/cachedregexp` instead of `regexp` (linter enforced)
- Cross-platform: normalize paths with `filepath.FromSlash()`, handle CRLF
- Error format: `fmt.Errorf("could not extract from %s: %w", path, err)`
- Extractors must handle malformed input gracefully (return empty slice, not panic)
- File positions are 1-indexed (line 1, column 1)

## CI Checks (GitHub Actions)

All must pass on PRs:

- Snapshot cleanliness
- Prettier formatting
- golangci-lint (v1.64.8)
- Tests on ubuntu, macos, windows
- License validation
- Datadog code coverage upload

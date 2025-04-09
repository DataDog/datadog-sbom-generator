## Install Git Hooks

Git hooks check that your code builds, lint and all tests pass at each commit.
Install the hooks on your local repository in two steps.

Step 1: install `pre-commit` (requires Python)

```shell
pip install pre-commit
```

Step 2: install the Git hooks on your repository

```shell
pre-commit install
```

You can contribute in 2 ways : Giving us feedback on the tool using [Github issues](https://github.com/DataDog/datadog-sbom-generator/issues) or sending us a PR with the change you would like to see.

This file will focus on giving you the keys to work on this project

### Build

To build OSV-Scanner, you'll need the following:

- [Python]() 3.10 or later with the [invoke package](https://www.pyinvoke.org/installing.html) installed
- [Go](https://golang.org/doc/install) 1.21 or later. You'll also need to set your `$GOPATH` and have `$GOPATH/bin` in your path.
- [GoReleaser](https://goreleaser.com/). This is optional, and only needed if you want reproducible builds.

You can produce a binary from the repository using go build or GoReleaser.

#### Build using only go

Run the following command in the project directory:

```bash
./scripts/build.sh
```

It will produce a binary called `osv-scanner` in the project directory

#### Build using goreleaser

Run the following command in the project directory:

```bash
./scripts/build_snapshot.sh
```

See [GoReleaser documentation](https://goreleaser.com/cmd/goreleaser_build/) for build options.

You can reproduce the downloadable builds by checking out the specific tag and running `goreleaser build`, using the same Go version as the one used during the actual release (see goreleaser workflows)

### Run tests

Run the following command in the project directory :

```bash
 ./scripts/run_tests.sh
```

Our integration tests heavily use snapshot testing through [go-snaps](https://github.com/gkampitakis/go-snaps).
To update the snapshot, you'll need to run

```bash
UPDATE_SNAPS=true ./scripts/run_tests.sh
```

If you want to generate a coverage report, you can run :

```bash
./scripts/generate_coverage_report.sh
```

### Linting

To lint your code, run the following command :

```bash
./scripts/run_lints.sh
```

### Updating LICENSE-3rdparty.csv

Whenever you need to add or upgrade a dependency, you should update the file called `LICENSE-3rdparty.csv`
(This file represents the different license and copyrights of dependencies used in this project)

To do it, please run the following command :

```bash
# Prerequisites
python3 -m pip install -r requirements.txt
go install -x github.com/goware/modvendor@latest
go install -x github.com/frapposelli/wwhrd@latest
go install -x github.com/go-enry/go-license-detector/v4/cmd/license-detector@latest

inv -e generate-licenses
```

## Releasing OSV-Scanner

1. Tag the main branch commit with the version name you want (e.g v1.0.0)
2. Wait for the Github workflow to run ([you can see it in the actions panel](https://github.com/DataDog/datadog-sbom-generator/actions/workflows/goreleaser.yml))
3. Once done, you will see a new draft release for your version in the [release section](https://github.com/DataDog/datadog-sbom-generator/releases)
4. After testing it, you can finally publish it 🎉

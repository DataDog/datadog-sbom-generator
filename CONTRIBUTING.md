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

## Build local binary

Run the following script.

```shell
./scripts/build.sh
```

A binary is then created in the top directory.

## Run lint

```shell
./scripts/run_lints.sh
```

## Run tests

```shell
./scripts/run_tests.sh
```

## Update test snapshots

```shell
UPDATE_SNAPS=true ./script/run_test.sh
```

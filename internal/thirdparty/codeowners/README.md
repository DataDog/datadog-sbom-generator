# CODEOWNERS parser

This directory contains a modified copy of [hmarr/codeowners](https://github.com/hmarr/codeowners).
Its MIT license and original copyright are preserved in `LICENSE`.

The modifications accept additional literal pattern characters, prevent a panic for the `/` pattern, and normalize Windows-style input paths on every operating system.
Keep parser compatibility tests when updating this copy.

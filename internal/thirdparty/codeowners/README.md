# CODEOWNERS parser

This directory contains a modified copy of [hmarr/codeowners](https://github.com/hmarr/codeowners).
Its MIT license and original copyright are preserved in `LICENSE`.

The modifications accept literal pattern characters including Unicode and `$`, prevent a panic for the `/` pattern, normalize Windows-style input paths on every operating system, and accept email owners with top-level domains longer than six letters.
Keep parser compatibility tests when updating this copy.

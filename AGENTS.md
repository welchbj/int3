## Workflow

- Testing
  - `./scripts/test.sh` - Run the test suite. This script accepts `pytest` command-line arguments.
  - `./scripts/test_with_info_logging.sh` - Same as `./scripts/test.sh`, but sets the int3 log level to INFO.
- Linting
  - `./scripts/format.sh` - Format the code. Always run this prior to linting.
  - `./scripts/lint.sh` - Lint the code for format and type errors. Your work is not complete until there are no linting errors.

## Directory Structure

- `docs/` - Project documentation, built on restructuredText (rst) and Sphinx.
- `examples/` - Example usage of the library.
- `int3/` - Top-level Python library directory.
  - `_vendored/` - External vendored libraries.
  - `architecture/` - Architecture metadata and register definitions for supported architectures.
  - `assembly/` - Assemble text to machine code and vice-versa.
  - `codegen` - Native code generation, instruction wrappers, and the choice-based subsystem.
  - `compilation` - Core and platform-specific compiler definitions.
  - `execution` - Execute assembly snippets in-process.
  - `factor` - Factor immediate values into operation-operand streams.
  - `format` - Format binary data across a variety of formats.
  - `meta` - Local file system utilities.
  - `mutation` - The code mutation and cleaning subsystem.
  - `platform` - Platform definitions, triple definitions, and platform-specific metadata like syscall calling conventions.
  - `__main__.py` - Command-line interface for the project.
  - `errors.py` - Library exception hierarchy.
- `patches/` - Patches to vendored libraries.
- `scripts/` - Project management scripts.
- `tests/` - Project test suite and test utilities.

## Style

- Any comments you write should be succinct, complete sentences.
- Use comments very rarely, only to provide additional context not obvious from the code itself.
- Write succinct, tightly-scoped unit tests for new functionality. Use existing test fixtures and patterns when possible.
- Imports should only be placed within the top import section of a Python source file. NEVER put import statements elsewhere.
- Tests are written as top-level `pytest` functions. NEVER use `pytest` classes to organize tests.

## Mutation Passes

Mutation passes are the core building block for mutating instructions and cleaning bad bytes and are implemented by defining classes that extend from `InstructionMutationPass`. New mutation passes MUST adhere to the following:

- Be tightly-scoped to the logic for a specific mutation pattern. There should never be several sub-branches within a single pass.
- When possible, map to high-level instruction patterns so our pass can work on multiple architectures.
  - It's okay to write architecture-specific passes, if we are targeting architecture-specific patterns.
- Only use the defined codegen interface within the `CodeGenerator` class - we should avoid inlining raw assembly instructions at all costs.

## Code Generation

The `CodeGenerator` class is the main interface for emitting raw machine code instruction paths for the mutation engine to choose from and has a few layers to its interfaces:

- Methods with names mapping to common assembly instructions - Thin wrappers around core cross-architecture instruction types (like moves, jumps, branches, and so on).
- `ll_`-prefixed methods - Low-level methods that present multi-instruction choices built from the previous category.
- `hl_`-prefixed methods - High-level methods that incorporate computations (like factoring) to present a wide array of instruction choices.

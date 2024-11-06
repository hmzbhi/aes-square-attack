# TP1 Crypo_Eng

This project includes an AES encryption implementation along with related test cases. The repository is organized into several directories for source files, tests, documentation, and tools.

## Directory Structure

- **`src/`**: Contains source code for AES encryption and attack functions.
- **`test/`**: Contains test files to validate AES encryption, attacks, and configuration changes.
- **`tools/`**: Contains additional tools and helper functions for the AES operations.
- **`doc/`**: Documentation files including AES standards and project specifications.
- **`Makefile`**: Script to compile the project and run tests.
- **`README.md`**: This file.
- **`rendu.md`**: Summary or notes related to the project.

## Requirements

- **Compiler**: `gcc`
- **Flags**: The project uses `-Wall` and `-Wextra` flags for additional warnings.

## Compilation Instructions

To compile the project and build all tests:

```bash
make
```

To run all test executables:

```bash
make run
```

To remove all compiled object files and executables:

```bash
make clean
```

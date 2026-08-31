# Contributing

Thanks for contributing to Advanced Port Scanner.

## Development

1. Create a virtual environment.
2. Install the package in editable mode: `python -m pip install -e .`
3. Run tests with `python -m pytest -q`.
4. Keep changes focused and documented.

## Pull requests

Please include:

- a clear description of the change
- tests for behavioral changes
- documentation updates when user-facing behavior changes
- security considerations for networking or API changes

## Scope

Contributions must remain focused on authorized defensive network discovery. Do not add credential attacks, exploitation, stealth, or evasion functionality.

## Code quality

Prefer small, testable functions, explicit validation, safe defaults, and structured error handling. Avoid shell-based execution when a standard-library API is available.

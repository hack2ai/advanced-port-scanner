# PyPI publishing

The repository builds Python distributions on every version tag and can publish them to PyPI with GitHub OIDC trusted publishing.

## One-time setup

Configure a PyPI Trusted Publisher for:

- Owner: `hack2ai`
- Repository: `advanced-port-scanner`
- Workflow: `.github/workflows/pypi.yml`
- Environment: `pypi`

Then enable the repository variable `PYPI_PUBLISH_ENABLED` with the value `true`.

Until both settings exist, version tags still build and validate the package, but the PyPI upload job is intentionally skipped.

For an explicit one-off publish, the workflow can also be started manually for a version tag with the `publish` input enabled.

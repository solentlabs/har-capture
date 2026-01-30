# Contributing to har-capture

Thank you for your interest in contributing to har-capture!

## Development Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/solentlabs/har-capture.git
   cd har-capture
   ```

1. **Create a virtual environment**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows
   ```

1. **Install in development mode**

   ```bash
   pip install -e ".[dev,full]"
   ```

1. **Install pre-commit hooks**

   ```bash
   pre-commit install
   pre-commit install --hook-type commit-msg
   pre-commit install --hook-type pre-push
   ```

   This installs:

   - **pre-commit**: Runs ruff lint/format on staged files
   - **commit-msg**: Validates commit message format
   - **pre-push**: Runs full test suite before push

## Code Quality Standards

This project enforces strict quality standards:

### Type Checking

All code must pass `mypy --strict`:

```bash
mypy src/
```

### Linting & Formatting

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Check linting
ruff check .

# Fix auto-fixable issues
ruff check --fix .

# Format code
ruff format .
```

### Testing

All code must have tests. We require 60% coverage minimum:

```bash
# Run tests with coverage
pytest

# Run without coverage for faster feedback
pytest --no-cov

# Run specific test file
pytest tests/test_sanitization/test_html.py
```

### Pre-commit Hooks

Pre-commit runs automatically on `git commit`. To run manually:

```bash
pre-commit run --all-files
```

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting (no code change)
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:

```
feat(sanitization): add WiFi credential detection
fix(cli): handle missing output directory
docs: update installation instructions
test(validation): add PII detection tests
```

## Pull Request Process

1. **Create a branch** from `main`:

   ```bash
   git checkout -b feat/my-feature
   ```

1. **Make your changes** following the code standards above

1. **Run all checks locally**:

   ```bash
   # One command to run everything CI runs:
   ./scripts/ci-local.sh

   # Or run each check separately:
   pre-commit run --all-files
   pytest
   mypy src/
   ```

1. **Push and create a PR**:

   ```bash
   git push -u origin feat/my-feature
   ```

1. **Fill out the PR template** with:

   - Description of changes
   - Related issues
   - Testing performed

1. **Wait for CI** to pass and address any feedback

## Project Structure

```
har-capture/
├── src/har_capture/       # Main package
│   ├── sanitization/      # PII removal
│   ├── capture/           # Browser-based capture
│   ├── validation/        # PII leak detection
│   └── cli/               # Command-line interface
├── tests/                 # Test files (mirror src structure)
├── docs/                  # Documentation
└── pyproject.toml         # Project configuration
```

## Adding New Features

1. **Write tests first** (TDD encouraged)
1. **Add type hints** to all functions
1. **Add docstrings** (Google style)
1. **Update CHANGELOG.md** under `[Unreleased]`
1. **Update README.md** if adding user-facing features

## Dependencies

- **Core package has ZERO dependencies** - only stdlib
- Optional dependencies are in `[project.optional-dependencies]`
- Add new optional deps only when truly necessary
- Dev dependencies go in the `dev` extra

## Questions?

- Open an issue for bugs or feature requests
- Use discussions for questions

Thank you for contributing!

______________________________________________________________________

## Maintainer Setup

One-time setup for repository maintainers:

### GitHub Repository Settings

1. **Enable private vulnerability reporting**

   - Settings → Code security and analysis → Private vulnerability reporting → Enable

1. **Create GitHub Environments**

   - Settings → Environments → New environment
   - Create `pypi` (for production releases)
   - Create `test-pypi` (for test releases)

### PyPI Trusted Publishing

Configure OIDC publishing (no API tokens needed):

1. **PyPI:** https://pypi.org/manage/account/publishing/

   - Add publisher
   - Owner: `solentlabs`
   - Repository: `har-capture`
   - Workflow: `publish.yml`
   - Environment: `pypi`

1. **Test PyPI:** https://test.pypi.org/manage/account/publishing/

   - Same settings, environment: `test-pypi`

### Releasing

```bash
# Update version in pyproject.toml and src/har_capture/__init__.py
# Update CHANGELOG.md

git add -A
git commit -m "chore: release v0.1.0"
git tag v0.1.0
git push && git push --tags
```

The publish workflow triggers automatically on version tags.

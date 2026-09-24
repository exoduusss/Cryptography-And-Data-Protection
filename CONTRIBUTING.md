# Contributing to Cryptography & Secure Systems

Thank you for your interest in contributing! This repository is organized as a structured 3-week applied cryptography portfolio.

## Development Setup

1. **Prerequisites**:
   - Python 3.11+
   - Git
   - GitHub CLI (`gh`) (optional for local dev, needed for publishing)

2. **Setup Environment**:
   ```powershell
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt -r requirements-dev.txt
   pip install -e .
   ```

   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt -r requirements-dev.txt
   pip install -e .
   ```

3. **Pre-commit Hooks**:
   ```bash
   pre-commit install
   ```

## Development & Verification Standards

All changes must pass the strict Verification Gate:
```bash
ruff check .
ruff format --check .
mypy week1_feistel week2_double_ratchet week3_paillier_auction
bandit -r week1_feistel week2_double_ratchet week3_paillier_auction -x week1_feistel/tests,week2_double_ratchet/tests,week3_paillier_auction/tests
pytest --cov=week1_feistel --cov=week2_double_ratchet --cov=week3_paillier_auction --cov-fail-under=85
```

## Commit Guidelines

We enforce [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(w1-feistel)`: New feature or module for Week 1
- `fix(w2-ratchet)`: Bug fix for Week 2
- `docs(w3-paillier)`: Documentation updates for Week 3
- `test(...)`: Adding or refactoring tests
- `chore(...)`: Tooling, CI, dependencies, or housekeeping

## Summary of Changes

- **Week / Domain**: [Week 1: Feistel / Week 2: Double Ratchet / Week 3: Paillier]
- **Type of Change**: [Feature / Bug Fix / Documentation / Security / Refactor]

### Description
<!-- Provide a clear and concise description of the changes introduced -->

## Verification Checklist

- [ ] `ruff check .` passed with 0 errors
- [ ] `ruff format --check .` passed
- [ ] `mypy <week_dir>` passed with strict type annotations
- [ ] `bandit -r <week_dir> -x <week_dir>/tests` passed with 0 security issues
- [ ] `pytest <week_dir> --cov=<week_dir> --cov-fail-under=85` passed
- [ ] Demo script executed and output verified
- [ ] Documentation and architectural diagrams updated in `docs/`
- [ ] No hardcoded secrets, keys, or non-educational claims

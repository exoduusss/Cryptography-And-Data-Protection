# Workspace Cryptographic Engineering Rules

1. **Imports & Packages**: Every folder that holds Python code has an `__init__.py`. Use absolute imports (`from week1_feistel.src.feistel import ...`), never fragile relative paths or `sys.path` hacks.
2. **Project Configuration**: `pyproject.toml` defines `requires-python = ">=3.11"`, package discovery for all three weeks, and `[tool.pytest.ini_options]` with `testpaths`, `pythonpath = ["."]`, and `asyncio_mode = "auto"`. `pytest` must work from the repo root with no extra flags.
3. **Tooling Configuration**: Configure ruff, mypy, bandit, and coverage in `pyproject.toml`. Bandit excludes `tests/`.
4. **Matplotlib Backend**: Matplotlib uses the headless backend (`matplotlib.use("Agg")`) and saves PNGs to `docs/images/` (create if missing). Never call `plt.show()` in tests or CI.
5. **Hypothesis Testing**: Hypothesis with slow crypto: use `@settings(deadline=None, max_examples=...)` and small key sizes. Paillier tests use 512-bit keys, the demo uses 2048-bit. Cache test keypairs in a session-scoped fixture.
6. **Cross-Platform Compatibility**: Use `pathlib`, UTF-8 file I/O, and no hardcoded absolute paths. Everything must run on Windows, macOS, and Linux.
7. **Server Testing**: Server tests use FastAPI `TestClient`/`httpx`, a configurable port (default 8000), and no fixed sleeps.
8. **Randomness & Cryptographic Primitives**: Randomness only via `secrets`/`os.urandom`. Vetted libraries for X25519/Ed25519/HKDF/AEAD; never implement those yourself. Never hardcode keys or secrets. `.gitignore` covers `.env`, `*.pem`, `*.key`, `.venv`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `htmlcov`, `.coverage`.
9. **Documentation & Typing**: Type hints and docstrings everywhere. Educational code (Feistel, Paillier) is labeled "not for production use." No claims like "military-grade" or "completely secure." Document every cryptographic assumption and limitation (timing side channels, no constant-time guarantees, metadata leakage).
10. **Persistence**: These rules persist in the repository `.agents/rules/` directory across sessions and context resets.

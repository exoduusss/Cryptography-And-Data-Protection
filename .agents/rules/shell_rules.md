# Shell and Environment Guidelines

- **Operating System**: Windows (Microsoft Windows NT 10.0.26200.0)
- **Shell**: Windows PowerShell 5.1
- **Syntax Rules**:
  - Do NOT chain commands with `&&` (PowerShell 5.1 does not support `&&`; use `;` or execute commands sequentially).
  - Activate Python virtual environments using `.venv\Scripts\Activate.ps1` (or `& .\.venv\Scripts\Activate.ps1`).

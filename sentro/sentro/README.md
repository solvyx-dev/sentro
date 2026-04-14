# sentro

[![PyPI](https://img.shields.io/pypi/v/sentro)](https://pypi.org/project/sentro/)
[![Python](https://img.shields.io/pypi/pyversions/sentro)](https://pypi.org/project/sentro/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-sentro--docs.onrender.com-informational)](https://sentro-docs.onrender.com)

**Scan Python packages for malicious code, typosquatting, and supply-chain attacks — before they ever install.**

Built by [Solvyx.dev](https://solvyx.dev)

```bash
sentro install requests
```

```
╭──────────────────────── sentro scan ─────────────────────────╮
│   Package : requests 2.31.0                                     │
│   PyPI    : verified                                            │
│   Risk    : SAFE  (score 0/100)                                 │
╰─────────────────────────────────────────────────────────────────╯
  No issues found.
```

---

## What it detects

- **Malicious code** — `eval()` / `exec()` at module level, `os.system()`, socket connections to hardcoded IPs
- **Install hooks** — dangerous calls in `setup.py` that run unconditionally at install time
- **Obfuscation** — `exec(base64.b64decode(...))` chains, high-entropy strings, `marshal.loads` payloads
- **Typosquatting** — names similar to popular packages (`reqeusts`, `numpy-dev`), Unicode homoglyphs
- **Dependency confusion** — package names that shadow Python stdlib modules
- **Metadata signals** — very new packages, suspiciously low download counts, missing author info

Each finding contributes to a **risk score (0–100)**. The overall verdict is `SAFE`, `WARNING`, or `DANGER`.

---

## Install

```bash
pip install sentro
```

Requires Python 3.11+.

---

## Quick start

```bash
# Scan and install
sentro install requests

# Scan only — don't install
sentro install requests --no-install

# Block install if anything scores DANGER (for CI pipelines)
sentro install requests --strict
```

---

> **Full documentation** — configuration reference, all CLI flags, CI integration guide, installer detection, and more:
>
> ### [sentro-docs.onrender.com](https://sentro-docs.onrender.com)

---

## License

MIT — built and maintained by [Solvyx.dev](https://solvyx.dev)
# Sentro Documentation

> **Scan Python packages for malicious code, typosquatting, and supply-chain attacks — before they ever install.**

Sentro acts as a security-aware wrapper around `pip`, `uv`, `poetry`, and other Python package managers. It downloads the package from PyPI, statically analyzes the source code, and gives you a risk verdict (**SAFE**, **WARNING**, or **DANGER**) — all before a single byte of malicious code touches your environment.

---

## Table of Contents

1. [Install](#install)
2. [Quick Start](#quick-start)
3. [CLI Reference](#cli-reference)
4. [Configuration](#configuration)
5. [What Sentro Detects](#what-sentro-detects)
6. [Reputation-Aware Scoring](#reputation-aware-scoring)
7. [Output Formats](#output-formats)
8. [CI Integration](#ci-integration)
9. [Troubleshooting False Positives](#troubleshooting-false-positives)

---

## Install

```bash
pip install sentro
```

Requires **Python 3.11+**.

---

## Quick Start

```bash
# Scan and install
sentro install requests

# Scan only — do not install
sentro install requests --no-install

# Block installation if DANGER is detected (great for CI)
sentro install requests --strict

# Detailed output with per-scanner summaries and metadata
sentro install requests --verbose
```

---

## CLI Reference

### `sentro install <packages...>`

The main command. Scans each package, prints a report, then forwards to the detected package manager (pip by default, or uv/poetry/etc. when available).

| Flag | Env Var | Description |
|------|---------|-------------|
| `--strict` | `SENTRO_STRICT=1` | Exit with error and **block installation** if any package scores `DANGER`. |
| `--no-install` | — | Scan only; do not invoke the installer. |
| `--skip-scan` | — | Skip scanning entirely and pass straight to the installer. |
| `-v, --verbose` | `SENTRO_VERBOSE=1` | Show **detailed findings**, per-scanner summaries, package age, download counts, and progress messages. |
| `--output-format {text,json}` | `SENTRO_OUTPUT_FORMAT` | Change report format. JSON supports verbose metadata. |
| `--installer {pip,uv,conda,mamba,poetry,pipenv,pdm,auto}` | `SENTRO_INSTALLER` | Force a specific installer. Default is `auto`. |
| `-r requirements.txt` | — | Scan all packages listed in a requirements file. |
| `--config path.toml` | — | Load an explicit TOML config file. |

All unknown flags (e.g. `--index-url`, `--constraint`) are forwarded transparently to the underlying installer.

### `sentro detect-installer`

Shows which package manager Sentro would use automatically.

```bash
$ sentro detect-installer
Detected installer: uv
```

---

## Configuration

Sentro merges configuration from multiple sources (lowest to highest priority):

1. Built-in defaults
2. `~/.config/sentro/config.toml`
3. `pyproject.toml` → `[tool.sentro]`
4. `.sentro.toml` in the current directory
5. Explicit `--config` path
6. `SENTRO_*` environment variables
7. CLI flags

### Example `.sentro.toml`

```toml
[sentro]
strict = false
verbose = false
output_format = "text"
whitelist_packages = ["my-internal-lib", "another-private-pkg"]
scanners_disabled = ["metadata"]
pypi_timeout = 15
prefer_wheel = true

[sentro.thresholds]
warning = 30
danger = 70
```

### Environment Variables

| Variable | Effect |
|----------|--------|
| `SENTRO_STRICT=1` | Enable strict mode |
| `SENTRO_VERBOSE=1` | Enable verbose output |
| `SENTRO_OUTPUT_FORMAT=json` | Set output format |
| `SENTRO_DANGER_THRESHOLD=70` | Override danger threshold |
| `SENTRO_WARNING_THRESHOLD=30` | Override warning threshold |
| `SENTRO_WHITELIST=pkg1,pkg2` | Comma-separated whitelist |

---

## What Sentro Detects

Sentro runs multiple specialized scanners against every package. Findings are aggregated into a single **risk score (0–100)**.

### 1. Malicious Code (`malicious_code`)

Detects dynamic code execution, shell invocations, network anomalies, and real-world malware patterns.

| Pattern | Severity | Notes |
|---------|----------|-------|
| `eval()` / `exec()` at **module level** | `DANGER` | Runs unconditionally on import. |
| `eval(base64.b64decode(...))` / `exec(zlib.decompress(...))` | `DANGER` | Classic obfuscation chain. |
| `os.system(...)` | `DANGER` or `INFO` | Downgraded to `INFO` in CLI / viewer / launcher contexts. |
| `subprocess(..., shell=True)` | `DANGER` or `WARNING` | Downgraded for known-safe commands (`git log`, `xdg-open`, `clear`, etc.). |
| `socket.connect(("1.2.3.4", port))` | `DANGER` | Hardcoded IPs are strong C2 indicators. |
| `socket.connect(("8.8.8.8", port))` | `INFO` (score 0) | Recognized as the common local-IP detection trick. |
| `requests.get("https://pastebin.com/...")` | `WARNING` | Pastebin, Discord webhooks, Telegram, raw GitHub, and similar staging services. |
| `open("~/.bashrc", "a")` | `DANGER` | Writing to sensitive files (persistence / credential theft). |
| `ctypes.CDLL("./payload.so")` | `WARNING` | Loading native libraries — common payload hiding technique. |
| `getattr(__builtins__, "eval")` | `DANGER` | Reflection evasion used to bypass simple static analysis. |
| `pip.main(["install", "evil"])` | `DANGER` | Programmatic pip installs (chain-loading malware). |
| `subprocess.run([sys.executable, "-m", "pip", "install", ...])` | `DANGER` | Same as above, via subprocess. |
| `importlib.import_module(variable)` | `WARNING` | Dynamic imports outside `try/except` blocks. Skipped for normal compatibility shims. |

**Smart exclusions:**
- `# nosec` comments suppress findings on that line (Bandit convention).
- Name-shadowed builtins (e.g. `from mylib import eval`) are ignored.
- `eval(compile(..., "exec"))` — the standard file-loading pattern — is scored as `INFO` (5) instead of double-flagged.
- `compile()` inside a function by itself is skipped entirely.
- `__import__()` at module level is `INFO` (0) because it is overwhelmingly used for lazy loading.

### 2. Obfuscation (`obfuscation`)

| Pattern | Severity |
|---------|----------|
| `exec(base64.b64decode(...))` chains | `DANGER` |
| Large base64/hex string constants | `WARNING` |
| High-entropy strings (>6.2 bits/char) | `WARNING` — only when other suspicious findings already exist in the same file |
| `marshal.loads` chains | `DANGER` |

Test files are skipped for encoded-constant checks (they legitimately contain fixtures and key material).

### 3. Setup Hooks (`setup_hooks`)

Analyzes `setup.py` for dangerous install-time behavior.

| Pattern | Severity |
|---------|----------|
| `os.system()` / `exec()` / `eval()` at module scope in `setup.py` | `DANGER` |
| `cmdclass` override | `WARNING` |
| Dynamic `install_requires` | `WARNING` |

### 4. Typosquatting (`typosquatting`)

| Pattern | Severity |
|---------|----------|
| Non-ASCII / homoglyph characters in package name | `DANGER` |
| Name very similar to a top PyPI package | `WARNING` |
| Popular package + suspicious suffix (`-dev`, `-fix`, `2`, `3`) | `WARNING` |

### 5. Dependency Confusion (`dependency_confusion`)

| Pattern | Severity |
|---------|----------|
| Package shadows a Python stdlib module (`json`, `os`, `urllib`) | `DANGER` |
| Package not found on PyPI | `DANGER` |

### 6. Metadata (`metadata`)

Uses PyPI API data to surface reputation signals.

| Pattern | Severity |
|---------|----------|
| Published < 7 days ago | `DANGER` |
| Published < 30 days ago | `WARNING` |
| < 100 downloads last month | `WARNING` |
| Only one release ever | `WARNING` |
| No author, homepage, or description | `WARNING` |

---

## Reputation-Aware Scoring

Not every `eval()` call is malicious. Sentro uses **package reputation** to avoid false-positive `WARNING` / `DANGER` on established, heavily-downloaded libraries.

If a package has **no DANGER findings**, its raw score is multiplied by a **reputation discount**:

| Downloads last month | Age | Discount | Example effect |
|----------------------|-----|----------|----------------|
| > 50,000 | > 1 year | **0.25×** | `numpy`, `requests`, `pandas` |
| > 10,000 | > 90 days | **0.5×** | `flask`, `django` |
| > 1,000 | > 30 days | **0.75×** | Mid-size utilities |
| ≤ 1,000 or ≤ 30 days | — | **1.0×** (no discount) | Brand-new / niche packages |

**Important:** Discounts are **ignored** as soon as a single `DANGER`-severity finding exists (e.g. a decode-exec chain). Real malware always scores at full strength.

In `--verbose` mode you can see the exact discount applied:

```text
Reputation discount  : 25%
```

---

## Output Formats

### Text (default)

Clean, colorized terminal output. Use `-v` for extra columns and a per-scanner summary table.

```bash
sentro install requests -v
```

### JSON

Machine-readable output ideal for CI dashboards.

```bash
sentro install requests --output-format json -v
```

Verbose JSON adds:
- `metadata` — `age_days`, `download_stats`, `reputation_discount`
- `scanner_summary` — count of findings per scanner by severity

---

## CI Integration

Use `--strict` in CI pipelines to fail the build when malicious code is detected:

```yaml
# .github/workflows/security.yml
- name: Scan dependencies with Sentro
  run: sentro install -r requirements.txt --strict
```

If any package scores `DANGER`, Sentro exits with code `1` and blocks installation.

For machine-readable CI logs, combine with JSON:

```yaml
- run: sentro install -r requirements.txt --strict --output-format json -v
```

---

## Troubleshooting False Positives

Sentro is designed to minimize false positives through contextual heuristics, but if you encounter one:

1. **Check `--verbose`** to see exactly which scanner and rule triggered.
2. **Add `# nosec`** to the line in your own code if the finding is intentional (Bandit convention).
3. **Whitelist internal packages** in `.sentro.toml`:
   ```toml
   whitelist_packages = ["my-private-lib"]
   ```
4. **Disable a specific scanner** if it is noisy for your use case:
   ```toml
   scanners_disabled = ["metadata"]
   ```

If a top PyPI package is still falsely flagged as `DANGER`, please [open an issue](https://github.com/solvyx-dev/sentro/issues) — it is treated as a high-priority bug.

---

## Changelog Highlights

### Accuracy & False-Positive Reduction
- **Name-shadowing detection** — locally imported `eval` / `exec` names are no longer confused with builtins.
- **Compile-exec deduplication** — `exec(compile(..., "exec"))` is recognized as the standard file-loading pattern.
- **Per-file finding caps** — repeated identical patterns in large packages (e.g. `numpy` f2py) are collapsed into a summary note.
- **Safe-command regex** — `git log`, `xdg-open`, `clear`, `make`, `--version` in `subprocess(shell=True)` are downgraded.
- **Safe-public-IP detection** — `8.8.8.8`, `1.1.1.1`, etc. used for local-IP discovery are scored as `INFO` (0).
- **`# nosec` support** — suppresses findings on manually reviewed lines.

### New Real-World Attack Detections
- Sensitive file writes (`~/.bashrc`, `~/.ssh/authorized_keys`, cron dirs, Windows startup)
- Programmatic pip installations (`pip.main`, `subprocess pip install`)
- `ctypes` native library loading
- `getattr(__builtins__, "eval")` reflection evasion
- Dynamic `importlib.import_module` (outside `try/except`)
- Hardcoded requests to suspicious staging URLs (Pastebin, Discord, Telegram, raw GitHub)

### Reporting & UX
- **`--verbose` / `-v`** flag for detailed findings, progress messages, scanner summaries, and metadata.
- **Enhanced text report** with age, downloads, reputation discount, and per-scanner breakdown.
- **Enhanced JSON report** with `metadata` and `scanner_summary` in verbose mode.
- **Progress indicators** during multi-package scans.

---

**License:** MIT — built and maintained by [Solvyx.dev](https://solvyx.dev)

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

# SleuthCred

<p align="center">
  <img src="assets/logo.png" alt="SleuthCred logo" width="320"/>
</p>

SleuthCred is a toolkit for scanning SMB shares to detect potential credentials and secrets, and optionally enriching matches with a lightweight machine-learning based detector. It combines categorized regex-based detection with contextual enrichment and scan statistics to help reduce false positives and prioritize findings.

This repository is intended for authorized security assessments, red-team engagements, and defensive research. Do not run it against systems you do not own or do not have explicit permission to test.

---

## Features

- Categorized regex patterns for:
  - common hash formats (MD5, SHA variants, bcrypt, phpass, etc.)
  - cloud and API keys (AWS, Google, Stripe, Slack, etc.)
  - tokens (Bearer, Basic, JWT, base64-ish)
  - service secrets and URLs with embedded credentials
  - generic credentials (email, password fields, private keys)
- Optional ML-based enricher (`nxc_credential_detector`) that:
  - computes token features (length, entropy, hex ratio, char classes)
  - optionally loads a joblib/scikit-learn artifact for model-based scoring
  - extracts nearby key/value context and produces a final verdict and score
- Context lines for matches (configurable)
- Robust SMB handling: reconnection, backoff, and sensible retry behavior
- Per-scan statistics and JSON results export
- File and folder filtering by extension, filename keywords, and size limits
- Configurable scan depth and file-size thresholds

---

## Repository structure (typical)

- `modules/search_passwords.py` — NXC module that implements `SMBCredentialSearcher` and integrates scanning logic.
- `modules/detector/nxc_credential_detector.py` — Lightweight enricher/classifier that provides `enrich_match(...)`. Optionally loads a joblib model artifact (`MODEL_PATH`).
- `README.md` — this file.
- `LICENSE` — license file (e.g., MIT).
- `requirements.txt` — (optional) list of Python dependencies.

---

## Requirements

- Python 3.8+ recommended
- Optional / suggested Python packages:
  - impacket
  - joblib (optional — required to load an ML artifact)
  - scikit-learn==1.8.0 (if the model artifact uses sklearn objects)
- The NXC runtime environment that provides `nxc.protocols.smb.remotefile`, `nxc.paths.NXC_PATH`, and `nxc.helpers.misc.CATEGORY` (if integrating as an NXC module).

Example installation (system-wide or venv):
```bash
pip install impacket joblib scikit-learn
```

Note: `joblib` is optional. The enricher falls back to purely heuristic rules when the joblib artifact is not available.

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/interhack86/sleuthcred.git
cd sleuthcred
```

2. (Optional) Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

Or install core dependencies manually:
```bash
pip install impacket joblib scikit-learn
```

If packaging is desired, add packaging metadata and run:
```bash
pip install .
```

4. Deploy to NetExec:
Copy the module and the detector to your local NetExec configuration directory:
```cp modules/search_passwords.py ~/.nxc/modules/
cp modules/detector/nxc_credential_detector.py ~/.nxc/modules/detector/
```

---

## Configuration

- `MODEL_PATH` environment variable:
  - Path to the joblib-model artifact for the enricher (default: `model.joblib`).
  - The artifact may be either:
    - a dict with keys `"model"`, `"scaler"` (optional), and `"meta"` (optional), or
    - a raw estimator (fallback).
- `CUSTOM_FOLDER` constant in the scanner module:
  - If set, forces the scanner to use that folder as the target folder.
- NXC module options (exposed via `NXCModule.options`):
  - `SHARE` — target share name (e.g., `C$`). If unset, all accessible shares are enumerated.
  - `FOLDER` — folder inside the share to start scanning (requires `SHARE`).
  - `MAX_FILE_SIZE` — maximum file size (bytes) to scan (default: 2 * 1024 * 1024).
  - `DEPTH` — maximum recursion depth (default: 4).
  - `PATTERN_TYPES` — comma-separated list of pattern categories (`hashes,aws,google,tokens,services,generic`), or `all`.
  - `CONTEXT_LINES` — number of context lines to display with matches (default: 2).
  - `STATS_FLAG` — enable/disable printing statistics (true/false).
  - `DEBUG` — verbose mode (true/false).
  - `OUTPUT_FOLDER` — directory to save JSON results (default under `NXC_PATH`).
  - `PRINT_FALLBACK` — print fallback matches when enricher is not installed (true/false).

---

## Usage

### As an NXC module (example)
Integrate the module into your NXC environment and run it with module options. Example option format shown in the module docs:

```
nxc smb CDIR -u '' -p '' -M search_passwords
```
OR
```
nxc smb CDIR -u '' -p '' -M search_passwords -o SHARE=C$ -o FOLDER=Users -o MAX_FILE_SIZE=5242880 -o DEPTH=4 -o CONTEXT_LINES=2 -o DEBUG=true
```

When executed, the module will:
- enumerate shares (or use `SHARE` if specified),
- walk folders up to the configured depth,
- read files that match allowed extensions and are not filtered,
- run regex detectors and optionally call the enricher for each match,
- print highlights and save JSON results if `OUTPUT_FOLDER` is set.

### Enricher CLI quick test
The enricher script supports a simple CLI mode for local testing. Use it by piping file content and providing the required arguments:

```bash
cat somefile.txt | python modules/detector/nxc_credential_detector.py <category> <pattern_name> <token> <share> <filepath>
```

Example:
```bash
echo "password=mySecret123" | python modules/detector/nxc_credential_detector.py generic password mySecret123 SHARE path/to/file
```

This prints a JSON enriched match object to stdout.

---

## Output

When `OUTPUT_FOLDER` is configured, the scanner writes a JSON file named:
```
<remote_host>_credentials.json
```

Structure includes:
- `target` — remote host
- `timestamp` — scan time
- `statistics` — aggregated scan counters and metadata
- `suspicious_filenames` — findings based on filename heuristics
- `content_matches` — enriched matches grouped by file
- `all_matches` — raw match records

---

## Troubleshooting

- Model load fails:
  - Ensure `joblib` is installed and `MODEL_PATH` points to a valid artifact.
  - Artifact format: either the estimator directly, or a dict containing `"model"` and optional `"scaler"` and `"meta"`.
- Too many false positives:
  - Enable `DEBUG` to see why tokens were flagged.
  - Narrow `PATTERN_TYPES` to specific categories.
  - Improve the ML artifact with additional labeled data.
- SMB connection issues:
  - Verify credentials and network connectivity.
  - Check that the account has permission to list/read the target shares.
  - Network instability may require raising timeouts or adjusting retry/backoff.

---

## Security & OPSEC

Use this tool only with explicit authorization. Scanning systems, collecting credentials, or exfiltrating secrets without permission may be illegal.

If you store results, secure them appropriately (disk encryption, access controls) and avoid sharing discovered secrets in public or insecure channels. Consider redaction or secure vaulting for discovered credentials.

---

## Contributing

Contributions are welcome. Suggested workflow:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/xxx`).
3. Add tests for new behavior.
4. Open a pull request describing your changes and rationale.

Please include unit tests for any change in heuristics or ML behavior. Provide small sample inputs demonstrating fixes for false positives/negatives.

---

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the `LICENSE` file in the repository for the full text:

`LICENSE` path in repo: `@interhack86/sleuthcred/files/LICENSE` (GPL v3)

You can also view the full license in the repository at:
`LICENSE` (root of the repository)

---

## TODO / Roadmap

- Add unit tests for:
  - `shannon_entropy`, `hex_ratio`, `extract_features`
  - `classify_token_simple` heuristics
  - `enrich_match` integration and JSON output
- Provide a packaged ML model artifact and an example `MODEL_PATH`.
- Add a Docker image with consistent runtime environment (impacket, joblib, scikit-learn).
- Add CI (linting, tests) and pre-commit hooks.
- Improve estimator loading to be lazy (load model on first use) and replace `print()` with structured logging.

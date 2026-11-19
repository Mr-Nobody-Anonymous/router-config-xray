# Changelog

All notable changes to this project are documented here.

## [2.1.1] - 2026-11-19

### Fixed
- **CI/CD and `make demo` failure:** the demo intentionally exits `2` when findings are detected, which GitHub Actions (bash `-e`) and `make` treated as a failed step. Both now explicitly accept exit codes `0` and `2` using an `|| code=$?` pattern that works under `-e`.
- Resource leak in `fetch()`: HTTP error responses are now closed after reading (removed `ResourceWarning`).
- Test output noise and `ResourceWarning`s in tests: CLI tests capture stdout/stderr and test files use context managers.

### Tests
- 24 unit tests (+2 new): findings exit code is `2`, clean file exit code is `0`.
- Full CI step sequence verified locally under `bash -e -o pipefail`; all `make` targets pass.

## [2.1.0] - 2026-11-19

### Added
- `pyproject.toml` and `make install`: one-command install into a local `.venv` that provides a `router-config-xray` command (works under PEP 668 / Kali / Debian).
- Friendly, traceback-free errors for missing files, empty target lists, and invalid `--timeout` / `--concurrency`; exit code `130` on interrupt.
- Redirects are now reported but never followed, keeping every request on the authorized host.

### Fixed
- The `fetch()` docstring claimed redirects were not followed; the behavior now matches.

### Tests
- 22 unit tests (+5 new) covering clean CLI errors and local redirect handling.

## [2.0.0] - 2026-11-19

### Added
- `--demo` mode: run the bundled fictional config through the full pipeline with zero network/file setup.
- `--outdir`: write JSON, HTML and Markdown reports in one command.
- `--paths-file`: combine a custom endpoint wordlist with the built-in paths.
- `--concurrency N`: parallel read-only endpoint probing with a live TTY progress bar.
- Heuristic **exposure score** (0-100, `INFO` to `CRITICAL`) with human-readable reasons - informational, not CVSS.
- Session dashboard: target/endpoint/finding counts, elapsed time, top score, next steps.
- Full unit test suite (`tests/`, 17 tests) plus built-in `--self-test`.
- GitHub Actions CI matrix (Python 3.8 - 3.12) and `Makefile`.
- `CHANGELOG.md`.

### Changed
- Terminal UI rework: bright banner, verdict badges, labeled sections, exposure meter, wrapped boxes.
- HTML report is now a dark themed dashboard with score bars and severity cards; Markdown report uses summary tables.
- Base64 secrets now surface their decoded value as the primary `recovered` view.
- README rewritten around a 30-second demo, feature table and explicit compatibility limits.

### Fixed
- Secret recovery for printable base64 values (previously left the encoded string as `recovered`).
- `write_markdown()` nested `block()` closure could raise `UnboundLocalError`.
- LAN section printed a raw Python dict instead of readable key/value rows.

### Security / project
- Repository recreated under `Mr-Nobody-Anonymous` with all commits authored/committed by that account.
- No third-party dependencies; read-only behavior unchanged.

## [1.2.0]

- Initial public release: read-only config endpoint probing, tolerant extraction, terminal/JSON/HTML/Markdown reports, `--redact`.

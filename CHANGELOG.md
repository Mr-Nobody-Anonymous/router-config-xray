# Changelog

All notable changes to this project are documented here.

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

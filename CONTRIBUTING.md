# Contributing

Thanks for your interest in contributing! This is a small embedded project — contributions are welcome whether it's a bug fix, new feature, improved blocklist support, or better documentation.

## Getting Started

1. **Fork** the repo and clone your fork
2. Copy `include/secrets.h.example` → `include/secrets.h` and fill in your credentials
3. Generate a blocklist: `python tools/generate_blocklist.py`
4. Build: `pio run -e esp32-c6`
5. Flash: `pio run -e esp32-c6 -t uploadfs -t upload`

## Development Guidelines

### Code Style
- C++17, Arduino framework
- Keep the DNS hot path **allocation-free** — no `String`, no `new`, no `malloc` in `loop()`
- New modules go in `src/` as self-contained `.h` files included by `main.cpp`
- Match existing indentation (4-space, no tabs)

### RAM Budget
The ESP32-C6 has 320 KB RAM. Current usage is ~51 KB, leaving ~270 KB free.
Any new feature should document its RAM cost in a comment near its data structures.

### Flash Budget
`app0`/`app1` partitions are 1.375 MB each. Current firmware is ~1.25 MB (86%).
Features that significantly increase binary size should be gated with a `#define` so users can opt out.

## Submitting a Pull Request

1. Create a branch: `git checkout -b feature/my-feature`
2. Make your changes and test on real hardware
3. Include serial monitor output showing the feature working
4. Open a PR against `main` with a clear description of what changed and why

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Serial monitor output and hardware details are essential for diagnosing ESP32 issues.

## Blocklist Sources

New blocklist sources can be added to `tools/generate_blocklist.py`. Requirements:
- Must be in standard hosts-file format (`0.0.0.0 domain.com`)
- Must be publicly accessible without authentication
- Should be maintained/updated regularly

## License

By contributing, you agree your contributions will be licensed under the [MIT License](LICENSE).

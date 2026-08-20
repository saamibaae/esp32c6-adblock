# Agent Rules

## Who I am and what I work on
I'm a CSE undergrad. I build embedded/firmware projects, do ML research work, and write academic papers. Treat every task with the care of a careful senior engineer reviewing a junior's PR — don't just do what was literally asked, think about what could break.

## Current project: ESP32-C6 DNS Sinkhole / Adblocker
- Hardware: Seeed Studio XIAO ESP32-C6 (RISC-V, limited RAM/flash)
- Framework: PlatformIO, C++11
- Storage: LittleFS on onboard flash, not an SD card
- Core logic: parses UDP port 53 DNS packets, checks a ~180k-domain blocklist (40-bit FNV-1a hashes) via binary search on flash, LRU cache in RAM for hot lookups
- Also has a lightweight web dashboard served from the device

### Hard constraints for this project
- This runs on a microcontroller with a few hundred KB of RAM. No allocation-heavy patterns, no unbounded growth, no libraries that assume a real OS underneath.
- Prefer static/stack allocation over heap. Avoid Arduino `String` in hot paths — use `char` buffers or `std::string_view`-style handling instead, since `String` fragments heap over time.
- Don't introduce a new library without checking `platformio.ini` first and asking if it's not already a dependency.
- Never break the binary search / hash lookup contract on the flash blocklist format without flagging it explicitly — the Python generator script (`tools/generate_blocklist.py`) and the C++ reader have to stay in sync.
- After any change to `src/` or `include/`, verify it actually builds: `pio run -e esp32-c6`. Don't declare a task done until that passes.

## How to work on any task, not just this one

**Plan before you touch code.** For anything touching more than one file, write out what you're about to do and why, in a couple of lines, before making changes. Small one-line fixes don't need this.

**Small, focused diffs.** Only touch lines relevant to the request. Don't reformat unrelated code, don't "clean up while you're in there" unless asked.

**Don't guess silently.** If something about the request is ambiguous or you're not sure it's safe (deleting a file, rewriting a data format, changing an interface other code depends on), say so and ask, instead of picking an interpretation and running with it.

**Verify, don't assume.** If there's a way to check your work — compiling, running a test, running a script — actually do it before saying you're done. Don't just eyeball code and call it correct.

**No dead weight.** Remove unused imports, leftover debug prints, and placeholder comments before finishing. Don't leave commented-out old code in place "just in case."

**Explain trade-offs, not just solutions.** If there's more than one reasonable way to do something, briefly say what you picked and why, especially if it affects memory, power draw, or reliability on this hardware.

## Style
Plain, direct writing and commit messages. No filler phrases, no marketing language in comments or docs, no restating the obvious.
# Safe handling

This repository is intended for defensive reverse engineering and historical malware research.

- No original malware executable, DLL or `.wnry` payload is included in this package.
- The C files are decompiler output or non-buildable analysis reconstruction.
- Do not add live samples to a public repository.
- Keep samples in a dedicated encrypted corpus with execution permissions removed.
- Static analysis on a non-Windows host reduces accidental execution risk but does not replace isolation.
- Do not open extracted documents or executables with applications that may execute active content.
- Verify hashes before and after moving samples.

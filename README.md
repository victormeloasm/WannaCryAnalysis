# WannaCry Core Loader — Static RE Package

Static reverse-engineering package for the WannaCry core loader sample:

```text
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
```

Prepared for GitHub publication by **Victor Duarte Melo (Fr0ggy_)**.

> This repository contains analysis artifacts only. It intentionally excludes the original malware and extracted executable payloads.

## Highlights

- PE32 x86 GUI loader, Visual C++ 6-era toolchain.
- No conventional packer signature; high entropy is caused by an encrypted embedded archive.
- Custom PE resource `XIA/2058/1033` at file offset `0x100F0`.
- Encrypted ZIP password: `WNcry@2ol7`.
- Deterministic hostname-derived service/directory name.
- Auto-start service plus direct-process fallback.
- Registry working-directory persistence under `Software\WanaCrypt0r`, value `wd`.
- `c.wnry` wallet patching and Tor endpoint configuration.
- RSA + Rijndael/AES decryption of `t.wnry`.
- MemoryModule-style manual mapping and `TaskStart(NULL, NULL)` handoff.

## Repository layout

```text
docs/
  ANALYSIS.md                 Full technical report
  FUNCTION_MAP.md             Ghidra address-to-name map
  IOCS.md                     Hashes, paths, mutex, registry, wallets, onions
  OPEN_QUESTIONS.md           Follow-on reverse-engineering plan
  REPRODUCIBILITY.md          Static extraction and analysis commands
  RESOURCE_MAP.md             Payload hierarchy
src/
  wannacry_loader_reconstructed.c  Readable, non-buildable reconstruction
  ghidra_decompile_renamed.c       Full decompile with analysis names
  function_map.csv                 Machine-readable naming map
evidence/
  ghidra_original_decompile.c
  static_triage_dump.txt
  archive listings, hashes and file-type reports
  analysis.json
rules/
  wannacry_core_loader.yar
scripts/
  static_extract.sh
  find_tor_references.sh
SECURITY.md
```

## Start here

Read [`docs/ANALYSIS.md`](docs/ANALYSIS.md), then use [`src/function_map.csv`](src/function_map.csv) while renaming the Ghidra project.

## Scope status

This package is a complete write-up of the **outer/core loader phase** analyzed so far. It does not claim that the inner `TaskStart` payload or every extracted component has been fully reversed. Those targets are listed in [`docs/OPEN_QUESTIONS.md`](docs/OPEN_QUESTIONS.md).

## Attribution and provenance

The readable C file is an analysis reconstruction, not leaked or recovered original source. The full renamed file is derived from Ghidra decompiler output and preserves address suffixes for traceability.

## The Original Public Key from WannaCry RSA-2048 cipher that stills unfactored

26123980013155777793031337501688741863556532323816881626009872764213943978830372369298745272107333491919979895551436446220495533663024981161377892687914117532302570329647019112176534720651117256801411742197324830722539439650245623068689071167081245212411745804951454355551349296400353993896307013284931255473966616296997761267631564027466132577388695503058851957815822327617059395372980339907417500762180956457279140884347295861354075966152765961880456593864985253139057448614627648063600788944423630125534233130663774435212807217673968388513794847561116924433094159182718434994527519403127020407480127542614440056693


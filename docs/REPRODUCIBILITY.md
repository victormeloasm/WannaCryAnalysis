# Reproducibility notes

All commands below are static. Do not execute the Windows sample.

## List PE resources

```bash
wrestool -l SAMPLE.exe
```

## Extract the custom resource as raw bytes

```bash
mkdir -p resources
wrestool -x --raw --type='XIA' --name=2058 --language=1033 \
  -o resources SAMPLE.exe
```

## Deterministic carve using the confirmed file offset and size

```bash
dd if=SAMPLE.exe of=wannacry_payload.zip bs=1 \
   skip=$((0x100f0)) count=3446325 status=progress
```

## List or extract the encrypted ZIP

```bash
7z l -p'WNcry@2ol7' wannacry_payload.zip
mkdir -p payload
7z x -p'WNcry@2ol7' -opayload wannacry_payload.zip
chmod -R a-x payload
```

## Search extracted components for Tor references

```bash
find payload -type f -print0 |
while IFS= read -r -d '' f; do
    hits=$(
        {
            strings -a -n 6 "$f"
            strings -a -el -n 6 "$f"
        } | grep -Ei 'tor\.exe|Data[\/]+Tor|torrc|SocksPort|ControlPort|9050|9150|\.onion'
    )
    if [ -n "$hits" ]; then
        printf '
===== %s =====
%s
' "$f" "$hits"
    fi
done
```

## Ghidra

Import as PE32 little-endian x86. Treat the CRT entry point separately and rename `0x00401FE7` as the application main routine. Use `src/function_map.csv` as the naming reference.

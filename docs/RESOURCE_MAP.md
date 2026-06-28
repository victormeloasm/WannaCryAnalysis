# Resource and payload map

```text
Outer PE
└── .rsrc
    ├── XIA / 2058 / 1033
    │   └── encrypted ZIP (password: WNcry@2ol7)
    │       ├── b.wnry
    │       ├── c.wnry
    │       ├── msg/m_*.wnry
    │       ├── r.wnry
    │       ├── s.wnry
    │       │   └── ZIP: Tor 0.2.9.10 + OpenSSL/libevent/MinGW runtimes
    │       ├── t.wnry
    │       │   └── WANACRY! + RSA-protected key + encrypted PE
    │       ├── taskdl.exe
    │       ├── taskse.exe
    │       └── u.wnry
    ├── VERSIONINFO
    │   └── fake DiskPart metadata
    └── manifest
        └── asInvoker + Common Controls + supportedOS declarations
```

The outer loader only decrypts and maps `t.wnry` directly. Other components are extracted for use by the inner payloads.

# Function map

Names are analysis labels, not recovered source identifiers.

| Address | Proposed name | Subsystem | Confidence | Rationale |
|---|---|---|---|---|
| `0x00401000` | `TransferConfigFile` | loader/config | high | Reads or writes exactly 0x30C bytes from c.wnry depending on mode. |
| `0x00401064` | `RunHiddenProcess` | loader/process | high | CreateProcessA wrapper using CREATE_NO_WINDOW and SW_HIDE; optional wait/timeout. |
| `0x004010FD` | `RegistryWorkingDirectory` | loader/registry | high | Stores or restores CWD under HKLM/HKCU Software\WanaCrypt0r, value wd. |
| `0x00401225` | `GenerateHostDerivedName` | loader/install | high | Seeds MSVCRT rand() with product of UTF-16 hostname characters; emits 8-15 lowercase letters plus 3 digits. |
| `0x004012FD` | `PayloadCryptoContext_Construct` | crypto/context | medium | Constructor-like routine for RSA/AES payload context. |
| `0x0040135E` | `PayloadCryptoContext_DeletingDestructor` | crypto/context | medium | Deleting destructor wrapper. |
| `0x0040137A` | `PayloadCryptoContext_Destruct` | crypto/context | medium | Destroys crypto subobjects and wipes buffers. |
| `0x004013CE` | `SecureWipePayloadBuffers` | crypto/context | high | Zeroes two 1 MiB buffers before GlobalFree. |
| `0x00401437` | `InitializePayloadCryptoContext` | crypto/context | high | Imports RSA key and allocates two 1 MiB work buffers. |
| `0x004014A6` | `DecryptTwnryPayload` | crypto/container | high | Parses WANACRY! container, RSA-decrypts key material, decrypts ciphertext and returns plaintext PE. |
| `0x0040170A` | `ResolveRequiredRuntimeAPIs` | loader/api | high | Resolves CryptoAPI plus wide file APIs dynamically. |
| `0x004017DD` | `CryptoKeyContext_Construct` | crypto/context | medium | Initializes key handles and critical section. |
| `0x004017FF` | `CryptoKeyContext_DeletingDestructor` | crypto/context | medium | Deleting destructor wrapper. |
| `0x0040181B` | `CryptoKeyContext_Destruct` | crypto/context | high | Deletes critical section. |
| `0x0040182C` | `AcquireRsaAesProvider` | crypto/CryptoAPI | high | Tries CryptAcquireContextA with default then Microsoft Enhanced RSA and AES provider, PROV_RSA_AES, CRYPT_VERIFYCONTEXT. |
| `0x00401861` | `ImportRsaPrivateKey` | crypto/CryptoAPI | high | Imports embedded key blob or a key blob read from a file. |
| `0x004018B9` | `ReleaseCryptoKeyContext` | crypto/CryptoAPI | high | Destroys imported keys and releases provider. |
| `0x004018F9` | `ImportRsaKeyFromFile` | crypto/CryptoAPI | high | Reads a bounded key file and imports it with CryptImportKey. |
| `0x004019E1` | `RsaDecryptBuffer` | crypto/CryptoAPI | high | Calls CryptDecrypt under a critical section and copies the resulting key material. |
| `0x00401A45` | `ResolveCryptoApiFunctions` | loader/api | high | LoadLibrary/GetProcAddress resolver for CryptoAPI functions. |
| `0x00401AF6` | `TryCreateWorkingDirectory` | loader/install | high | Creates base and generated subdirectory, changes CWD, attempts hidden/system attributes, optionally formats full path. |
| `0x00401B5F` | `SelectInstallationDirectory` | loader/install | high | Tries Windows\ProgramData, Windows\Intel, additional fallback(s), then temp parent. |
| `0x00401CE8` | `InstallAndStartService` | loader/persistence | high | Creates/starts auto-start service named with generated host-derived string; command is cmd.exe /c "<tasksche path>". |
| `0x00401DAB` | `ExtractEmbeddedResourceArchive` | loader/resources | high | Finds XIA resource 2058, opens password-protected ZIP, enumerates and extracts entries; preserves existing c.wnry. |
| `0x00401E9E` | `PatchConfigWithBitcoinAddress` | loader/config | high | Reads c.wnry, writes one of three embedded Bitcoin addresses at offset 0xB2, writes 0x30C-byte structure back. |
| `0x00401EFF` | `WaitForInitializationMutex` | loader/synchronization | high | Polls Global\MsWinZonesCacheCounterMutexA0 once per second. |
| `0x00401F5D` | `StartInstalledCopy` | loader/install | high | Tries service launch, then direct hidden CreateProcess fallback, waiting up to 60 seconds for mutex. |
| `0x00401FE7` | `WannaCryLoaderMain` | loader/main | high | Real WinMain-equivalent for installer/extractor/inner-payload loader. |
| `0x004021BD` | `MemoryLoadLibrary` | manual PE loader | high | Convenience wrapper around embedded MemoryModule-style loader. |
| `0x004021E9` | `MemoryLoadLibraryEx` | manual PE loader | high | Validates and maps an x86 PE image from memory. |
| `0x00402457` | `CheckInputBufferSize` | manual PE loader | high | Bounds check helper with ERROR_INVALID_DATA. |
| `0x00402470` | `MemoryCopySections` | manual PE loader | high | Allocates and copies PE sections. |
| `0x0040254B` | `MemoryFinalizeSections` | manual PE loader | high | Coalesces sections and applies final protections/discard behavior. |
| `0x0040264F` | `MemoryGetSectionSize` | manual PE loader | high | Derives effective size for code/data/BSS sections. |
| `0x0040267B` | `MemoryFinalizeSection` | manual PE loader | high | VirtualProtect or decommit a finalized section range. |
| `0x0040271D` | `MemoryExecuteTlsCallbacks` | manual PE loader | high | Invokes TLS callbacks with DLL_PROCESS_ATTACH. |
| `0x00402758` | `MemoryPerformBaseRelocation` | manual PE loader | high | Applies IMAGE_REL_BASED_HIGHLOW relocations. |
| `0x004027DF` | `MemoryBuildImportTable` | manual PE loader | high | Loads imported DLLs and resolves imports by name/ordinal. |
| `0x00402924` | `MemoryGetProcAddress` | manual PE loader | high | Resolves exports in the memory-mapped module by name or ordinal. |
| `0x004029CC` | `MemoryFreeLibrary` | manual PE loader | high | Runs detach, frees dependencies, releases mapped image and loader state. |
| `0x00402A46` | `RijndaelContext_Construct` | Rijndael/AES | medium | Initializes cipher object state. |
| `0x00402A53` | `RijndaelContext_DeletingDestructor` | Rijndael/AES | medium | Deleting destructor wrapper. |
| `0x00402A6F` | `RijndaelContext_Destruct` | Rijndael/AES | medium | Base destructor. |
| `0x00402A76` | `RijndaelInitialize` | Rijndael/AES | high | Validates 128/192/256-bit key and block lengths; builds encryption/decryption round keys. |
| `0x00402E7E` | `RijndaelEncryptBlock128` | Rijndael/AES | medium | Specialized 128-bit block encryption core. |
| `0x004031BC` | `RijndaelDecryptBlock128` | Rijndael/AES | medium | Specialized 128-bit block decryption core. |
| `0x0040350F` | `RijndaelEncryptBlock` | Rijndael/AES | high | General block encryption dispatcher/core. |
| `0x00403797` | `RijndaelDecryptBlock` | Rijndael/AES | high | General block decryption dispatcher/core. |
| `0x00403A28` | `XorCipherBlock` | Rijndael/AES | high | XOR helper used for chained block mode. |
| `0x00403A77` | `RijndaelTransformBuffer` | Rijndael/AES | high | Processes whole buffers; mode 1 matches CBC decryption used for t.wnry. |
| `0x00407070` | `CreateDirectoryTree` | ZIP extraction | high | Recursively creates directory components for ZIP entries. |
| `0x00407136` | `ExtractZipEntry` | ZIP extraction | high | Extracts one selected entry to disk or buffer and restores timestamps. |
| `0x0040747B` | `CloseZipContextInternal` | ZIP extraction | high | Closes current entry and underlying archive context. |
| `0x004074A4` | `OpenZipArchiveInternal` | ZIP extraction | high | Allocates ZIP wrapper and opens archive from supplied memory interface. |
| `0x00407527` | `ZipContext_Construct` | ZIP extraction | high | Initializes ZIP extraction context and optional destination root. |
| `0x00407572` | `ZipContext_Cleanup` | ZIP extraction | high | Frees destination path and scratch buffer. |
| `0x004075AD` | `OpenEmbeddedZipArchive` | ZIP extraction | high | Opens an archive from memory using the supplied password. |
| `0x004075C4` | `QueryEmbeddedZipEntry` | ZIP extraction | high | Returns archive item count or metadata/name for a selected index. |
| `0x00407603` | `ExtractEmbeddedZipEntryEx` | ZIP extraction | high | Generic entry extraction wrapper. |
| `0x0040763D` | `ExtractEmbeddedZipEntryToDisk` | ZIP extraction | high | Extracts an archive entry to disk. |
| `0x00407656` | `CloseEmbeddedZipArchive` | ZIP extraction | high | Closes and frees ZIP archive wrapper. |
| `0x0040792A` | `ConfigureFloatingPointRuntime` | MSVC CRT | high | Calls _controlfp during CRT initialization; not malware logic. |
| `0x0040793F` | `UserMathErrorStub` | MSVC CRT | high | Empty CRT math-error stub. |

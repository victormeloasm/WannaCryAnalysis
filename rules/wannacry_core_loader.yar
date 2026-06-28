rule WannaCry_Core_Loader_ed01ebfbc9eb
{
    meta:
        description = "WannaCry core loader / resource extractor"
        author = "Victor Duarte Melo (Fr0ggy_)"
        scope = "static defensive detection"
        sample_sha256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

    strings:
        $zip_password = "WNcry@2ol7" ascii
        $inner_magic = "WANACRY!" ascii
        $mutex = "Global\\MsWinZonesCacheCounterMutexA" ascii
        $task_start = "TaskStart" ascii
        $installed_name = "tasksche.exe" ascii
        $acl = "icacls . /grant Everyone:F /T /C /Q" ascii
        $hide = "attrib +h ." ascii
        $provider = "Microsoft Enhanced RSA and AES Cryptographic Provider" ascii
        $wallet1 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        $wallet2 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
        $wallet3 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
        $resource_type = "XIA" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        7 of them
}

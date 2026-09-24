#include "entrasyncdump_common.h"


void cmd_version() {
    ENTRACONNECT_VERSION ver = { 0 };

    if (!read_entra_version(&ver)) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find or read target installation.\n");
        return;
    }

    CONST WCHAR* sqlInstance = find_localdb_instance();

    CONST CHAR* authNote = NULL;
    CONST CHAR* authType = classify_auth_type(&ver, &authNote);

    CHAR verStr[32];
    API(MSVCRT, sprintf)(verStr, "%d.%d.%d.%d", ver.major, ver.minor, ver.build, ver.revision);

    BeaconPrintf(CALLBACK_OUTPUT,
        "Version: %s\n"
        "File: %ls\n"
        "SQL instance: %ls\n"
        "Auth type: %s\n"
        "Note: %s\n",
        verStr, ver.filePath,
        sqlInstance ? sqlInstance : L"(not found)",
        authType, authNote
    );
}


#ifdef _DEBUG
void main(int argc, char* argv[]) {
    cmd_version();
}
#else
void go(PCHAR args, int alen) {
    cmd_version();
}
#endif

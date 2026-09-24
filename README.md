# entraconnectdump-bof

Cobalt Strike Beacon Object Files for extracting credentials from Microsoft Entra Connect (Azure AD Connect) servers. Supports both password-based (MSOL\_/Sync\_ accounts) and certificate-based (ABA) authentication configurations.

## Prerequisites

- Local administrator on the Entra Connect server
- Entra Connect service (miiserver.exe) must be running
- Cobalt Strike 4.x with BOF support

## Modules

### `version`

Read-only recon. Reads the installed Entra Connect version from disk, auto-discovers the LocalDB instance name from the ADSync service profile's filesystem, and classifies the authentication type based on version thresholds:

- **< 2.4**: Password-only (MSOL\_/Sync\_ accounts)
- **2.4 - 2.5**: ABA/certificate available as preview
- **>= 2.6**: ABA/certificate is the default for new installs

```
entrasyncdump version
```

### `dumpcertinfo`

Certificate recon for ABA-capable installs. Enumerates certificate thumbprints from the ADSync service account's certificate directory on disk and queries the LocalDB for the Application/Client ID from `mms_management_agent.private_configuration_xml`. No impersonation required.

```
entrasyncdump dumpcertinfo [instancename]
```

### `dumpcert`

Certificate-based credential extraction for ABA installs. Enables SeDebugPrivilege, performs two-stage impersonation (admin -> SYSTEM via svchost -> ADSync via miiserver), opens the certificate store under the ADSync identity, acquires the CNG private key handle (software KSP or TPM-backed), and builds a signed RS256 JWT assertion. The assertion can be used with `roadtx` or direct OAuth2 token requests.

```
entrasyncdump dumpcert <thumbprint> <client_id> <tenant_id>
```

- `thumbprint` - 40-character hex certificate thumbprint (from `dumpcertinfo`)
- `client_id` - Application/Client ID (from `dumpcertinfo`)
- `tenant_id` - Azure AD tenant ID (GUID or domain)

### `autodumpcert`

Streamlined certificate extraction. Takes a PID directly (no process enumeration, no SQL queries), auto-discovers the thumbprint from the certificate directory, and signs the JWT. Requires the Beacon to already be running as SYSTEM (e.g., via `steal_token`).

```
entrasyncdump autodumpcert <pid> <tenant_id> <client_id>
```

- `pid` - PID of miiserver.exe (from `ps`)
- `tenant_id` - Azure AD tenant ID
- `client_id` - Application/Client ID (from `dumpcertinfo`)

### `dumpcreds`

Password credential extraction for MSOL\_/Sync\_ account installs. Connects to the ADSync LocalDB as local admin (before impersonation), queries server configuration for the encryption keyset metadata, queries credential rows from `mms_management_agent`, then impersonates the ADSync service to retrieve and DPAPI-decrypt the keyset blob (from credential store or registry). The AES-256 key extracted from the keyset decrypts each `encrypted_configuration` column (AES-CBC). Parses the resulting UTF-16LE XML for the password attribute and outputs `domain\username password`.

```
entrasyncdump dumpcreds [instancename]
```

## Workflows

### Password-based credentials (MSOL\_/Sync\_)

```
entrasyncdump version
entrasyncdump dumpcreds
```

### Certificate-based (ABA) - manual

```
entrasyncdump version
entrasyncdump dumpcertinfo
entrasyncdump dumpcert <thumbprint> <client_id> <tenant_id>
```

Use the output JWT assertion with `roadtx` or a direct token request.

### Certificate-based (ABA) - quiet

```
steal_token <system_pid>
entrasyncdump autodumpcert <miiserver_pid> <tenant_id> <client_id>
rev2self
```

No process enumeration, no SQL queries. Requires SYSTEM context and known PIDs.

## Disclaimer

This tool is provided for authorised security testing, red team engagements, and educational purposes only. Use it only on systems you own or have explicit written permission to test. Unauthorised access to computer systems is illegal and unethical. The authors accept no responsibility for misuse or damage caused by this tool.

## Building

Requires MinGW-w64 cross-compiler.

```bash
make          # release (no verbose output)
make verbose  # verbose build (debug messages in Beacon output)
make clean
```

## Loading

```
aggressor> load entrasyncdump.cna
```

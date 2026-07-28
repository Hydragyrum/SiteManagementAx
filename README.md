# FileHost - Adaptix C2 Service Extender

A file hosting and scripted web delivery service for AdaptixC2. Host files over HTTP/HTTPS and generate one-liner payloads to download and execute them on target systems.

## Features

- Host arbitrary files on any interface/port with HTTP or HTTPS
- Persistent hosting across server restarts (stored in Adaptix DB)
- One-shot mode: serve the file once, then auto-remove
- 17 built-in delivery methods across Windows, Linux, and cross-platform
- Base64-encoded PowerShell (`-enc`) option for cmd.exe compatibility
- Custom script editor with `{{URL}}` template variable
- HTTP Range request support (required by `bitsadmin`)
- Real-time download counter broadcast to all operators
- Auto-detection of MIME types from file extension
- GUI integrated into Adaptix main menu (Site Management)

## Directory Structure

```
file_host/
  config.yaml         Plugin metadata (service type, name, SSL paths)
  pl_main.go          Plugin entrypoint - InitPlugin, Call dispatcher
  handler.go          SiteManager, ServerPool, HTTP handler, API handlers
  oneliner.go         Delivery method templates and PS encoding
  ax_config.axs       AxScript GUI - Host File, Manage, Attacks dialogs
  Makefile             Build + deploy targets
  setup_filehost.sh   Standalone setup script for fresh AdaptixC2 installs
```

## Build & Deploy

**Prerequisites:** Go 1.25.4, same version used to compile `adaptixserver`.

### Using the Makefile (existing Adaptix setup)

```bash
# Build the plugin
make all

# Build and copy to ../Server/extenders/file_host/
make deploy
```

### Using the setup script (fresh install)

```bash
./setup_filehost.sh --ax /path/to/AdaptixC2
```

This copies source into the Adaptix workspace, registers it in `go.work`, builds, and deploys.

### Register in profile.yaml

Add to the `extenders:` list in your server's `profile.yaml`:

```yaml
Teamserver:
  extenders:
    - "extenders/file_host/config.yaml"
```

Restart the Adaptix server to load the plugin.

## Configuration

`config.yaml` defines the plugin identity and SSL certificate paths:

```yaml
extender_type: "service"
extender_file: "service_filehost.so"
ax_file: "ax_config.axs"

service_name: "FileHost"
service_config: |
  ssl_cert: "server.rsa.crt"
  ssl_key: "server.rsa.key"
  token_enc_key: "CHANGE_ME_WITH_A_LONG_RANDOM_SECRET"
```

SSL cert/key paths are relative to the server working directory. Required only if hosting HTTPS sites.
Set `token_enc_key` to a high-entropy secret (recommended: at least 32 random characters) so stored GitLab access tokens are encrypted with a strong key.

## Usage

After loading, a **Site Management** menu appears in the Adaptix client main menu bar with three entries:

### Host File

Upload a file to serve over HTTP/HTTPS.

| Field | Description |
|-------|-------------|
| File | Local file to host (Browse to select) |
| URI Path | URL path the file will be served at (e.g. `/hosted/payload.bin`) |
| Bind Host | Network interface to bind (0.0.0.0 = all interfaces) |
| Port | TCP port for the file server |
| Content-Type | MIME type (auto-detected from extension) |
| Download Name | Optional `Content-Disposition` filename |
| Enable SSL/TLS | Serve over HTTPS using configured cert/key |
| One-shot | Serve the file once, then auto-remove the site |

A confirmation popup shows the full URL, file size, and content-type on success.

### Attacks (Scripted Web Delivery)

Generate one-liner commands to download and execute hosted files on target systems.

| Field | Description |
|-------|-------------|
| Hosted Site | Select from active hosted files |
| Target URL | Auto-populated from selection, or enter manually |
| Category | Download & Execute, In-Memory, Shellcode, Custom Script |
| Method | Delivery technique (varies by category) |
| Base64 Encode (-enc) | Encode PowerShell payload with `-enc` flag |

**Generate** creates the one-liner. **Copy to Clipboard** copies it.

### Manage (Site Management)

Table view of all active hosted sites showing URI, host, port, SSL, content-type, file size, download count, one-shot status, creator, and full URL.

Actions: **Remove Selected**, **Copy URL**, **Refresh**.

## Delivery Methods

### Download & Execute

| Method | Shell | SSL Bypass | Notes |
|--------|-------|------------|-------|
| PowerShell Download + Exec | PowerShell | Yes | Downloads to `$env:TEMP`, runs with `Start-Process` |
| certutil | cmd.exe | No | `certutil -urlcache -split -f` |
| curl Download + Exec | cmd.exe | Yes | `curl -sko` with `-k` flag |
| curl \| bash | bash | Yes | Pipe to bash (Linux) |
| wget | bash | Yes | Downloads to `/tmp/payload` (Linux) |
| bitsadmin | cmd.exe | No | BITS transfer, requires HTTP Range support |

### In-Memory Execution

| Method | Shell | SSL Bypass | Notes |
|--------|-------|------------|-------|
| PowerShell IEX | PowerShell | Yes | `IEX(New-Object Net.WebClient).DownloadString()` |
| PowerShell IWR | PowerShell | Yes | `IEX(IWR -UseBasicParsing ...).Content` |
| mshta | cmd.exe | No | Executes HTA content directly |
| regsvr32 | cmd.exe | No | Loads `.sct` scriptlet via `scrobj.dll` |
| rundll32 | cmd.exe | No | JavaScript via `mshtml` |
| cscript | cmd.exe | No | Writes temp `.js` file, executes, deletes |

### Shellcode Execution

| Method | Shell | SSL Bypass | Notes |
|--------|-------|------------|-------|
| PowerShell VirtualAlloc | PowerShell | Yes | `VirtualAlloc` RWX + `CreateThread` + managed `Sleep(-1)` |
| PowerShell Fiber | PowerShell | Yes | `ConvertThreadToFiber` + `CreateFiber` + `SwitchToFiber` |
| PowerShell Nt Syscalls | PowerShell | Yes | `NtAllocateVirtualMemory` (RW) + `NtProtectVirtualMemory` (RX) + `NtCreateThreadEx` |
| Linux /dev/shm exec | bash | Yes | Downloads to `/dev/shm`, executes, cleans up |
| Linux memfd_create | bash | Yes | Python3 `memfd_create` + `execve` (fileless) |

### Custom Script

Free-form editor with a `{{URL}}` placeholder. Click Generate to substitute the target URL into your script.

## Base64 Encode (-enc)

When the **Base64 Encode** checkbox is checked, PowerShell methods use `-enc` instead of `-c '...'`:

```
powershell -nop -w hidden -enc <UTF-16LE-Base64>
```

This is useful when running PowerShell commands from `cmd.exe`, where single-quoted `-c '...'` payloads are treated as string literals instead of being executed. The `-enc` flag works identically from both shells.

Non-PowerShell methods (certutil, bitsadmin, curl, etc.) are unaffected by this setting.

## Architecture

### Server-Side (Go Plugin)

- **`pl_main.go`** - `InitPlugin` receives the Teamserver interface, parses SSL config, initializes `SiteManager`, restores persisted sites. `Call` dispatches to handler functions.
- **`handler.go`** - `SiteManager` stores hosted sites in memory with mutex-protected access. `ServerPool` manages per-host:port HTTP/HTTPS servers. `FileServer.ServeHTTP` serves files with `http.ServeContent` (handles Range, HEAD, Content-Length). Handlers for `host_file`, `remove_site`, `list_sites`, `generate_attack`.
- **`oneliner.go`** - Template-based one-liner generation. `formatPS` handles PowerShell encoding modes. `encodePS` performs UTF-16LE base64 encoding.

### Client-Side (AxScript)

- **`ax_config.axs`** - Three dialogs: Host File (file upload form), Manage (site table with actions), Attacks (delivery method generator with custom script editor). Communicates with the server via `ax.service_command` / `data_handler`.

### Data Flow

```
Operator GUI  -->  ax.service_command("FileHost", "host_file", {...})
                          |
                   Adaptix Server
                          |
                   Plugin.Call(operator, "host_file", args)
                          |
                   handleHostFile() --> SiteManager.Add()
                                    --> ServerPool.GetOrStart()
                                    --> SiteManager.Persist()
                                    --> broadcast("site_added")
                          |
                   data_handler() updates STATE, refreshes table
```

### Persistence

Sites are stored via `TsExtenderDataSave` with key prefix `site:`. On server restart, `RestoreAll()` loads all persisted sites and restarts their HTTP servers.

## Known Limitations

| Limitation | Reason |
|------------|--------|
| certutil fails with self-signed SSL | Windows CryptoAPI rejects untrusted certs, no bypass flag available |
| bitsadmin fails with SSL | BITS service validates certificates, cannot be overridden |
| mshta fails with SSL | Same as above |
| `powershell -c '...'` from cmd.exe prints as text | cmd.exe doesn't recognize single quotes; use `-enc` checkbox |
| regsvr32 requires `.sct` format | Only loads scriptlet XML, not arbitrary payloads |

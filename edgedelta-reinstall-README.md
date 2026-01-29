# EdgeDelta Uninstall/Reinstall Script

A comprehensive script for safely uninstalling and reinstalling the EdgeDelta agent while preserving configuration files, environment settings, and API keys.

## Features

- **Backup & Restore**: Automatically backs up all configuration before uninstall
- **Multi-OS Support**: Works on Linux (RHEL, Ubuntu, Debian, etc.) and macOS
- **Resume Capability**: Can resume from interrupted runs
- **Flexible Installation**: Supports custom paths, versions, and API keys
- **SELinux Handling**: Automatically configures SELinux on supported systems
- **Idempotent Operations**: Safe to re-run at any stage

## Supported Operating Systems

| OS Family | Distributions |
|-----------|---------------|
| Red Hat | RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora, Oracle Linux |
| Debian | Ubuntu, Debian, Linux Mint, Pop!_OS |
| Amazon | Amazon Linux 1 & 2 |
| SUSE | SLES, openSUSE |
| macOS | All versions with Homebrew support |

### Init Systems

- **systemd** (most modern Linux distributions)
- **launchd** (macOS)
- **SysVinit** (older Linux systems)

## Usage

```bash
sudo ./edgedelta-reinstall.sh [OPTIONS]
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-api_key <key>` | Override the API key (uses provided key instead of backup) |
| `-p <path>` | Set custom install path (skips path selection prompt) |
| `-p` | Force install path prompt (even if original path has 'edgedelta') |
| `-r` | Force backup selection prompt (skips auto-selection) |
| `-v <version>` | Install specific agent version (e.g., `2.12.0`, `2.12.0-rc.48`) |
| `-h, --help` | Show help message |

### Examples

```bash
# Standard interactive run (installs latest version)
sudo ./edgedelta-reinstall.sh

# Reinstall with a new API key
sudo ./edgedelta-reinstall.sh -api_key "your-new-api-key-here"

# Reinstall to a specific path
sudo ./edgedelta-reinstall.sh -p /opt/edgedelta/agent

# Force path selection prompt
sudo ./edgedelta-reinstall.sh -p

# Force backup selection (don't auto-select)
sudo ./edgedelta-reinstall.sh -r

# Install specific version
sudo ./edgedelta-reinstall.sh -v 2.12.0

# Install release candidate version
sudo ./edgedelta-reinstall.sh -v 2.12.0-rc.48

# Combine multiple options
sudo ./edgedelta-reinstall.sh -api_key "your-key" -p /custom/path -v 2.12.0
```

## How It Works

### Phase 1: Backup

1. **Detects OS** - Identifies Linux distribution, version, and init system
2. **Finds service file** - Locates the EdgeDelta service configuration
3. **Parses configuration** - Extracts install path, environment file location, etc.
4. **Creates timestamped backup** - Stores all files in `/tmp/edge_delta/YYYYMMDD_HHMMSS/`

**Files backed up:**
- Service file (`edgedelta.service` or `com.edgedelta.agent.plist`)
- Environment file (if configured)
- Override files (systemd drop-ins)
- API key file
- Installation metadata

### Phase 2: Uninstall

1. **Stops service** - Gracefully stops and disables the EdgeDelta service
2. **Removes files** - Deletes install directory, service files, and related directories
3. **Reloads init system** - Runs `systemctl daemon-reload` on systemd systems

### Phase 3: Reinstall (Optional)

1. **Selects backup** - Auto-selects best backup by file coverage score
2. **Selects install path** - Prompts for path if original didn't include 'edgedelta'
3. **Downloads installer** - Fetches latest (or specified version) from EdgeDelta
4. **Runs installer** - Installs with saved API key and custom path
5. **Updates service file** - Adjusts paths if installation location changed
6. **Restores configs** - Copies back environment and override files
7. **Configures SELinux** - Disables enforcement for EdgeDelta binary
8. **Starts service** - Enables and starts the EdgeDelta service

## Backup Location

All backups are stored in `/tmp/edge_delta/` with timestamped subdirectories:

```
/tmp/edge_delta/
├── 20250129_143022/
│   ├── edgedelta.service         # Service file copy
│   ├── environment               # Environment variables file
│   ├── environment.path          # Original path of environment file
│   ├── apikey                    # API key file
│   ├── apikey.path               # Original path of apikey file
│   ├── overrides/                # systemd override files
│   │   └── *.conf
│   ├── overrides.path            # Original override directory path
│   └── install_metadata.conf     # OS info and original paths
└── state                         # Resume tracking file
```

### Backup Scoring

When multiple backups exist, the script scores each by file coverage (0-5 points):

| File | Points |
|------|--------|
| Service file | +1 |
| Environment file | +1 |
| Override files | +1 |
| API key | +1 |
| Metadata file | +1 |

The backup with the highest score is auto-selected. Use `-r` to force manual selection.

## Path Selection Logic

When reinstalling, the script checks if the original install path contains an `edgedelta` directory:

**If path already has 'edgedelta'** (e.g., `/opt/edgedelta/agent`):
- Uses the original path automatically
- Use `-p` flag (without value) to force the selection prompt

**If path lacks 'edgedelta'** (e.g., `/opt/couchbase/var/lib/data`):
- Displays a warning
- Offers four options:
  1. Use previous path: `/opt/couchbase/var/lib/data`
  2. Use fixed path: `/opt/couchbase/var/lib/data/edgedelta` (Recommended)
  3. Use default path: `/opt/edgedelta/agent` (Recommended)
  4. Enter custom path

## SELinux Configuration

On systems with SELinux enabled and enforcing, the script:

1. Detects SELinux status using `getenforce`
2. Sets the EdgeDelta binary to unconfined execution:
   ```bash
   chcon -t unconfined_exec_t /path/to/edgedelta
   ```
3. Falls back to `semanage fcontext` if `chcon` fails

This allows EdgeDelta to run without SELinux denials while keeping the rest of the system protected.

## Resume Capability

If the script is interrupted, it can resume from where it left off:

1. State is tracked in `/tmp/edge_delta/state`
2. Each completed step is recorded
3. On re-run, detects the incomplete backup
4. Prompts to resume or start fresh
5. Skips already-completed steps

**Tracked steps:**
- `backup_service`
- `backup_env`
- `backup_overrides`
- `backup_apikey`
- `backup_metadata`
- `stop_service`
- `remove_edgedelta`

## Troubleshooting

### Service won't start after reinstall

Check SELinux denials:
```bash
ausearch -m avc -ts recent | grep edgedelta
```

Verify service file paths:
```bash
systemctl cat edgedelta
```

### API key not found

The script searches for API keys in this order:
1. `<install_path>/apikey` file
2. `ED_API_KEY` in environment file
3. `ED_API_KEY` from systemd service environment
4. `ED_API_KEY` from launchd plist (macOS)

If not found, you'll be prompted to enter one during reinstall, or use `-api_key`.

### Path not updated after install

If the service file still references old paths:
```bash
# Check current paths
grep -E "ExecStart|WorkingDirectory|EnvironmentFile" /etc/systemd/system/edgedelta.service

# The script should have updated these automatically
# If not, manually edit and reload:
sudo systemctl daemon-reload
sudo systemctl restart edgedelta
```

### Backup directory permissions

The backup directory is created with `chmod 700` (owner-only access) since it contains the API key.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (missing root, unsupported OS, missing API key, etc.) |

## Security Notes

- API keys are stored in backup files with restricted permissions (600)
- Backup directory has restricted permissions (700)
- The script requires root/sudo to run
- Backups in `/tmp` may be cleared on reboot - copy important backups elsewhere if needed

## Related Commands

After installation:
```bash
# Check service status
systemctl status edgedelta

# View logs
journalctl -u edgedelta -f

# Restart service
systemctl restart edgedelta

# Check EdgeDelta version
/opt/edgedelta/agent/edgedelta --version
```

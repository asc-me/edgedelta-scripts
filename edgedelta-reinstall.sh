#!/bin/bash
#
# EdgeDelta Uninstall/Reinstall Script
#
# This script:
# 1. Reads the EdgeDelta service file to find configuration
# 2. Backs up environment files, override files, and API key
# 3. Removes the existing EdgeDelta installation
# 4. Optionally reinstalls the latest version with preserved configuration
#
# All backups are stored in /tmp/edge_delta (Linux) or /tmp/edge_delta (macOS)
#
# Supports resuming from a partial run. If a previous execution was
# interrupted, re-running the script will detect the existing backup
# and continue from the last completed step.
#
# Supported operating systems:
# - RHEL / CentOS / Rocky Linux / AlmaLinux / Fedora
# - Ubuntu / Debian
# - macOS
# - Amazon Linux
# - SUSE / openSUSE
#
# Usage:
#   sudo ./edgedelta-reinstall.sh [OPTIONS]
#
# Options:
#   -api_key <key>    Override the API key (use this instead of backup)
#   -p <path>         Set custom install path (skip path selection prompt)
#   -p                Force install path prompt (even if path has edgedelta)
#   -r                Force backup selection prompt (skip auto-selection)
#   -v <version>      Install specific agent version (e.g., 2.12.0, 2.12.0-rc.48)
#   -h, --help        Show this help message
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─── Command-line arguments ───────────────────────────────────────────────────

# Flag variables (set by parse_args)
ARG_API_KEY=""                  # Override API key
ARG_INSTALL_PATH=""             # Override install path
ARG_FORCE_PATH_PROMPT=false     # Force path selection prompt
ARG_FORCE_BACKUP_PROMPT=false   # Force backup selection prompt
ARG_AGENT_VERSION=""            # Specific agent version to install
ARG_RESTORE_MODE=false          # Restore-only mode (skip backup/uninstall)

show_help() {
    cat <<EOF
EdgeDelta Uninstall/Reinstall Script

Usage:
  sudo $0 [OPTIONS]

Options:
  -api_key <key>    Override the API key during reinstall
                    (uses provided key instead of backup)
  -p <path>         Set custom install path during reinstall
                    (skips path selection prompt)
  -p                Force install path prompt during reinstall
                    (even if original path already has 'edgedelta')
  -r                Force backup selection prompt during reinstall
                    (skips auto-selection of best backup)
  -restore          Restore-only mode: skip backup/uninstall phases
                    and go directly to install from existing backup
  -v <version>      Install specific agent version during reinstall
                    (e.g., 2.12.0, 2.12.0-rc.48, latest)
  -h, --help        Show this help message

Examples:
  # Standard run (interactive, installs latest version)
  sudo $0

  # Reinstall with a new API key
  sudo $0 -api_key "your-new-api-key-here"

  # Reinstall to a specific path
  sudo $0 -p /opt/edgedelta/agent

  # Force path selection prompt
  sudo $0 -p

  # Force backup selection prompt
  sudo $0 -r

  # Install specific version
  sudo $0 -v 2.12.0

  # Install release candidate version
  sudo $0 -v 2.12.0-rc.48

  # Combine options
  sudo $0 -api_key "your-key" -p /custom/path -v 2.12.0

  # Restore from existing backup (skip backup/uninstall)
  sudo $0 -restore

  # Restore with specific version
  sudo $0 -restore -v 2.12.0

EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -api_key)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    ARG_API_KEY="$2"
                    shift 2
                else
                    log_error "-api_key requires a key value"
                    exit 1
                fi
                ;;
            -p)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    # Path provided
                    ARG_INSTALL_PATH="$2"
                    shift 2
                else
                    # No path provided - force prompt
                    ARG_FORCE_PATH_PROMPT=true
                    shift
                fi
                ;;
            -r)
                ARG_FORCE_BACKUP_PROMPT=true
                shift
                ;;
            -restore)
                ARG_RESTORE_MODE=true
                shift
                ;;
            -v)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    ARG_AGENT_VERSION="$2"
                    shift 2
                else
                    log_error "-v requires a version value (e.g., 2.12.0 or 2.12.0-rc.48)"
                    exit 1
                fi
                ;;
            -h|--help)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Store original args for later parsing (after logging functions are defined)
ORIGINAL_ARGS=("$@")

# ─── OS Detection ─────────────────────────────────────────────────────────────

# Detected OS info (set by detect_os)
OS_TYPE=""          # linux, macos
OS_FAMILY=""        # redhat, debian, macos, suse, amazon
OS_NAME=""          # ubuntu, rhel, rocky, centos, fedora, debian, macos, amazon, suse
OS_VERSION=""       # version number
INIT_SYSTEM=""      # systemd, launchd, sysvinit
HAS_SELINUX=false
HAS_APPARMOR=false

detect_os() {
    # Detect kernel type
    local kernel
    kernel=$(uname -s)

    case "$kernel" in
        Linux)
            OS_TYPE="linux"
            detect_linux_distro
            ;;
        Darwin)
            OS_TYPE="macos"
            OS_FAMILY="macos"
            OS_NAME="macos"
            OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
            INIT_SYSTEM="launchd"
            ;;
        *)
            OS_TYPE="unknown"
            OS_FAMILY="unknown"
            OS_NAME="unknown"
            ;;
    esac

    # Detect security modules (Linux only)
    if [[ "$OS_TYPE" == "linux" ]]; then
        if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
            HAS_SELINUX=true
        fi
        if command -v aa-status &>/dev/null && aa-status &>/dev/null; then
            HAS_APPARMOR=true
        fi
    fi
}

detect_linux_distro() {
    # Try /etc/os-release first (modern standard)
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_NAME="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"

        case "$OS_NAME" in
            rhel|centos|rocky|almalinux|fedora|ol)
                OS_FAMILY="redhat"
                ;;
            ubuntu|debian|linuxmint|pop)
                OS_FAMILY="debian"
                ;;
            amzn)
                OS_FAMILY="amazon"
                OS_NAME="amazon"
                ;;
            sles|opensuse*|suse)
                OS_FAMILY="suse"
                ;;
            *)
                # Try to detect from ID_LIKE
                case "${ID_LIKE:-}" in
                    *rhel*|*fedora*|*centos*)
                        OS_FAMILY="redhat"
                        ;;
                    *debian*|*ubuntu*)
                        OS_FAMILY="debian"
                        ;;
                    *suse*)
                        OS_FAMILY="suse"
                        ;;
                    *)
                        OS_FAMILY="unknown"
                        ;;
                esac
                ;;
        esac
    # Fallback to older detection methods
    elif [[ -f /etc/redhat-release ]]; then
        OS_FAMILY="redhat"
        OS_NAME=$(awk '{print tolower($1)}' /etc/redhat-release)
        OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/debian_version ]]; then
        OS_FAMILY="debian"
        OS_NAME="debian"
        OS_VERSION=$(cat /etc/debian_version)
    elif [[ -f /etc/SuSE-release ]]; then
        OS_FAMILY="suse"
        OS_NAME="suse"
    else
        OS_FAMILY="unknown"
        OS_NAME="unknown"
    fi

    # Detect init system
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
        INIT_SYSTEM="systemd"
    elif [[ -f /etc/init.d/edgedelta ]]; then
        INIT_SYSTEM="sysvinit"
    else
        INIT_SYSTEM="unknown"
    fi
}

print_os_info() {
    echo ""
    echo "Detected Operating System:"
    echo "──────────────────────────────────────────"
    echo "  OS Type:      $OS_TYPE"
    echo "  OS Family:    $OS_FAMILY"
    echo "  OS Name:      $OS_NAME"
    echo "  OS Version:   $OS_VERSION"
    echo "  Init System:  $INIT_SYSTEM"
    [[ "$HAS_SELINUX" == true ]] && echo "  SELinux:      enabled"
    [[ "$HAS_APPARMOR" == true ]] && echo "  AppArmor:     enabled"
    echo "──────────────────────────────────────────"
}

# ─── OS-specific paths and settings ───────────────────────────────────────────

setup_os_paths() {
    case "$OS_TYPE" in
        linux)
            BACKUP_DIR="/tmp/edge_delta"
            DEFAULT_INSTALL_PATH="/opt/edgedelta/agent"

            # Service file paths for systemd
            SERVICE_FILE_PATHS=(
                "/etc/systemd/system/edgedelta.service"
                "/lib/systemd/system/edgedelta.service"
                "/usr/lib/systemd/system/edgedelta.service"
            )
            OVERRIDE_DIR="/etc/systemd/system/edgedelta.service.d"

            # SysVinit paths (fallback)
            SYSVINIT_SCRIPT="/etc/init.d/edgedelta"
            ;;
        macos)
            BACKUP_DIR="/tmp/edge_delta"
            DEFAULT_INSTALL_PATH="/opt/edgedelta/agent"

            # LaunchDaemon paths for macOS
            SERVICE_FILE_PATHS=(
                "/Library/LaunchDaemons/edgedelta.plist"
                "/Library/LaunchDaemons/com.edgedelta.agent.plist"
                "$HOME/Library/LaunchAgents/edgedelta.plist"
                "$HOME/Library/LaunchAgents/com.edgedelta.agent.plist"
            )
            OVERRIDE_DIR=""  # macOS doesn't use override directories
            LAUNCHD_LABEL="edgedelta"
            ;;
        *)
            # Defaults
            BACKUP_DIR="/tmp/edge_delta"
            DEFAULT_INSTALL_PATH="/opt/edgedelta/agent"
            SERVICE_FILE_PATHS=()
            OVERRIDE_DIR=""
            ;;
    esac

    # State file tracks progress across runs
    STATE_FILE="${BACKUP_DIR}/state"
}

# Run OS detection and setup immediately
detect_os
setup_os_paths

# ─── Logging ──────────────────────────────────────────────────────────────────

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_skip() {
    echo -e "${GREEN}[SKIP]${NC} $1 (already done)"
}

# ─── State tracking ──────────────────────────────────────────────────────────

# Mark a step as completed
mark_step() {
    echo "$1" >> "$STATE_FILE"
}

# Check if a step was already completed in a previous run
step_done() {
    [[ -f "$STATE_FILE" ]] && grep -qxF "$1" "$STATE_FILE"
}

# ─── Detect previous backup from an interrupted run ──────────────────────────

detect_previous_run() {
    # Look for an existing state file indicating a partial run
    if [[ -f "$STATE_FILE" ]]; then
        # Find the backup subdir from state — stored on the first line prefixed with BACKUP_SUBDIR=
        PREV_SUBDIR=$(grep "^BACKUP_SUBDIR=" "$STATE_FILE" 2>/dev/null | cut -d'=' -f2-)
        if [[ -n "$PREV_SUBDIR" && -d "$PREV_SUBDIR" ]]; then
            echo ""
            log_warn "Detected a previous incomplete run"
            log_info "Backup directory: $PREV_SUBDIR"
            echo ""
            echo "  Completed steps:"
            grep -v "^BACKUP_SUBDIR=" "$STATE_FILE" | while read -r step; do
                echo "    - $step"
            done
            echo ""
            read -p "Resume the previous run? (Y/n): " RESUME_CHOICE
            if [[ ! "$RESUME_CHOICE" =~ ^[Nn]$ ]]; then
                BACKUP_SUBDIR="$PREV_SUBDIR"
                RESUMING=true
                # Reload metadata if it exists
                if [[ -f "$BACKUP_SUBDIR/install_metadata.conf" ]]; then
                    source "$BACKUP_SUBDIR/install_metadata.conf"
                    log_info "Loaded saved metadata (install path: $INSTALL_PATH)"
                fi
                return 0
            else
                # User chose not to resume — archive old state and start fresh
                mv "$STATE_FILE" "${STATE_FILE}.$(date +%s).old"
                RESUMING=false
                return 0
            fi
        fi
    fi
    RESUMING=false
}

# ─── Precondition checks ─────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        case "$OS_TYPE" in
            linux)
                log_error "This script must be run as root (use sudo)"
                exit 1
                ;;
            macos)
                log_error "This script must be run as root (use sudo)"
                exit 1
                ;;
            *)
                log_warn "Running as non-root user - some operations may fail"
                ;;
        esac
    fi
}

check_os_supported() {
    if [[ "$OS_TYPE" == "unknown" ]]; then
        log_error "Unsupported operating system"
        log_error "This script supports: RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora, Ubuntu, Debian, Amazon Linux, SUSE, macOS"
        exit 1
    fi

    if [[ "$INIT_SYSTEM" == "unknown" && "$OS_TYPE" == "linux" ]]; then
        log_warn "Could not detect init system - service management may not work correctly"
    fi
}

# Find the service file, falling back to backup from a previous run
find_service_file() {
    # On systems with SELinux (like RHEL 9), file tests may fail even if the file exists
    # Use systemctl to ask systemd directly where the service file is located
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        local systemd_path
        systemd_path=$(systemctl show edgedelta -p FragmentPath --value 2>/dev/null)
        if [[ -n "$systemd_path" && "$systemd_path" != "" ]]; then
            SERVICE_FILE="$systemd_path"
            log_info "Found service file via systemctl: $SERVICE_FILE"
            return 0
        fi
    fi

    # Fall back to checking standard paths
    for path in "${SERVICE_FILE_PATHS[@]}"; do
        if [[ -f "$path" ]]; then
            SERVICE_FILE="$path"
            log_info "Found service file: $SERVICE_FILE"
            return 0
        fi
    done

    # Service file already removed — try to use backup copy
    local backup_service_name
    case "$OS_TYPE" in
        linux)
            backup_service_name="edgedelta.service"
            ;;
        macos)
            backup_service_name="edgedelta.plist"
            ;;
        *)
            backup_service_name="edgedelta.service"
            ;;
    esac

    if [[ -n "$BACKUP_SUBDIR" && -f "$BACKUP_SUBDIR/$backup_service_name" ]]; then
        SERVICE_FILE="$BACKUP_SUBDIR/$backup_service_name"
        log_warn "Live service file not found, using backup copy: $SERVICE_FILE"
        return 0
    fi

    log_error "EdgeDelta service file not found in standard locations or backups"
    log_error "Searched: ${SERVICE_FILE_PATHS[*]}"
    exit 1
}

# ─── Parse service file ──────────────────────────────────────────────────────

parse_service_file() {
    # Skip if we already loaded metadata from a resumed run
    if [[ "$RESUMING" == true && -n "$INSTALL_PATH" ]]; then
        log_info "Using saved metadata from previous run"
        return 0
    fi

    log_info "Parsing service file for configuration..."

    case "$OS_TYPE" in
        linux)
            parse_systemd_service
            ;;
        macos)
            parse_launchd_plist
            ;;
        *)
            log_warn "Unknown OS type, attempting systemd parsing"
            parse_systemd_service
            ;;
    esac
}

parse_systemd_service() {
    EXEC_START=$(grep -E "^ExecStart=" "$SERVICE_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-)
    if [[ -n "$EXEC_START" ]]; then
        AGENT_BINARY=$(echo "$EXEC_START" | awk '{print $1}')
        INSTALL_PATH=$(dirname "$AGENT_BINARY")
        log_info "Agent binary: $AGENT_BINARY"
        log_info "Install path: $INSTALL_PATH"
    else
        log_warn "Could not extract ExecStart from service file"
        INSTALL_PATH="$DEFAULT_INSTALL_PATH"
    fi

    ENV_FILE=$(grep -E "^EnvironmentFile=" "$SERVICE_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-)
    ENV_FILE="${ENV_FILE#-}"
    if [[ -n "$ENV_FILE" ]]; then
        log_info "Environment file configured: $ENV_FILE"
    else
        log_info "No environment file configured in service file"
    fi

    WORKING_DIR=$(grep -E "^WorkingDirectory=" "$SERVICE_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-)
    [[ -n "$WORKING_DIR" ]] && log_info "Working directory: $WORKING_DIR"

    SERVICE_USER=$(grep -E "^User=" "$SERVICE_FILE" 2>/dev/null | head -1 | cut -d'=' -f2-)
    [[ -n "$SERVICE_USER" ]] && log_info "Service user: $SERVICE_USER"
}

parse_launchd_plist() {
    # Parse macOS plist file (XML format)
    # Use PlistBuddy if available, otherwise fall back to grep/sed

    if command -v /usr/libexec/PlistBuddy &>/dev/null; then
        # Extract ProgramArguments (first element is the binary path)
        AGENT_BINARY=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$SERVICE_FILE" 2>/dev/null || echo "")
        if [[ -n "$AGENT_BINARY" ]]; then
            INSTALL_PATH=$(dirname "$AGENT_BINARY")
            log_info "Agent binary: $AGENT_BINARY"
            log_info "Install path: $INSTALL_PATH"
        else
            log_warn "Could not extract ProgramArguments from plist"
            INSTALL_PATH="$DEFAULT_INSTALL_PATH"
        fi

        # Extract WorkingDirectory if set
        WORKING_DIR=$(/usr/libexec/PlistBuddy -c "Print :WorkingDirectory" "$SERVICE_FILE" 2>/dev/null || echo "")
        [[ -n "$WORKING_DIR" ]] && log_info "Working directory: $WORKING_DIR"

        # Extract UserName if set
        SERVICE_USER=$(/usr/libexec/PlistBuddy -c "Print :UserName" "$SERVICE_FILE" 2>/dev/null || echo "")
        [[ -n "$SERVICE_USER" ]] && log_info "Service user: $SERVICE_USER"

        # macOS doesn't use EnvironmentFile in the same way
        ENV_FILE=""
    else
        # Fallback: use grep/sed to parse plist
        AGENT_BINARY=$(grep -A1 "<key>ProgramArguments</key>" "$SERVICE_FILE" 2>/dev/null | grep -oE ">[^<]+<" | head -2 | tail -1 | tr -d '><')
        if [[ -n "$AGENT_BINARY" ]]; then
            INSTALL_PATH=$(dirname "$AGENT_BINARY")
            log_info "Agent binary: $AGENT_BINARY"
            log_info "Install path: $INSTALL_PATH"
        else
            log_warn "Could not extract program path from plist"
            INSTALL_PATH="$DEFAULT_INSTALL_PATH"
        fi
        ENV_FILE=""
    fi
}

# ─── Backup functions (each is idempotent) ────────────────────────────────────

create_backup_dir() {
    if [[ -d "$BACKUP_SUBDIR" ]]; then
        log_skip "Backup directory already exists"
        return 0
    fi
    log_info "Creating backup directory: $BACKUP_SUBDIR"
    mkdir -p "$BACKUP_SUBDIR"
    chmod 700 "$BACKUP_SUBDIR"
    # Record the subdir path so a resumed run can find it
    echo "BACKUP_SUBDIR=${BACKUP_SUBDIR}" >> "$STATE_FILE"
}

backup_service_file() {
    if step_done "backup_service"; then
        log_skip "Service file backup"
        return 0
    fi

    # Determine backup filename based on OS
    local backup_name
    case "$OS_TYPE" in
        macos)
            backup_name="edgedelta.plist"
            ;;
        *)
            backup_name="edgedelta.service"
            ;;
    esac

    if [[ -f "$SERVICE_FILE" ]]; then
        log_info "Backing up service file..."
        cp "$SERVICE_FILE" "$BACKUP_SUBDIR/$backup_name"
        log_success "Service file backed up"
    else
        log_info "Service file not present on disk (may already be removed)"
    fi
    mark_step "backup_service"
}

backup_environment_file() {
    if step_done "backup_env"; then
        log_skip "Environment file backup"
        return 0
    fi
    if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
        log_info "Backing up environment file: $ENV_FILE"
        cp "$ENV_FILE" "$BACKUP_SUBDIR/environment"
        echo "$ENV_FILE" > "$BACKUP_SUBDIR/environment.path"
        log_success "Environment file backed up"
    else
        log_info "No environment file to back up"
    fi
    mark_step "backup_env"
}

backup_override_files() {
    if step_done "backup_overrides"; then
        log_skip "Override files backup"
        return 0
    fi
    if [[ -d "$OVERRIDE_DIR" ]]; then
        OVERRIDE_FILES=$(find "$OVERRIDE_DIR" -name "*.conf" 2>/dev/null)
        if [[ -n "$OVERRIDE_FILES" ]]; then
            mkdir -p "$BACKUP_SUBDIR/overrides"
            for override_file in $OVERRIDE_FILES; do
                log_info "Backing up override file: $override_file"
                cp "$override_file" "$BACKUP_SUBDIR/overrides/"
            done
            echo "$OVERRIDE_DIR" > "$BACKUP_SUBDIR/overrides.path"
            log_success "Override files backed up"
        else
            log_info "No override files found in $OVERRIDE_DIR"
        fi
    else
        log_info "No override directory found"
    fi
    mark_step "backup_overrides"
}

backup_api_key() {
    if step_done "backup_apikey"; then
        log_skip "API key backup"
        return 0
    fi

    log_info "Searching for API key file in install path..."

    API_KEY_FOUND=false
    API_KEY=""
    API_KEY_FILE="${INSTALL_PATH}/apikey"

    if [[ -f "$API_KEY_FILE" ]]; then
        log_info "Found API key file: $API_KEY_FILE"
        cp "$API_KEY_FILE" "$BACKUP_SUBDIR/apikey"
        echo "$API_KEY_FILE" > "$BACKUP_SUBDIR/apikey.path"
        API_KEY=$(cat "$API_KEY_FILE")
        API_KEY_FOUND=true
        log_success "API key file backed up from: $API_KEY_FILE"
    else
        log_warn "API key file not found at: $API_KEY_FILE"

        # Fallback: environment file
        if [[ -f "$BACKUP_SUBDIR/environment" ]]; then
            API_KEY_FROM_ENV=$(grep -E "^ED_API_KEY=" "$BACKUP_SUBDIR/environment" 2>/dev/null | cut -d'=' -f2- | tr -d '"' | tr -d "'")
            if [[ -n "$API_KEY_FROM_ENV" ]]; then
                log_info "Found API key in environment file (fallback)"
                echo "$API_KEY_FROM_ENV" > "$BACKUP_SUBDIR/apikey_from_env"
                API_KEY_FOUND=true
                API_KEY="$API_KEY_FROM_ENV"
            fi
        fi

        # Fallback: systemd service (Linux only)
        if [[ "$API_KEY_FOUND" == false && "$INIT_SYSTEM" == "systemd" ]]; then
            API_KEY_FROM_SERVICE=$(systemctl show edgedelta --property=Environment 2>/dev/null | grep -oP 'ED_API_KEY=\K[^ ]+' || true)
            if [[ -n "$API_KEY_FROM_SERVICE" ]]; then
                log_info "Found API key from systemd service (fallback)"
                echo "$API_KEY_FROM_SERVICE" > "$BACKUP_SUBDIR/apikey_from_service"
                API_KEY_FOUND=true
                API_KEY="$API_KEY_FROM_SERVICE"
            fi
        fi

        # Fallback: launchd environment (macOS)
        if [[ "$API_KEY_FOUND" == false && "$INIT_SYSTEM" == "launchd" ]]; then
            if command -v /usr/libexec/PlistBuddy &>/dev/null && [[ -f "$SERVICE_FILE" ]]; then
                API_KEY_FROM_PLIST=$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:ED_API_KEY" "$SERVICE_FILE" 2>/dev/null || true)
                if [[ -n "$API_KEY_FROM_PLIST" ]]; then
                    log_info "Found API key from launchd plist (fallback)"
                    echo "$API_KEY_FROM_PLIST" > "$BACKUP_SUBDIR/apikey_from_service"
                    API_KEY_FOUND=true
                    API_KEY="$API_KEY_FROM_PLIST"
                fi
            fi
        fi
    fi

    if [[ "$API_KEY_FOUND" == true ]]; then
        log_success "API key backed up"
    else
        log_warn "No API key found - you will need to provide one during reinstallation"
    fi
    mark_step "backup_apikey"
}

store_install_metadata() {
    if step_done "backup_metadata"; then
        log_skip "Install metadata"
        return 0
    fi

    log_info "Storing installation metadata..."

    cat > "$BACKUP_SUBDIR/install_metadata.conf" <<EOF
# EdgeDelta Installation Metadata
# Generated: $(date)
# Original Service File: $SERVICE_FILE

# OS Information
OS_TYPE=${OS_TYPE}
OS_FAMILY=${OS_FAMILY}
OS_NAME=${OS_NAME}
OS_VERSION=${OS_VERSION}
INIT_SYSTEM=${INIT_SYSTEM}

# Installation Paths
INSTALL_PATH=${INSTALL_PATH}
AGENT_BINARY=${AGENT_BINARY}
WORKING_DIR=${WORKING_DIR}
SERVICE_USER=${SERVICE_USER}
ENV_FILE=${ENV_FILE}
EXEC_START=${EXEC_START}
API_KEY_FILE=${INSTALL_PATH}/apikey
EOF

    log_success "Installation metadata stored"
    mark_step "backup_metadata"
}

# ─── Uninstall functions (each is idempotent) ─────────────────────────────────

stop_service() {
    if step_done "stop_service"; then
        log_skip "Stop service"
        return 0
    fi

    log_info "Stopping EdgeDelta service..."

    case "$INIT_SYSTEM" in
        systemd)
            if systemctl is-active --quiet edgedelta 2>/dev/null; then
                systemctl stop edgedelta
                log_success "EdgeDelta service stopped"
            else
                log_info "EdgeDelta service was not running"
            fi

            if systemctl is-enabled --quiet edgedelta 2>/dev/null; then
                systemctl disable edgedelta
                log_success "EdgeDelta service disabled"
            fi
            ;;
        launchd)
            if launchctl list | grep -q "$LAUNCHD_LABEL" 2>/dev/null; then
                launchctl unload -w "/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" 2>/dev/null || \
                launchctl bootout system/"$LAUNCHD_LABEL" 2>/dev/null || true
                log_success "EdgeDelta service stopped and unloaded"
            else
                log_info "EdgeDelta service was not running"
            fi
            ;;
        sysvinit)
            if [[ -f "$SYSVINIT_SCRIPT" ]]; then
                "$SYSVINIT_SCRIPT" stop 2>/dev/null || true
                log_success "EdgeDelta service stopped"
                # Disable from runlevels
                if command -v chkconfig &>/dev/null; then
                    chkconfig edgedelta off 2>/dev/null || true
                elif command -v update-rc.d &>/dev/null; then
                    update-rc.d -f edgedelta remove 2>/dev/null || true
                fi
            else
                log_info "EdgeDelta init script not found"
            fi
            ;;
        *)
            log_warn "Unknown init system: $INIT_SYSTEM - attempting generic stop"
            pkill -f edgedelta 2>/dev/null || true
            ;;
    esac

    mark_step "stop_service"
}

remove_edgedelta() {
    if step_done "remove_edgedelta"; then
        log_skip "Remove EdgeDelta"
        return 0
    fi

    log_info "Removing EdgeDelta installation..."

    # Remove the install directory contents only (not the parent)
    if [[ -n "$INSTALL_PATH" && -d "$INSTALL_PATH" ]]; then
        log_info "Removing install directory: $INSTALL_PATH"
        rm -rf "$INSTALL_PATH"
        log_success "Install directory removed"
    else
        log_info "Install directory already removed: $INSTALL_PATH"
    fi

    # Remove service file(s)
    for path in "${SERVICE_FILE_PATHS[@]}"; do
        if [[ -f "$path" ]]; then
            log_info "Removing service file: $path"
            rm -f "$path"
            log_success "Service file removed"
        fi
    done

    # Remove override directory (Linux systemd only)
    if [[ -n "$OVERRIDE_DIR" && -d "$OVERRIDE_DIR" ]]; then
        log_info "Removing override directory: $OVERRIDE_DIR"
        rm -rf "$OVERRIDE_DIR"
        log_success "Override directory removed"
    fi

    # Remove SysVinit script if present
    if [[ -f "$SYSVINIT_SCRIPT" ]]; then
        log_info "Removing init script: $SYSVINIT_SCRIPT"
        rm -f "$SYSVINIT_SCRIPT"
        log_success "Init script removed"
    fi

    # Remove environment file if it's in an edgedelta-specific location
    if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
        if [[ "$ENV_FILE" == *edgedelta* ]]; then
            log_info "Removing environment file: $ENV_FILE"
            rm -f "$ENV_FILE"
            log_success "Environment file removed"
        fi
    fi

    # Remove common EdgeDelta directories (OS-specific paths)
    local dirs_to_remove=()
    case "$OS_TYPE" in
        linux)
            dirs_to_remove=(
                "/etc/edgedelta"
                "/var/log/edgedelta"
                "/var/lib/edgedelta"
            )
            ;;
        macos)
            dirs_to_remove=(
                "/usr/local/etc/edgedelta"
                "/usr/local/var/log/edgedelta"
                "/var/log/edgedelta"
                "$HOME/Library/Logs/edgedelta"
            )
            ;;
    esac

    for dir in "${dirs_to_remove[@]}"; do
        if [[ -d "$dir" ]]; then
            log_info "Removing directory: $dir"
            rm -rf "$dir"
        fi
    done

    # Reload init system
    case "$INIT_SYSTEM" in
        systemd)
            systemctl daemon-reload
            ;;
        launchd)
            # No reload needed for launchd
            ;;
    esac

    log_success "EdgeDelta removal complete"
    mark_step "remove_edgedelta"
}

# ─── Backup selection ─────────────────────────────────────────────────────────

# Calculate a coverage score for a backup directory
# Returns score via echo (0-5 based on files present)
score_backup() {
    local dir="$1"
    local score=0

    [[ -f "$dir/edgedelta.service" ]] && score=$((score + 1))
    [[ -f "$dir/environment" ]] && score=$((score + 1))
    [[ -d "$dir/overrides" && -n "$(ls -A "$dir/overrides" 2>/dev/null)" ]] && score=$((score + 1))
    [[ -f "$dir/apikey" || -f "$dir/apikey_from_env" || -f "$dir/apikey_from_service" ]] && score=$((score + 1))
    [[ -f "$dir/install_metadata.conf" ]] && score=$((score + 1))

    echo "$score"
}

# Automatically select the best backup based on file coverage.
# If multiple backups have the same score, the most recent one is chosen.
# Sets RESTORE_SUBDIR.
select_backup() {
    log_info "Scanning for available backups in $BACKUP_DIR ..."

    # Collect backup directories (sorted by name descending = most recent first)
    BACKUP_LIST=()
    while IFS= read -r dir; do
        BACKUP_LIST+=("$dir")
    done < <(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d | sort -r)

    if [[ ${#BACKUP_LIST[@]} -eq 0 ]]; then
        log_warn "No backups found in $BACKUP_DIR"
        RESTORE_SUBDIR=""
        return 1
    fi

    # Score each backup and find the best one
    # Since list is already sorted most-recent-first, first highest score wins ties
    local best_dir=""
    local best_score=-1
    local best_idx=0
    local idx=0

    declare -a scores=()
    for dir in "${BACKUP_LIST[@]}"; do
        local score
        score=$(score_backup "$dir")
        scores+=("$score")

        if (( score > best_score )); then
            best_score=$score
            best_dir="$dir"
            best_idx=$idx
        fi
        idx=$((idx + 1))
    done

    # Display available backups with scores
    echo ""
    echo "Available backups:"
    echo "──────────────────────────────────────────"

    idx=0
    for dir in "${BACKUP_LIST[@]}"; do
        local dirname
        dirname=$(basename "$dir")
        local score="${scores[$idx]}"
        local marker=""

        # Mark the auto-selected backup (unless -r flag forces prompt)
        if [[ "$dir" == "$best_dir" && "$ARG_FORCE_BACKUP_PROMPT" != true ]]; then
            marker=" ← auto-select (score: ${score}/5)"
        else
            marker="   (score: ${score}/5)"
        fi

        # Show metadata summary if available
        local saved_path="unknown"
        if [[ -f "$dir/install_metadata.conf" ]]; then
            saved_path=$(grep "^INSTALL_PATH=" "$dir/install_metadata.conf" 2>/dev/null | cut -d'=' -f2-)
            saved_path="${saved_path:-unknown}"
        fi

        local has_env="no"
        local has_overrides="no"
        local has_apikey="no"
        [[ -f "$dir/environment" ]] && has_env="yes"
        [[ -d "$dir/overrides" && -n "$(ls -A "$dir/overrides" 2>/dev/null)" ]] && has_overrides="yes"
        [[ -f "$dir/apikey" || -f "$dir/apikey_from_env" || -f "$dir/apikey_from_service" ]] && has_apikey="yes"

        echo "  $((idx + 1))) ${dirname}${marker}"
        echo "      path: ${saved_path}"
        echo "      env: ${has_env}  overrides: ${has_overrides}  apikey: ${has_apikey}"
        echo ""

        idx=$((idx + 1))
    done

    echo "──────────────────────────────────────────"
    echo ""

    # Check if backup selection prompt is forced via -r flag
    if [[ "$ARG_FORCE_BACKUP_PROMPT" == true ]]; then
        log_info "Backup selection prompt forced via -r flag"
        while true; do
            read -p "Select backup to restore from [1-${#BACKUP_LIST[@]}]: " choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#BACKUP_LIST[@]} )); then
                break
            fi
            log_warn "Invalid selection. Enter a number between 1 and ${#BACKUP_LIST[@]}"
        done
        RESTORE_SUBDIR="${BACKUP_LIST[$((choice - 1))]}"
        log_info "Selected backup: $(basename "$RESTORE_SUBDIR")"
        return 0
    fi

    # Auto-select the best backup
    RESTORE_SUBDIR="$best_dir"
    log_success "Auto-selected backup: $(basename "$RESTORE_SUBDIR") (score: ${best_score}/5)"

    # Offer to override if there are multiple backups
    if [[ ${#BACKUP_LIST[@]} -gt 1 ]]; then
        read -p "Use this backup? (Y/n) or enter number to choose different: " choice
        choice="${choice:-y}"

        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#BACKUP_LIST[@]} )); then
            RESTORE_SUBDIR="${BACKUP_LIST[$((choice - 1))]}"
            log_info "Selected backup: $(basename "$RESTORE_SUBDIR")"
        elif [[ "$choice" =~ ^[Nn]$ ]]; then
            while true; do
                read -p "Select backup to restore from [1-${#BACKUP_LIST[@]}]: " choice
                if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#BACKUP_LIST[@]} )); then
                    break
                fi
                log_warn "Invalid selection. Enter a number between 1 and ${#BACKUP_LIST[@]}"
            done
            RESTORE_SUBDIR="${BACKUP_LIST[$((choice - 1))]}"
            log_info "Selected backup: $(basename "$RESTORE_SUBDIR")"
        fi
    fi
}

# ─── Install path selection ───────────────────────────────────────────────────

# Prompt user to choose installation path. Sets TARGET_PATH.
# Skips prompting if the original path already contains "edgedelta".
select_install_path() {
    # Read saved metadata from the selected restore backup
    if [[ -f "$RESTORE_SUBDIR/install_metadata.conf" ]]; then
        source "$RESTORE_SUBDIR/install_metadata.conf"
    fi

    local original_path="${INSTALL_PATH:-/opt/edgedelta/agent}"
    local default_path="/opt/edgedelta/agent"
    local recommended_path=""

    # Check if install path was provided via command-line flag
    if [[ -n "$ARG_INSTALL_PATH" ]]; then
        TARGET_PATH="$ARG_INSTALL_PATH"
        log_info "Using command-line specified path: $TARGET_PATH"
        INSTALL_PATH="$TARGET_PATH"
        return 0
    fi

    # Check if we should force the prompt (even if path has edgedelta)
    local force_prompt="$ARG_FORCE_PATH_PROMPT"

    # Check if the original path contains "edgedelta" directory
    if [[ "$original_path" == *"/edgedelta/"* || "$original_path" == *"/edgedelta" ]]; then
        if [[ "$force_prompt" != true ]]; then
            # Path already has edgedelta — no need to prompt, use original path
            TARGET_PATH="$original_path"
            log_info "Using previous installation path: $TARGET_PATH"
            INSTALL_PATH="$TARGET_PATH"
            return 0
        fi
        # Force prompt is set, fall through to path selection
        log_info "Path prompt forced via -p flag"
    fi

    # Original path does not have "edgedelta" or prompt was forced
    # Build a recommended path by appending "edgedelta" to the original path
    # This preserves mount points while adding a dedicated edgedelta directory
    recommended_path="${original_path}/edgedelta"

    echo ""
    echo "Installation Path Selection"
    echo "──────────────────────────────────────────"
    echo ""

    if [[ "$original_path" != *"/edgedelta/"* && "$original_path" != *"/edgedelta" ]]; then
        log_warn "Previous path does not include an 'edgedelta' directory"
        echo ""
    fi

    echo "Previous installation path: $original_path"
    echo ""
    echo "  1) Use previous path:  $original_path"
    echo "  2) Use fixed path:     $recommended_path  (Recommended)"
    echo "  3) Use default path:   $default_path  (Recommended)"
    echo "  4) Enter custom path"
    echo ""

    local choice
    while true; do
        read -p "Select installation path [1-4]: " choice
        case "$choice" in
            1)
                TARGET_PATH="$original_path"
                break
                ;;
            2)
                TARGET_PATH="$recommended_path"
                break
                ;;
            3)
                TARGET_PATH="$default_path"
                break
                ;;
            4)
                read -p "Enter custom installation path: " TARGET_PATH
                if [[ -z "$TARGET_PATH" ]]; then
                    log_warn "Path cannot be empty"
                    continue
                fi
                break
                ;;
            *)
                log_warn "Invalid selection. Enter 1, 2, 3, or 4"
                ;;
        esac
    done

    echo ""
    log_info "Selected installation path: $TARGET_PATH"

    # Update INSTALL_PATH so restore functions can use it
    INSTALL_PATH="$TARGET_PATH"
}

# ─── Install / restore functions ──────────────────────────────────────────────

install_edgedelta() {
    log_info "Installing latest EdgeDelta agent..."

    # Check if API key was provided via command-line flag
    if [[ -n "$ARG_API_KEY" ]]; then
        API_KEY="$ARG_API_KEY"
        log_info "Using API key provided via command-line"
    else
        # Get API key from backup (prefer the apikey file from install path)
        if [[ -f "$RESTORE_SUBDIR/apikey" ]]; then
            API_KEY=$(cat "$RESTORE_SUBDIR/apikey")
            log_info "Using API key from backup"
        elif [[ -f "$RESTORE_SUBDIR/apikey_from_env" ]]; then
            API_KEY=$(cat "$RESTORE_SUBDIR/apikey_from_env")
            log_info "Using API key from backup (environment)"
        elif [[ -f "$RESTORE_SUBDIR/apikey_from_service" ]]; then
            API_KEY=$(cat "$RESTORE_SUBDIR/apikey_from_service")
            log_info "Using API key from backup (service)"
        fi
    fi

    if [[ -z "$API_KEY" ]]; then
        log_warn "No API key found in backup or command-line"
        read -p "Enter EdgeDelta API key: " API_KEY
        if [[ -z "$API_KEY" ]]; then
            log_error "API key is required for installation"
            return 1
        fi
    fi

    # Clean up ALL existing edgedelta files before running installer
    # (installer may fail if these already exist)
    log_info "Cleaning up existing EdgeDelta files before install..."

    # Remove all edgedelta-related files from common locations
    find /etc -name '*edgedelta*' -exec rm -rf '{}' + 2>/dev/null || true
    find /var/log -name '*edgedelta*' -exec rm -rf '{}' + 2>/dev/null || true
    find /usr/local/etc -name '*edgedelta*' -exec rm -rf '{}' + 2>/dev/null || true
    find /usr/local/var -name '*edgedelta*' -exec rm -rf '{}' + 2>/dev/null || true

    # Also clean up systemd-specific locations
    for path in "${SERVICE_FILE_PATHS[@]}"; do
        if [[ -f "$path" ]]; then
            log_info "Removing existing service file: $path"
            rm -f "$path"
        fi
    done
    # Remove symlink from multi-user.target.wants
    if [[ -e "/etc/systemd/system/multi-user.target.wants/edgedelta.service" ]]; then
        log_info "Removing existing service symlink"
        rm -f "/etc/systemd/system/multi-user.target.wants/edgedelta.service"
    fi
    # Reload systemd to pick up the removals
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        systemctl daemon-reload 2>/dev/null || true
    fi

    log_success "Cleanup complete"

    # Detect architecture for version-specific downloads
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="arm64" ;;
    esac

    # Determine OS type for download URL
    local os_label="linux"
    if [[ "$OS_TYPE" == "macos" ]]; then
        os_label="macosx"
    fi

    if [[ -n "$ARG_AGENT_VERSION" ]]; then
        # Version-specific install: download directly from versioned URL
        # (the generic install.sh ignores the VERSION variable)
        local version_url="https://release.edgedelta.com/v${ARG_AGENT_VERSION}/edgedelta-${os_label}-${arch}.sh"
        log_info "Installing EdgeDelta agent version: $ARG_AGENT_VERSION"
        log_info "Downloading from: $version_url"

        INSTALL_SCRIPT=$(mktemp)
        curl -sL "$version_url" -o "$INSTALL_SCRIPT"
        chmod +x "$INSTALL_SCRIPT"

        log_info "Running version-specific installer..."
        ED_API_KEY="$API_KEY" ED_INSTALL_PATH="$TARGET_PATH" bash "$INSTALL_SCRIPT"
    else
        # Latest version: use the generic install.sh
        log_info "Installing latest EdgeDelta agent version"
        log_info "Downloading EdgeDelta install script..."

        INSTALL_SCRIPT=$(mktemp)
        curl -sL https://release.edgedelta.com/release/install.sh -o "$INSTALL_SCRIPT"
        chmod +x "$INSTALL_SCRIPT"

        # Build environment variables for the installer
        local install_env="ED_API_KEY=\"$API_KEY\""
        if [[ "$TARGET_PATH" != "/opt/edgedelta/agent" ]]; then
            install_env="$install_env ED_INSTALL_PATH=\"$TARGET_PATH\""
        fi

        log_info "Running EdgeDelta installer..."
        eval "$install_env bash \"$INSTALL_SCRIPT\""
    fi

    rm -f "$INSTALL_SCRIPT"

    # Check if binary was actually installed
    if [[ ! -f "${TARGET_PATH}/edgedelta" ]]; then
        log_warn "EdgeDelta binary not found after installer ran at: ${TARGET_PATH}/edgedelta"
        log_info "Attempting platform-specific installer as fallback..."

        # Detect architecture
        local arch
        arch=$(uname -m)
        case "$arch" in
            x86_64)  arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l)  arch="arm64" ;;
        esac
        log_info "Detected architecture: $(uname -m) -> $arch"

        # Determine version to download
        local version="${ARG_AGENT_VERSION:-latest}"
        local download_url=""

        # EdgeDelta releases are .sh installer scripts
        if [[ "$version" == "latest" ]]; then
            download_url="https://release.edgedelta.com/release/edgedelta-linux-${arch}.sh"
        else
            download_url="https://release.edgedelta.com/v${version}/edgedelta-linux-${arch}.sh"
        fi

        log_info "Downloading installer from: $download_url"

        # Download the platform-specific installer
        local tmp_installer=$(mktemp)
        local http_code
        http_code=$(curl -sL -w "%{http_code}" "$download_url" -o "$tmp_installer" 2>/dev/null)

        if [[ "$http_code" == "200" && -s "$tmp_installer" ]]; then
            log_info "Download successful (HTTP $http_code)"

            # Verify it's a shell script
            if head -1 "$tmp_installer" | grep -q "^#!"; then
                chmod +x "$tmp_installer"
                log_info "Running platform-specific installer..."

                # Run the installer with API key and install path
                ED_API_KEY="$API_KEY" ED_INSTALL_PATH="$TARGET_PATH" bash "$tmp_installer"

                rm -f "$tmp_installer"

                # Check if binary was installed this time
                if [[ -f "${TARGET_PATH}/edgedelta" ]]; then
                    log_success "Binary installed successfully via platform-specific installer"

                    # Set correct SELinux context on install path
                    if [[ "$HAS_SELINUX" == true ]]; then
                        log_info "Restoring SELinux file contexts..."
                        restorecon -Rv "${TARGET_PATH}" 2>/dev/null || \
                        chcon -t bin_t "${TARGET_PATH}/edgedelta" 2>/dev/null || true
                    fi
                else
                    log_error "Platform-specific installer also failed to install binary"
                    log_error "Please check network connectivity and try manually:"
                    log_error "  curl -sL $download_url | ED_API_KEY=<key> ED_INSTALL_PATH=$TARGET_PATH bash"
                    return 1
                fi
            else
                log_error "Downloaded file is not a valid shell script"
                log_error "First line: $(head -1 "$tmp_installer")"
                rm -f "$tmp_installer"
                return 1
            fi
        else
            log_error "Failed to download EdgeDelta installer (HTTP $http_code)"
            log_error "URL: $download_url"
            rm -f "$tmp_installer"
            return 1
        fi
    fi

    # Check if service file was created (SELinux on RHEL 9 may block this)
    local service_created=false
    for path in "${SERVICE_FILE_PATHS[@]}"; do
        if [[ -f "$path" ]]; then
            service_created=true
            break
        fi
    done

    if [[ "$service_created" == false && "$INIT_SYSTEM" == "systemd" ]]; then
        log_warn "Installer did not create service file (likely blocked by SELinux)"
        log_info "Restoring service file from backup..."

        if [[ -f "$RESTORE_SUBDIR/edgedelta.service" ]]; then
            # Copy backed-up service file to systemd directory
            local service_dest="/etc/systemd/system/edgedelta.service"
            cp "$RESTORE_SUBDIR/edgedelta.service" "$service_dest"

            # Update paths in the service file if install path changed
            if [[ -n "$TARGET_PATH" ]]; then
                sed -i "s|ExecStart=.*|ExecStart=${TARGET_PATH}/edgedelta|" "$service_dest"
                sed -i "s|WorkingDirectory=.*|WorkingDirectory=${TARGET_PATH}|" "$service_dest"
            fi

            # Set correct SELinux context for systemd unit file
            if [[ "$HAS_SELINUX" == true ]]; then
                log_info "Setting SELinux context on service file..."
                restorecon -v "$service_dest" 2>/dev/null || \
                chcon -t systemd_unit_file_t "$service_dest" 2>/dev/null || \
                log_warn "Could not set SELinux context on service file"
            fi

            chmod 755 "$service_dest"
            log_success "Service file restored to: $service_dest"
        else
            log_error "No backup service file available to restore"
            log_error "You may need to manually create /etc/systemd/system/edgedelta.service"
        fi
    fi

    log_success "EdgeDelta agent installed"
}

update_service_file_paths() {
    # Update the service file to ensure paths are correct after installation
    # This handles cases where the install path was changed

    if [[ "$OS_TYPE" != "linux" || "$INIT_SYSTEM" != "systemd" ]]; then
        # Only applicable to Linux systemd
        return 0
    fi

    local service_file
    service_file=$(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -name "edgedelta.service" 2>/dev/null | head -1)

    if [[ -z "$service_file" ]]; then
        log_warn "Service file not found, skipping path update"
        return 0
    fi

    log_info "Verifying service file paths..."

    # Check if ExecStart points to the correct binary
    local current_exec
    current_exec=$(grep -E "^ExecStart=" "$service_file" 2>/dev/null | head -1 | cut -d'=' -f2- | awk '{print $1}')
    local expected_binary="${TARGET_PATH}/edgedelta"

    if [[ -n "$current_exec" && "$current_exec" != "$expected_binary" ]]; then
        log_info "Updating ExecStart path: $current_exec -> $expected_binary"
        # Update the binary path in ExecStart (preserve any arguments)
        sed -i "s|^ExecStart=.*|ExecStart=${expected_binary}|" "$service_file"
        log_success "Service file ExecStart updated"
    fi

    # Check if WorkingDirectory points to the correct path
    local current_workdir
    current_workdir=$(grep -E "^WorkingDirectory=" "$service_file" 2>/dev/null | head -1 | cut -d'=' -f2-)

    if [[ -n "$current_workdir" && "$current_workdir" != "$TARGET_PATH" ]]; then
        log_info "Updating WorkingDirectory: $current_workdir -> $TARGET_PATH"
        sed -i "s|^WorkingDirectory=.*|WorkingDirectory=${TARGET_PATH}|" "$service_file"
        log_success "Service file WorkingDirectory updated"
    elif [[ -z "$current_workdir" ]]; then
        # Add WorkingDirectory if not present
        sed -i "/^\[Service\]/a WorkingDirectory=${TARGET_PATH}" "$service_file"
        log_info "Added WorkingDirectory to service file"
    fi
}

restore_environment_file() {
    if [[ -f "$RESTORE_SUBDIR/environment" ]]; then
        log_info "Restoring environment file..."

        # Get original paths from backup metadata
        local original_env_path=""
        local original_install_path=""

        if [[ -f "$RESTORE_SUBDIR/environment.path" ]]; then
            original_env_path=$(cat "$RESTORE_SUBDIR/environment.path")
        fi

        if [[ -f "$RESTORE_SUBDIR/install_metadata.conf" ]]; then
            original_install_path=$(grep "^INSTALL_PATH=" "$RESTORE_SUBDIR/install_metadata.conf" 2>/dev/null | cut -d'=' -f2-)
        fi

        # Determine where to place the environment file
        # If the install path changed, we need to adjust paths accordingly
        if [[ -n "$original_env_path" ]]; then
            if [[ -n "$original_install_path" && "$original_env_path" == "$original_install_path"* ]]; then
                # Environment file was inside the install directory
                # Adjust to new install path
                local relative_path="${original_env_path#$original_install_path}"
                RESTORE_ENV_PATH="${TARGET_PATH}${relative_path}"
                log_info "Adjusting environment path to new install location"
            elif [[ "$original_env_path" == */edgedelta/* ]]; then
                # Environment file was in an edgedelta directory outside install path
                # Keep it there
                RESTORE_ENV_PATH="$original_env_path"
            else
                # Use original path as-is
                RESTORE_ENV_PATH="$original_env_path"
            fi
        else
            # Default to /etc/edgedelta/environment
            RESTORE_ENV_PATH="/etc/edgedelta/environment"
        fi

        log_info "Environment file destination: $RESTORE_ENV_PATH"

        mkdir -p "$(dirname "$RESTORE_ENV_PATH")"
        cp "$RESTORE_SUBDIR/environment" "$RESTORE_ENV_PATH"
        chmod 600 "$RESTORE_ENV_PATH"

        # Update service file to reference the environment file (Linux systemd only)
        if [[ "$OS_TYPE" == "linux" && "$INIT_SYSTEM" == "systemd" ]]; then
            local new_service_file
            new_service_file=$(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -name "edgedelta.service" 2>/dev/null | head -1)

            if [[ -n "$new_service_file" ]]; then
                if ! grep -q "^EnvironmentFile=" "$new_service_file"; then
                    sed -i "/^\[Service\]/a EnvironmentFile=-${RESTORE_ENV_PATH}" "$new_service_file"
                    log_info "Added EnvironmentFile to service file"
                else
                    sed -i "s|^EnvironmentFile=.*|EnvironmentFile=-${RESTORE_ENV_PATH}|" "$new_service_file"
                    log_info "Updated EnvironmentFile in service file"
                fi
            fi
        fi

        log_success "Environment file restored to: $RESTORE_ENV_PATH"
    fi
}

restore_override_files() {
    if [[ -d "$RESTORE_SUBDIR/overrides" ]]; then
        log_info "Restoring override files..."

        if [[ -f "$RESTORE_SUBDIR/overrides.path" ]]; then
            RESTORE_OVERRIDE_DIR=$(cat "$RESTORE_SUBDIR/overrides.path")
        else
            RESTORE_OVERRIDE_DIR="/etc/systemd/system/edgedelta.service.d"
        fi

        mkdir -p "$RESTORE_OVERRIDE_DIR"
        chmod 751 "$RESTORE_OVERRIDE_DIR"

        for override_file in "$RESTORE_SUBDIR/overrides"/*.conf; do
            if [[ -f "$override_file" ]]; then
                cp "$override_file" "$RESTORE_OVERRIDE_DIR/"
                # Systemd unit files must be world-readable (644)
                chmod 644 "$RESTORE_OVERRIDE_DIR/$(basename "$override_file")"
                log_info "Restored: $(basename "$override_file")"
            fi
        done

        log_success "Override files restored to: $RESTORE_OVERRIDE_DIR"
    fi
}

# ─── Security modules ─────────────────────────────────────────────────────────

configure_security() {
    # Only applicable to Linux
    if [[ "$OS_TYPE" != "linux" ]]; then
        return 0
    fi

    local target_path="${INSTALL_PATH:-/opt/edgedelta/agent}"

    # Configure SELinux if enabled
    if [[ "$HAS_SELINUX" == true ]]; then
        log_info "Configuring SELinux for EdgeDelta..."

        local selinux_status
        selinux_status=$(getenforce 2>/dev/null || echo "Disabled")

        if [[ "$selinux_status" != "Disabled" ]]; then
            log_info "SELinux is $selinux_status - restoring correct file contexts..."

            # Use restorecon to set the correct SELinux context for the install path
            # This sets bin_t on the binary (required for systemd to execute it)
            if [[ -d "${target_path}" ]]; then
                log_info "Running restorecon on ${target_path}..."
                restorecon -Rv "${target_path}" 2>/dev/null || {
                    log_warn "restorecon failed, trying chcon..."
                    if [[ -f "${target_path}/edgedelta" ]]; then
                        chcon -t bin_t "${target_path}/edgedelta" 2>/dev/null || true
                    fi
                }
                log_success "SELinux file contexts restored for EdgeDelta"
            else
                log_warn "EdgeDelta install path not found at ${target_path}"
            fi
        fi
    fi

    # Note: AppArmor typically doesn't need special configuration for EdgeDelta
    # but we log if it's present for awareness
    if [[ "$HAS_APPARMOR" == true ]]; then
        log_info "AppArmor is enabled (no special configuration needed for EdgeDelta)"
    fi
}

# ─── Finalize ─────────────────────────────────────────────────────────────────

finalize_installation() {
    log_info "Finalizing installation..."

    case "$INIT_SYSTEM" in
        systemd)
            # Clean up any non-symlink service files in target.wants directories
            # (systemctl enable requires these to be symlinks, not copies)
            local wants_file="/etc/systemd/system/multi-user.target.wants/edgedelta.service"
            if [[ -f "$wants_file" && ! -L "$wants_file" ]]; then
                log_info "Removing non-symlink service file from multi-user.target.wants"
                rm -f "$wants_file"
            fi

            systemctl daemon-reload
            systemctl enable edgedelta

            configure_security

            systemctl start edgedelta

            sleep 2
            if systemctl is-active --quiet edgedelta; then
                log_success "EdgeDelta service is running"
            else
                log_warn "EdgeDelta service may not have started correctly"
                log_info "Check status with: systemctl status edgedelta"

                if [[ "$HAS_SELINUX" == true ]]; then
                    local selinux_status
                    selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
                    if [[ "$selinux_status" == "Enforcing" ]]; then
                        log_warn "SELinux is enforcing - check for denials: ausearch -m avc -ts recent | grep edgedelta"
                    fi
                fi
            fi
            ;;
        launchd)
            local plist_path="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"

            if [[ -f "$plist_path" ]]; then
                # Load the service
                launchctl load -w "$plist_path" 2>/dev/null || \
                launchctl bootstrap system "$plist_path" 2>/dev/null || true

                sleep 2
                if launchctl list | grep -q "$LAUNCHD_LABEL" 2>/dev/null; then
                    log_success "EdgeDelta service is running"
                else
                    log_warn "EdgeDelta service may not have started correctly"
                    log_info "Check status with: launchctl list | grep edgedelta"
                fi
            else
                log_warn "LaunchDaemon plist not found at $plist_path"
            fi
            ;;
        sysvinit)
            if [[ -f "$SYSVINIT_SCRIPT" ]]; then
                # Enable the service
                if command -v chkconfig &>/dev/null; then
                    chkconfig edgedelta on 2>/dev/null || true
                elif command -v update-rc.d &>/dev/null; then
                    update-rc.d edgedelta defaults 2>/dev/null || true
                fi

                configure_security

                "$SYSVINIT_SCRIPT" start

                sleep 2
                if "$SYSVINIT_SCRIPT" status &>/dev/null; then
                    log_success "EdgeDelta service is running"
                else
                    log_warn "EdgeDelta service may not have started correctly"
                    log_info "Check status with: $SYSVINIT_SCRIPT status"
                fi
            else
                log_warn "Init script not found at $SYSVINIT_SCRIPT"
            fi
            ;;
        *)
            log_warn "Unknown init system: $INIT_SYSTEM"
            log_info "You may need to start EdgeDelta manually"
            ;;
    esac
}

# ─── Summary ──────────────────────────────────────────────────────────────────

print_backup_summary() {
    echo ""
    echo "=========================================="
    echo "Backup Summary"
    echo "=========================================="
    echo "Backup location: $BACKUP_SUBDIR"
    echo ""
    echo "Files backed up:"
    ls -la "$BACKUP_SUBDIR"
    echo ""

    if [[ -f "$BACKUP_SUBDIR/install_metadata.conf" ]]; then
        echo "Installation metadata:"
        cat "$BACKUP_SUBDIR/install_metadata.conf"
    fi
    echo "=========================================="
}

# ─── Clean up state file on successful completion ─────────────────────────────

cleanup_state() {
    if [[ -f "$STATE_FILE" ]]; then
        rm -f "$STATE_FILE"
        log_info "State file cleaned up"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    # Parse command-line arguments first
    parse_args "${ORIGINAL_ARGS[@]}"

    echo ""
    echo "=========================================="
    echo "EdgeDelta Uninstall/Reinstall Script"
    echo "=========================================="

    # Display detected OS information
    print_os_info

    # Display any command-line overrides
    if [[ -n "$ARG_API_KEY" || -n "$ARG_INSTALL_PATH" || "$ARG_FORCE_PATH_PROMPT" == true || "$ARG_FORCE_BACKUP_PROMPT" == true || -n "$ARG_AGENT_VERSION" || "$ARG_RESTORE_MODE" == true ]]; then
        echo ""
        echo "Command-line overrides:"
        echo "──────────────────────────────────────────"
        [[ "$ARG_RESTORE_MODE" == true ]] && echo "  Mode:           RESTORE ONLY"
        [[ -n "$ARG_API_KEY" ]] && echo "  API Key:        (provided, ${#ARG_API_KEY} chars)"
        [[ -n "$ARG_INSTALL_PATH" ]] && echo "  Install Path:   $ARG_INSTALL_PATH"
        [[ "$ARG_FORCE_PATH_PROMPT" == true ]] && echo "  Path Prompt:    forced"
        [[ "$ARG_FORCE_BACKUP_PROMPT" == true ]] && echo "  Backup Prompt:  forced"
        [[ -n "$ARG_AGENT_VERSION" ]] && echo "  Agent Version:  $ARG_AGENT_VERSION"
        echo "──────────────────────────────────────────"
    fi

    # Check OS is supported
    check_os_supported

    # Check for root/sudo
    check_root

    # Ensure base backup dir exists for state file
    mkdir -p "$BACKUP_DIR"

    # ── Restore-only mode ──────────────────────────────────────────────────
    if [[ "$ARG_RESTORE_MODE" == true ]]; then
        echo ""
        log_info "=== RESTORE MODE ==="
        log_info "Skipping backup and uninstall phases"
        echo ""

        # Select backup to restore from
        select_backup
        if [[ -z "$RESTORE_SUBDIR" ]]; then
            log_error "No backup found to restore from"
            log_error "Run the script without -restore first to create a backup"
            exit 1
        fi

        # Let the user choose the installation path
        select_install_path

        # Run install and restore
        install_edgedelta
        update_service_file_paths
        restore_environment_file
        restore_override_files
        finalize_installation

        echo ""
        log_success "EdgeDelta restore complete!"
        echo ""
        echo "Useful commands:"
        echo "  Check status:  systemctl status edgedelta"
        echo "  View logs:     journalctl -u edgedelta -f"
        echo "  Restart:       systemctl restart edgedelta"
        echo ""

        exit 0
    fi

    # Check for a previous incomplete run
    detect_previous_run

    # Set up backup subdir for a fresh run
    if [[ "$RESUMING" != true ]]; then
        BACKUP_SUBDIR="${BACKUP_DIR}/$(date +%Y%m%d_%H%M%S)"
    fi

    find_service_file
    parse_service_file

    echo ""
    echo "Current EdgeDelta Configuration:"
    echo "  Service File:       $SERVICE_FILE"
    echo "  Install Path:       $INSTALL_PATH"
    echo "  Environment File:   ${ENV_FILE:-Not configured}"
    if [[ -n "$OVERRIDE_DIR" ]]; then
        echo "  Override Directory: $OVERRIDE_DIR"
    fi
    echo ""

    if [[ "$RESUMING" != true ]]; then
        read -p "Proceed with backup and uninstall? (y/N): " CONFIRM_UNINSTALL
        if [[ ! "$CONFIRM_UNINSTALL" =~ ^[Yy]$ ]]; then
            log_info "Aborted by user"
            exit 0
        fi
    else
        log_info "Resuming from previous run..."
    fi

    # ── Backup phase ──────────────────────────────────────────────────────
    echo ""
    log_info "=== BACKUP PHASE ==="
    create_backup_dir
    backup_service_file
    backup_environment_file
    backup_override_files
    backup_api_key
    store_install_metadata

    print_backup_summary

    # ── Uninstall phase ───────────────────────────────────────────────────
    echo ""
    log_info "=== UNINSTALL PHASE ==="
    stop_service
    remove_edgedelta

    log_success "EdgeDelta has been uninstalled"
    log_info "Backups are stored in: $BACKUP_SUBDIR"

    # ── Reinstall prompt ──────────────────────────────────────────────────
    echo ""
    read -p "Would you like to install the newest version of EdgeDelta? (y/N): " CONFIRM_REINSTALL

    if [[ "$CONFIRM_REINSTALL" =~ ^[Yy]$ ]]; then
        echo ""
        log_info "=== REINSTALL PHASE ==="

        # Let the user pick which backup to restore configs from
        select_backup
        if [[ -z "$RESTORE_SUBDIR" ]]; then
            log_error "No backup selected, cannot restore configuration"
            exit 1
        fi

        # Let the user choose the installation path
        select_install_path

        install_edgedelta
        update_service_file_paths
        restore_environment_file
        restore_override_files
        finalize_installation

        echo ""
        log_success "EdgeDelta reinstallation complete!"
        echo ""
        echo "Useful commands:"
        echo "  Check status:  systemctl status edgedelta"
        echo "  View logs:     journalctl -u edgedelta -f"
        echo "  Restart:       systemctl restart edgedelta"
        echo ""
    else
        echo ""
        log_info "Skipping reinstallation"
        echo ""
        echo "To reinstall later, you can use the backup files in:"
        echo "  $BACKUP_SUBDIR"
        echo ""
        echo "Manual reinstall command:"
        echo "  curl -sL https://release.edgedelta.com/release/install.sh | ED_API_KEY=<your-key> bash"
        echo ""
    fi

    # All done — clean up state file so next run starts fresh
    cleanup_state
}

main "$@"

#!/bin/bash

# Ubuntu Pro extension installer script (TEST VERSION)
# Downloads and installs the ubuntu_pro extension from tux234's fork/branch
# FOR TESTING ONLY - Use before PR is merged and releases are available
#
# This version downloads directly from the GitHub branch instead of releases
#
# Usage:
#   sudo ./install-ubuntu-pro-extension-test.sh

set -e  # Exit on any error

# Variables for TEST deployment
GITHUB_USER="tux234"
GITHUB_REPO="fleet-extensions"
GITHUB_BRANCH="tux234-add-ubuntu-pro"
EXTENSION_DIR="/var/fleetd/extensions"
OSQUERY_DIR="/etc/osquery"
EXTENSIONS_LOAD_FILE="$OSQUERY_DIR/extensions.load"
BACKUP_PATH=""
AUTO_INSTALL_DEPS=${AUTO_INSTALL_DEPS:-true}

echo "============================================"
echo "Ubuntu Pro Extension Installer (TEST MODE)"
echo "============================================"
echo "Source: https://github.com/$GITHUB_USER/$GITHUB_REPO"
echo "Branch: $GITHUB_BRANCH"
echo "============================================"

# Function to log messages with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "Error: This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to check if running on Ubuntu
check_ubuntu() {
    log "Checking if running on Ubuntu..."

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            log "Ubuntu detected: $PRETTY_NAME"
            return 0
        else
            log "Error: This script is designed for Ubuntu. Detected: $PRETTY_NAME"
            exit 1
        fi
    elif command -v lsb_release &> /dev/null; then
        local distro
        distro=$(lsb_release -si)
        if [[ "$distro" == "Ubuntu" ]]; then
            local version
            version=$(lsb_release -sd)
            log "Ubuntu detected: $version"
            return 0
        else
            log "Error: This script is designed for Ubuntu. Detected: $distro"
            exit 1
        fi
    else
        log "Error: Cannot determine Linux distribution"
        exit 1
    fi
}

# Function to detect architecture and set extension name
detect_architecture() {
    log "Detecting system architecture..."

    local arch
    arch=$(uname -m)

    case "$arch" in
        "x86_64")
            EXTENSION_NAME="ubuntu_pro-amd64.ext"
            log "Architecture detected: amd64 (x86_64)"
            ;;
        "aarch64"|"arm64")
            EXTENSION_NAME="ubuntu_pro-arm64.ext"
            log "Architecture detected: arm64 (aarch64)"
            ;;
        *)
            log "Error: Unsupported architecture: $arch"
            log "This script supports amd64 (x86_64) and arm64 (aarch64) only"
            exit 1
            ;;
    esac

    EXTENSION_PATH="$EXTENSION_DIR/$EXTENSION_NAME"
    BACKUP_PATH="$EXTENSION_PATH.backup.$(date +%Y%m%d_%H%M%S)"
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        log "curl not found, attempting to install..."
        log "Updating package lists..."

        if apt update; then
            log "Package lists updated successfully"
        else
            log "Warning: Failed to update package lists, proceeding with installation attempt"
        fi

        log "Installing curl..."
        if apt install -y curl; then
            log "curl installed successfully"
        else
            log "Error: Failed to install curl"
            log "Please install curl manually: sudo apt update && sudo apt install curl"
            exit 1
        fi

        if ! command -v curl &> /dev/null; then
            log "Error: curl installation appears to have failed"
            exit 1
        fi
    else
        log "curl is already installed"
    fi

    # Check if ubuntu-advantage-tools is installed
    if ! command -v pro &> /dev/null; then
        if [[ "$AUTO_INSTALL_DEPS" == "true" ]]; then
            log "ubuntu-advantage-tools not found, installing..."
            log "Updating package lists..."

            if apt update; then
                log "Package lists updated successfully"
            else
                log "Warning: Failed to update package lists, proceeding with installation attempt"
            fi

            log "Installing ubuntu-advantage-tools..."
            if apt install -y ubuntu-advantage-tools; then
                log "ubuntu-advantage-tools installed successfully"
            else
                log "Error: Failed to install ubuntu-advantage-tools"
                log "Please install manually: sudo apt update && sudo apt install ubuntu-advantage-tools"
                exit 1
            fi

            if ! command -v pro &> /dev/null; then
                log "Error: ubuntu-advantage-tools installation appears to have failed"
                exit 1
            fi
        else
            log "ERROR: ubuntu-advantage-tools not found and AUTO_INSTALL_DEPS=false"
            log "The extension requires the 'pro' command to function"
            log "Install with: sudo apt update && sudo apt install ubuntu-advantage-tools"
            exit 1
        fi
    else
        log "ubuntu-advantage-tools is installed"
    fi

    log "Prerequisites check completed"
}

# Function to create directory with proper ownership
create_directory() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        log "Creating directory: $dir"
        mkdir -p "$dir"
        chown root:root "$dir"
        chmod 755 "$dir"
        log "Directory created with proper permissions"
    else
        log "Directory already exists: $dir"
        chown root:root "$dir"
        chmod 755 "$dir"
    fi
}

# Function to backup existing extension
backup_existing() {
    if [[ -f "$EXTENSION_PATH" ]]; then
        log "Backing up existing extension to: $BACKUP_PATH"
        cp "$EXTENSION_PATH" "$BACKUP_PATH"
        log "Backup completed"
    fi
}

# Function to validate downloaded file
validate_download() {
    local file_path="$1"

    log "Validating downloaded file..."

    # Check if file exists and is not empty
    if [[ ! -f "$file_path" ]]; then
        log "Error: Downloaded file not found"
        return 1
    fi

    if [[ ! -s "$file_path" ]]; then
        log "Error: Downloaded file is empty"
        return 1
    fi

    # Check if file is executable format (basic check)
    local file_type
    file_type=$(file "$file_path" 2>/dev/null || echo "unknown")
    log "File type: $file_type"

    # For Linux, check if it's an ELF executable
    if [[ "$file_type" == *"ELF"* ]] || [[ "$file_type" == *"executable"* ]]; then
        log "File validation passed"
        return 0
    else
        log "Warning: File may not be a valid executable. Proceeding anyway..."
        return 0
    fi
}

# Function to download from GitHub branch (RAW file)
download_from_branch() {
    log "Downloading from GitHub branch (TEST MODE)..."
    log "Source: $GITHUB_USER/$GITHUB_REPO @ $GITHUB_BRANCH"

    # Create temporary file for download
    local temp_file
    temp_file=$(mktemp)

    # Construct raw GitHub URL for branch
    # Format: https://raw.githubusercontent.com/USER/REPO/BRANCH/path/to/file
    local download_url="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$GITHUB_BRANCH/ubuntu_pro/$EXTENSION_NAME"

    log "Download URL: $download_url"
    log "Downloading..."

    if curl -L --progress-bar --fail -o "$temp_file" "$download_url"; then
        log "Download successful"
    else
        log "Error: Download failed"
        log ""
        log "Possible reasons:"
        log "  1. Binary not built yet - run 'make build' in ubuntu_pro/ directory"
        log "  2. Binary not committed to git - run 'git add ubuntu_pro/*.ext && git commit && git push'"
        log "  3. Branch name is wrong - verify branch is '$GITHUB_BRANCH'"
        log ""
        log "To build the binary locally:"
        log "  cd /path/to/fleet-extensions/ubuntu_pro"
        log "  make build"
        log "  git add ubuntu_pro-amd64.ext ubuntu_pro-arm64.ext"
        log "  git commit -m 'Add compiled binaries'"
        log "  git push origin $GITHUB_BRANCH"
        rm -f "$temp_file"
        exit 1
    fi

    # Validate the download
    if validate_download "$temp_file"; then
        # Move to final location
        mv "$temp_file" "$EXTENSION_PATH"
        log "File moved to final location: $EXTENSION_PATH"
    else
        log "Error: File validation failed"
        rm -f "$temp_file"
        exit 1
    fi
}

# Function to make the extension executable and set proper ownership
setup_file_permissions() {
    log "Setting up file permissions..."
    chown root:root "$EXTENSION_PATH"
    chmod 755 "$EXTENSION_PATH"
    log "File permissions configured (owner: root:root, mode: 755)"
}

# Function to handle extensions.load file
setup_extensions_load() {
    log "Configuring extensions.load file..."

    # Create osquery directory if it doesn't exist
    if [[ ! -d "$OSQUERY_DIR" ]]; then
        log "Creating osquery directory: $OSQUERY_DIR"
        mkdir -p "$OSQUERY_DIR"
        chown root:root "$OSQUERY_DIR"
        chmod 755 "$OSQUERY_DIR"
    fi

    # Create extensions.load if it doesn't exist
    if [[ ! -f "$EXTENSIONS_LOAD_FILE" ]]; then
        log "Creating new extensions.load file"
        touch "$EXTENSIONS_LOAD_FILE"
        chown root:root "$EXTENSIONS_LOAD_FILE"
        chmod 644 "$EXTENSIONS_LOAD_FILE"
    fi

    # Remove any existing ubuntu_pro entries to avoid duplicates
    if grep -q "ubuntu_pro.*\.ext" "$EXTENSIONS_LOAD_FILE"; then
        log "Removing existing ubuntu_pro extension entries"
        sed -i '/ubuntu_pro.*\.ext/d' "$EXTENSIONS_LOAD_FILE"
    fi

    # Add the extension path
    log "Adding extension to extensions.load"
    echo "$EXTENSION_PATH" >> "$EXTENSIONS_LOAD_FILE"

    log "extensions.load configuration completed"
}

# Function to restart Orbit (Fleet's osquery wrapper)
restart_orbit() {
    log "Restarting Orbit service..."

    if systemctl is-active --quiet orbit; then
        log "Orbit service is running, scheduling restart..."
        # Use a delayed restart to avoid script termination if run via Fleet
        (sleep 10 && systemctl restart orbit) &
        log "Orbit restart scheduled in 10 seconds"
        log "This allows the script to complete if run via Fleet"
    else
        log "Orbit service is not running, attempting to start..."
        systemctl start orbit || log "Warning: Failed to start Orbit service"
    fi
}

# Function to display success message
show_success() {
    log ""
    log "=========================================="
    log "Ubuntu Pro Extension Installation Complete"
    log "=========================================="
    log "Extension: $EXTENSION_NAME"
    log "Location: $EXTENSION_PATH"
    log "Config: $EXTENSIONS_LOAD_FILE"
    log ""
    log "TEST MODE: Downloaded from branch $GITHUB_BRANCH"
    log ""
    log "To verify installation:"
    log "  sudo orbit shell -- --extension $EXTENSION_PATH --allow-unsafe"
    log "  Then run: SELECT * FROM ubuntu_pro_status;"
    log ""
    log "Or wait for Orbit to restart and check Fleet queries"
    log "=========================================="
}

# Main installation flow
main() {
    log "Starting Ubuntu Pro Extension installation (TEST MODE)..."

    # Run all checks
    check_root
    check_ubuntu
    detect_architecture
    check_prerequisites

    # Prepare for installation
    create_directory "$EXTENSION_DIR"
    backup_existing

    # Download and install
    download_from_branch
    setup_file_permissions
    setup_extensions_load

    # Restart service
    restart_orbit

    # Show completion message
    show_success

    log "Installation script completed successfully"
}

# Run main function
main

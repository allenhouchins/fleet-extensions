#!/bin/bash

# Snap packages extension installer script
# Downloads and installs the correct snap_packages extension for Ubuntu from GitHub
# Supports amd64 and arm64 architectures
#
# Usage:
#   sudo ./install_snap_packages_extension.sh

set -e  # Exit on any error

# Variables
GITHUB_REPO="allenhouchins/snap-packages-extension"
EXTENSION_DIR="/var/fleetd/extensions"
OSQUERY_DIR="/etc/osquery"
EXTENSIONS_LOAD_FILE="$OSQUERY_DIR/extensions.load"
BACKUP_PATH=""

echo "Starting Snap Packages Extension installation..."

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
            EXTENSION_NAME="snap_packages_amd64"
            log "Architecture detected: amd64 (x86_64)"
            ;;
        "aarch64"|"arm64")
            EXTENSION_NAME="snap_packages_arm64"
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
        
        # Update package lists
        log "Updating package lists..."
        if apt update; then
            log "Package lists updated successfully"
        else
            log "Warning: Failed to update package lists, proceeding with installation attempt"
        fi
        
        # Install curl
        log "Installing curl..."
        if apt install -y curl; then
            log "curl installed successfully"
        else
            log "Error: Failed to install curl"
            log "Please install curl manually: sudo apt update && sudo apt install curl"
            exit 1
        fi
        
        # Verify curl is now available
        if ! command -v curl &> /dev/null; then
            log "Error: curl installation appears to have failed"
            exit 1
        fi
    else
        log "curl is already installed"
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
        # Ensure proper ownership even if directory exists
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

# Function to get the latest release tag from GitHub
get_latest_release_tag() {
    log "Finding latest release tag..."
    
    # Try to get the latest release page and extract the actual tag
    local releases_url="https://github.com/$GITHUB_REPO/releases/latest"
    local response
    
    if ! response=$(curl -s -L "$releases_url"); then
        log "Error: Failed to fetch releases page"
        return 1
    fi
    
    # Extract the actual tag from the redirected URL or page content
    # Look for the tag in the URL path or in the page content
    local tag
    tag=$(echo "$response" | grep -o 'releases/tag/[^"]*' | head -1 | sed 's|releases/tag/||' | sed 's|".*||')
    
    if [[ -z "$tag" ]]; then
        # Alternative: look for version tags in the page content
        tag=$(echo "$response" | grep -o 'tag/[v0-9][^"]*' | head -1 | sed 's|tag/||' | sed 's|".*||')
    fi
    
    if [[ -z "$tag" ]]; then
        log "Error: Could not determine latest release tag"
        return 1
    fi
    
    log "Found latest release tag: $tag"
    echo "$tag"
}

# Function to construct download URL with specific tag
get_download_url_with_tag() {
    local tag="$1"
    local download_url="https://github.com/$GITHUB_REPO/releases/download/$tag/$EXTENSION_NAME"
    echo "$download_url"
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

# Function to download the latest release
download_latest_release() {
    log "Starting download process..."
    log "Target extension: $EXTENSION_NAME"
    
    # Create temporary file for download
    local temp_file
    temp_file=$(mktemp)
    
    # First, try the direct latest download URL
    local direct_url="https://github.com/$GITHUB_REPO/releases/latest/download/$EXTENSION_NAME"
    log "Attempting direct download from: $direct_url"
    
    if curl -L --progress-bar --fail -o "$temp_file" "$direct_url" 2>/dev/null; then
        log "Direct download successful"
    else
        log "Direct download failed, getting actual release tag..."
        
        # Get the actual latest release tag
        local latest_tag
        if ! latest_tag=$(get_latest_release_tag); then
            log "Error: Could not determine latest release tag"
            rm -f "$temp_file"
            exit 1
        fi
        
        # Construct download URL with the actual tag
        local download_url
        download_url=$(get_download_url_with_tag "$latest_tag")
        log "Download URL with tag: $download_url"
        
        # Download with the specific tag
        if curl -L --progress-bar --fail -o "$temp_file" "$download_url"; then
            log "Download with specific tag successful"
        else
            log "Error: Download failed with both methods"
            log "Please verify that '$EXTENSION_NAME' exists in the latest release at:"
            log "https://github.com/$GITHUB_REPO/releases/latest"
            rm -f "$temp_file"
            exit 1
        fi
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
    
    # Check if extensions.load file exists
    if [[ -f "$EXTENSIONS_LOAD_FILE" ]]; then
        log "extensions.load file exists, checking for existing entry..."
        
        # Remove any existing entries for this extension (handle duplicates)
        if grep -q "$EXTENSION_PATH" "$EXTENSIONS_LOAD_FILE"; then
            log "Removing existing entries for this extension..."
            # Create temp file without the extension path
            grep -v "$EXTENSION_PATH" "$EXTENSIONS_LOAD_FILE" > "$EXTENSIONS_LOAD_FILE.tmp" || true
            mv "$EXTENSIONS_LOAD_FILE.tmp" "$EXTENSIONS_LOAD_FILE"
        fi
        
        # Add the extension path
        echo "$EXTENSION_PATH" >> "$EXTENSIONS_LOAD_FILE"
        log "Extension path added to extensions.load"
    else
        log "Creating extensions.load file..."
        echo "$EXTENSION_PATH" > "$EXTENSIONS_LOAD_FILE"
        chown root:root "$EXTENSIONS_LOAD_FILE"
        chmod 644 "$EXTENSIONS_LOAD_FILE"
        log "extensions.load file created"
    fi
}

# Function to restart orbit service
restart_orbit_service() {
    log "Attempting to restart orbit service..."
    
    # Check if orbit service is active
    if systemctl is-active --quiet orbit.service; then
        log "Restarting orbit.service..."
        if systemctl restart orbit.service; then
            log "orbit.service restarted successfully"
            return 0
        else
            log "Warning: Failed to restart orbit.service"
            return 1
        fi
    else
        log "Warning: orbit.service not found or not running"
        log "Extension will be loaded on next orbit startup"
        return 1
    fi
}

# Function to cleanup on failure
cleanup_on_failure() {
    log "Cleaning up due to failure..."
    
    # Remove the downloaded extension if it exists
    if [[ -f "$EXTENSION_PATH" ]]; then
        rm -f "$EXTENSION_PATH"
        log "Removed failed installation file"
    fi
    
    # Restore backup if it exists
    if [[ -f "$BACKUP_PATH" ]]; then
        mv "$BACKUP_PATH" "$EXTENSION_PATH"
        log "Restored previous version from backup"
    fi
}

# Trap to handle errors
trap cleanup_on_failure ERR

# Main execution
main() {
    log "=== Snap Packages Extension Installer Started ==="
    
    # Ensure log directory exists
    mkdir -p /var/log
    
    check_root
    check_ubuntu
    detect_architecture
    check_prerequisites
    
    # Create the extensions directory
    create_directory "$EXTENSION_DIR"
    
    # Backup existing extension
    backup_existing
    
    # Download the latest release
    download_latest_release
    
    # Set up file permissions
    setup_file_permissions
    
    # Setup extensions.load file
    setup_extensions_load
    
    # Restart orbit service
    restart_orbit_service
    
    # Clean up backup on success
    if [[ -f "$BACKUP_PATH" ]]; then
        log "Removing backup file (installation successful)"
        rm -f "$BACKUP_PATH"
    fi
    
    log "=== Installation completed successfully! ==="
    log "Extension installed at: $EXTENSION_PATH"
    log "Extensions configuration: $EXTENSIONS_LOAD_FILE"
    log "Architecture: $(uname -m)"
    log "Extension binary: $EXTENSION_NAME"
    echo ""
}

# Run the main function
main "$@"
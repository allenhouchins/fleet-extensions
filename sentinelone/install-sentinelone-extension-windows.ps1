# SentinelOne extension installer script for Windows
# Downloads and installs the sentinelone extension from GitHub
# Supports x64 architecture
#
# Usage:
#   Run as Administrator:
#   PowerShell -ExecutionPolicy Bypass -File install-sentinelone-extension-windows.ps1

#Requires -RunAsAdministrator

# Variables
$GITHUB_REPO = "tux234/fleet-extensions"
$EXTENSION_DIR = "C:\Program Files\fleetd\extensions"
$OSQUERY_DIR = "C:\Program Files\osquery"
$EXTENSIONS_LOAD_FILE = "$OSQUERY_DIR\extensions.load"
$BACKUP_PATH = ""
$SENTINEL_CTL_PATTERNS = @(
    "C:\Program Files\SentinelOne\Sentinel Agent *\SentinelCtl.exe",
    "C:\Program Files (x86)\SentinelOne\Sentinel Agent *\SentinelCtl.exe"
)

Write-Host "Starting SentinelOne Extension installation for Windows..."

# Function to log messages with timestamp
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to check if running on Windows
function Test-Windows {
    Write-Log "Checking if running on Windows..."

    if ($PSVersionTable.PSVersion.Major -ge 5) {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        Write-Log "Windows detected: $($osInfo.Caption) (Version $($osInfo.Version))"
        return $true
    } else {
        Write-Log "Error: PowerShell 5.0 or higher is required"
        return $false
    }
}

# Function to detect architecture and set extension name
function Get-Architecture {
    Write-Log "Detecting system architecture..."

    $arch = $env:PROCESSOR_ARCHITECTURE

    switch ($arch) {
        "AMD64" {
            $script:EXTENSION_NAME = "sentinelone-windows-amd64.ext"
            Write-Log "Architecture detected: x64 (AMD64)"
        }
        "ARM64" {
            Write-Log "Error: ARM64 architecture is not currently supported for Windows"
            exit 1
        }
        default {
            Write-Log "Error: Unsupported architecture: $arch"
            Write-Log "This script supports x64 (AMD64) only"
            exit 1
        }
    }

    $script:EXTENSION_PATH = Join-Path $EXTENSION_DIR $EXTENSION_NAME
    $script:BACKUP_PATH = "$EXTENSION_PATH.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

# Function to check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."

    # Check if curl is available (built into Windows 10+)
    try {
        $null = Get-Command curl.exe -ErrorAction Stop
        Write-Log "curl is available"
    } catch {
        Write-Log "Error: curl not found"
        Write-Log "curl should be available in Windows 10+ by default"
        Write-Log "Please ensure you are running Windows 10 version 1803 or later"
        exit 1
    }

    # Check if SentinelCtl.exe is available (warning only, not required for extension to work)
    $sentinelctlFound = $false
    foreach ($pattern in $SENTINEL_CTL_PATTERNS) {
        $matches = Get-ChildItem -Path (Split-Path $pattern -Parent) -Filter (Split-Path $pattern -Leaf) -ErrorAction SilentlyContinue
        if ($matches) {
            Write-Log "SentinelOne CLI found at: $($matches[0].FullName)"
            $sentinelctlFound = $true
            break
        }
    }

    if (-not $sentinelctlFound) {
        Write-Log "WARNING: SentinelOne CLI (SentinelCtl.exe) not found at expected locations:"
        foreach ($pattern in $SENTINEL_CTL_PATTERNS) {
            Write-Log "  - $pattern"
        }
        Write-Log "The extension will still be installed, but it requires SentinelOne agent to function."
        Write-Log "If SentinelOne is installed, the extension will work once the agent is running."
        Write-Log ""
        Write-Log "Continuing with installation in 5 seconds... (Ctrl+C to cancel)"
        Start-Sleep -Seconds 5
    }

    Write-Log "Prerequisites check completed"
}

# Function to create directory with proper permissions
function New-DirectoryIfNotExists {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        Write-Log "Creating directory: $Path"
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Log "Directory created"
    } else {
        Write-Log "Directory already exists: $Path"
    }
}

# Function to backup existing extension
function Backup-ExistingExtension {
    if (Test-Path $EXTENSION_PATH) {
        Write-Log "Backing up existing extension to: $BACKUP_PATH"
        Copy-Item $EXTENSION_PATH $BACKUP_PATH
        Write-Log "Backup completed"
    }
}

# Function to get the latest release tag from GitHub
function Get-LatestReleaseTag {
    Write-Log "Finding latest release tag..."

    try {
        $releasesUrl = "https://github.com/$GITHUB_REPO/releases/latest"
        $response = Invoke-WebRequest -Uri $releasesUrl -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue

        # Get the redirect location which contains the tag
        if ($response.Headers.Location) {
            $tag = ($response.Headers.Location -split '/tag/')[-1]
        } else {
            # Fallback: fetch the page and parse
            $response = Invoke-WebRequest -Uri $releasesUrl -UseBasicParsing
            if ($response.Content -match 'releases/tag/([^"]+)') {
                $tag = $matches[1]
            }
        }

        if ($tag) {
            Write-Log "Found latest release tag: $tag"
            return $tag
        } else {
            Write-Log "Error: Could not determine latest release tag"
            return $null
        }
    } catch {
        Write-Log "Error: Failed to fetch releases page: $_"
        return $null
    }
}

# Function to construct download URL with specific tag
function Get-DownloadUrlWithTag {
    param([string]$Tag)
    return "https://github.com/$GITHUB_REPO/releases/download/$Tag/$EXTENSION_NAME"
}

# Function to validate downloaded file
function Test-DownloadedFile {
    param([string]$FilePath)

    Write-Log "Validating downloaded file..."

    # Check if file exists and is not empty
    if (-not (Test-Path $FilePath)) {
        Write-Log "Error: Downloaded file not found"
        return $false
    }

    $fileInfo = Get-Item $FilePath
    if ($fileInfo.Length -eq 0) {
        Write-Log "Error: Downloaded file is empty"
        return $false
    }

    Write-Log "File size: $($fileInfo.Length) bytes"

    # Basic PE header check for Windows executables
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            Write-Log "File validation passed (valid PE executable)"
            return $true
        } else {
            Write-Log "Warning: File may not be a valid Windows executable. Proceeding anyway..."
            return $true
        }
    } catch {
        Write-Log "Warning: Could not validate file format. Proceeding anyway..."
        return $true
    }
}

# Function to download the latest release
function Get-LatestRelease {
    Write-Log "Starting download process..."
    Write-Log "Target extension: $EXTENSION_NAME"

    # Create temporary file for download
    $tempFile = [System.IO.Path]::GetTempFileName()

    # First, try the direct latest download URL
    $directUrl = "https://github.com/$GITHUB_REPO/releases/latest/download/$EXTENSION_NAME"
    Write-Log "Attempting direct download from: $directUrl"

    try {
        Invoke-WebRequest -Uri $directUrl -OutFile $tempFile -UseBasicParsing
        Write-Log "Direct download successful"
    } catch {
        Write-Log "Direct download failed, getting actual release tag..."

        # Get the actual latest release tag
        $latestTag = Get-LatestReleaseTag
        if (-not $latestTag) {
            Write-Log "Error: Could not determine latest release tag"
            Remove-Item $tempFile -ErrorAction SilentlyContinue
            exit 1
        }

        # Construct download URL with the actual tag
        $downloadUrl = Get-DownloadUrlWithTag -Tag $latestTag
        Write-Log "Download URL with tag: $downloadUrl"

        # Download with the specific tag
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
            Write-Log "Download with specific tag successful"
        } catch {
            Write-Log "Error: Download failed with both methods"
            Write-Log "Please verify that '$EXTENSION_NAME' exists in the latest release at:"
            Write-Log "https://github.com/$GITHUB_REPO/releases/latest"
            Remove-Item $tempFile -ErrorAction SilentlyContinue
            exit 1
        }
    }

    # Validate the download
    if (Test-DownloadedFile -FilePath $tempFile) {
        # Move to final location
        Move-Item $tempFile $EXTENSION_PATH -Force
        Write-Log "File moved to final location: $EXTENSION_PATH"
    } else {
        Write-Log "Error: File validation failed"
        Remove-Item $tempFile -ErrorAction SilentlyContinue
        exit 1
    }
}

# Function to handle extensions.load file
function Set-ExtensionsLoad {
    Write-Log "Configuring extensions.load file..."

    # Create osquery directory if it doesn't exist
    if (-not (Test-Path $OSQUERY_DIR)) {
        Write-Log "Creating osquery directory: $OSQUERY_DIR"
        New-Item -ItemType Directory -Path $OSQUERY_DIR -Force | Out-Null
    }

    # Check if extensions.load file exists
    if (Test-Path $EXTENSIONS_LOAD_FILE) {
        Write-Log "extensions.load file exists, checking for existing entry..."

        # Remove any existing entries for this extension (handle duplicates)
        $content = Get-Content $EXTENSIONS_LOAD_FILE -ErrorAction SilentlyContinue
        if ($content -match [regex]::Escape($EXTENSION_PATH)) {
            Write-Log "Removing existing entries for this extension..."
            $content = $content | Where-Object { $_ -notmatch [regex]::Escape($EXTENSION_PATH) }
            Set-Content -Path $EXTENSIONS_LOAD_FILE -Value $content
        }

        # Add the extension path
        Add-Content -Path $EXTENSIONS_LOAD_FILE -Value $EXTENSION_PATH
        Write-Log "Extension path added to extensions.load"
    } else {
        Write-Log "Creating extensions.load file..."
        Set-Content -Path $EXTENSIONS_LOAD_FILE -Value $EXTENSION_PATH
        Write-Log "extensions.load file created"
    }
}

# Function to restart orbit service
function Restart-OrbitService {
    Write-Log "Attempting to restart orbit service..."

    # Check if orbit service exists
    $orbitService = Get-Service -Name "Fleet osquery" -ErrorAction SilentlyContinue
    if ($orbitService) {
        Write-Log "Restarting Fleet osquery service..."
        try {
            Restart-Service -Name "Fleet osquery" -Force
            Write-Log "Fleet osquery service restarted successfully"
            return $true
        } catch {
            Write-Log "Warning: Failed to restart Fleet osquery service: $_"
            return $false
        }
    } else {
        Write-Log "Warning: Fleet osquery service not found"
        Write-Log "Extension will be loaded on next orbit startup"
        return $false
    }
}

# Function to cleanup on failure
function Invoke-CleanupOnFailure {
    Write-Log "Cleaning up due to failure..."

    # Remove the downloaded extension if it exists
    if (Test-Path $EXTENSION_PATH) {
        Remove-Item $EXTENSION_PATH -Force
        Write-Log "Removed failed installation file"
    }

    # Restore backup if it exists
    if (Test-Path $BACKUP_PATH) {
        Move-Item $BACKUP_PATH $EXTENSION_PATH -Force
        Write-Log "Restored previous version from backup"
    }
}

# Main execution
function Main {
    Write-Log "=== SentinelOne Extension Installer for Windows Started ==="

    # Check if running as Administrator
    if (-not (Test-Administrator)) {
        Write-Log "Error: This script must be run as Administrator"
        Write-Log "Please right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }

    # Check Windows
    if (-not (Test-Windows)) {
        exit 1
    }

    # Detect architecture
    Get-Architecture

    # Check prerequisites
    Test-Prerequisites

    try {
        # Create the extensions directory
        New-DirectoryIfNotExists -Path $EXTENSION_DIR

        # Backup existing extension
        Backup-ExistingExtension

        # Download the latest release
        Get-LatestRelease

        # Setup extensions.load file
        Set-ExtensionsLoad

        # Restart orbit service
        Restart-OrbitService

        # Clean up backup on success
        if (Test-Path $BACKUP_PATH) {
            Write-Log "Removing backup file (installation successful)"
            Remove-Item $BACKUP_PATH -Force
        }

        Write-Log "=== Installation completed successfully! ==="
        Write-Log "Extension installed at: $EXTENSION_PATH"
        Write-Log "Extensions configuration: $EXTENSIONS_LOAD_FILE"
        Write-Log "Architecture: $env:PROCESSOR_ARCHITECTURE"
        Write-Log "Extension binary: $EXTENSION_NAME"
        Write-Host ""
        Write-Log "Note: The extension requires SentinelOne agent to be installed and running."
        Write-Log "      Query the table with: SELECT * FROM sentinelone_info;"

    } catch {
        Write-Log "Error occurred during installation: $_"
        Invoke-CleanupOnFailure
        exit 1
    }
}

# Run the main function
Main

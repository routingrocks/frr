#!/bin/bash
# devenv_extract_metadata.sh
# Generic script to extract package-specific metadata for devenv build tracking
# This script detects the package type and extracts appropriate metadata
# Output format: XB-METADATA-KEY: value (one per line)

set -e

SOURCE_DIR="$1"
REPO_NAME="$2"

if [ -z "$SOURCE_DIR" ]; then
    echo "Usage: $0 <source_dir> [repo_name]" >&2
    exit 1
fi

if [ ! -d "$SOURCE_DIR" ]; then
    echo "ERROR: Source directory does not exist: $SOURCE_DIR" >&2
    exit 1
fi

# Function to extract FRR version from configure.ac
extract_frr_metadata() {
    local configure_ac="$SOURCE_DIR/configure.ac"
    
    if [ -f "$configure_ac" ]; then
        local version=$(grep '^AC_INIT' "$configure_ac" | cut -d'[' -f3 | cut -d']' -f1)
        if [ -n "$version" ]; then
            echo "XB-METADATA-FRR-VERSION: $version"
        else
            echo "WARNING: Failed to extract FRR version from configure.ac" >&2
        fi
    fi
}

# Function to extract Mellanox SDK metadata from Makefile
extract_mellanox_metadata() {
    local makefile="$SOURCE_DIR/build-config/Makefile"
    
    if [ -f "$makefile" ]; then
        # Extract SDK version
        local sdk_version=$(grep '^MLXSDK_VERSION' "$makefile" | cut -d'=' -f2 | tr -d ' ')
        if [ -n "$sdk_version" ]; then
            echo "XB-METADATA-SDK-VERSION: $sdk_version"
        fi
        
        # Extract FW version
        local fw_version=$(grep '^MLX_FW_VERSION' "$makefile" | cut -d'=' -f2 | tr -d ' ')
        if [ -n "$fw_version" ]; then
            echo "XB-METADATA-FW-VERSION: $fw_version"
        fi
        
        # Extract SIMX version
        local simx_version=$(grep '^SIMX_VERSION' "$makefile" | cut -d'=' -f2 | tr -d ' ')
        if [ -n "$simx_version" ]; then
            echo "XB-METADATA-SIMX-VERSION: $simx_version"
        fi
        
        if [ -z "$sdk_version" ] && [ -z "$fw_version" ] && [ -z "$simx_version" ]; then
            echo "WARNING: Failed to extract any Mellanox SDK versions from Makefile" >&2
        fi
    fi
}

# Function to extract generic metadata from common files
extract_generic_metadata() {
    # Add build timestamp
    echo "XB-BUILD-TIMESTAMP: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    
    # Add source package info if available
    if [ -f "$SOURCE_DIR/debian/changelog" ]; then
        cd "$SOURCE_DIR"
        local source_pkg=$(dpkg-parsechangelog -SSource 2>/dev/null || echo "unknown")
        local version=$(dpkg-parsechangelog -SVersion 2>/dev/null || echo "unknown")
        echo "XB-SOURCE-PACKAGE: $source_pkg"
        echo "XB-PACKAGE-VERSION: $version"
    fi
}

# Main extraction logic - detect package type and extract appropriate metadata
main() {
    local extracted_count=0
    
    # Try FRR metadata extraction
    if [ -f "$SOURCE_DIR/configure.ac" ]; then
        extract_frr_metadata
        extracted_count=$((extracted_count + 1))
    fi
    
    # Try Mellanox SDK metadata extraction
    if [ -f "$SOURCE_DIR/build-config/Makefile" ]; then
        extract_mellanox_metadata
        extracted_count=$((extracted_count + 1))
    fi
    
    # Always extract generic metadata
    extract_generic_metadata
    
    # Log to stderr for debugging (stdout is used for XB- fields)
    if [ "$extracted_count" -gt 0 ]; then
        echo "Successfully extracted metadata for package type(s) in $SOURCE_DIR" >&2
    else
        echo "No specific package metadata found in $SOURCE_DIR, using generic metadata only" >&2
    fi
}

# Run main function
main "$@"

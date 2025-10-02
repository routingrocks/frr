#!/bin/bash
# devenv_extract_metadata.sh for FRR
# Extract FRR version from configure.ac
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
        # Extract version from AC_INIT([frr], [VERSION], ...) format
        local version=$(grep '^AC_INIT' "$configure_ac" | sed -n 's/^AC_INIT(\[[^]]*\], \[\([^]]*\)\].*/\1/p')
        if [ -n "$version" ]; then
            echo "XB-METADATA-FRR-VERSION: $version"
        else
            echo "WARNING: Failed to extract FRR version from configure.ac" >&2
            exit 1
        fi
    else
        echo "ERROR: configure.ac not found in $SOURCE_DIR" >&2
        exit 1
    fi
}

# Main extraction
extract_frr_metadata

# Log success to stderr
echo "Successfully extracted FRR metadata from $SOURCE_DIR" >&2
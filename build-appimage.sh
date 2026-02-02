#!/bin/bash
# TESSERACT AppImage Build Script
#
# This script builds a portable Linux AppImage package.
#
# Requirements:
# - Rust toolchain (cargo)
# - appimagetool (https://github.com/AppImage/appimagetool)
# - strip (binutils)
#
# Usage:
#   ./build-appimage.sh [--release|--debug]
#
# The resulting AppImage will be placed in target/{release,debug}/

set -e

# Configuration
APP_NAME="tesseract"
DISPLAY_NAME="TESSERACT"
VERSION="0.1.0"
COMMENT="Secure removable storage encryption"
CATEGORY="Security"

# Parse arguments
BUILD_TYPE="${1:---release}"
if [[ "$BUILD_TYPE" != "--release" && "$BUILD_TYPE" != "--debug" ]]; then
    echo "Usage: $0 [--release|--debug]"
    exit 1
fi

# Determine build directory
if [[ "$BUILD_TYPE" == "--release" ]]; then
    BUILD_DIR="target/release"
    CARGO_FLAGS="--release"
else
    BUILD_DIR="target/debug"
    CARGO_FLAGS=""
fi

echo "=============================================="
echo "Building TESSERACT AppImage"
echo "=============================================="
echo "Build type: $BUILD_TYPE"
echo "Version: $VERSION"
echo ""

# Build the binary
echo "Step 1: Building binary..."
cargo build $CARGO_FLAGS --bin tesseract-gui -p tesseract-gui

# Check binary exists
BINARY="$BUILD_DIR/tesseract-gui"
if [[ ! -f "$BINARY" ]]; then
    echo "Error: Binary not found at $BINARY"
    exit 1
fi

echo "Binary size: $(du -h "$BINARY" | cut -f1)"

# Create AppDir structure
echo ""
echo "Step 2: Creating AppDir..."
APPDIR="$BUILD_DIR/$APP_NAME.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/64x64/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/48x48/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/32x32/apps"
mkdir -p "$APPDIR/usr/share/metainfo"

# Copy and strip binary
echo ""
echo "Step 3: Copying and stripping binary..."
cp "$BINARY" "$APPDIR/usr/bin/$APP_NAME"
chmod +x "$APPDIR/usr/bin/$APP_NAME"

if [[ "$BUILD_TYPE" == "--release" ]]; then
    BEFORE_SIZE=$(stat -c%s "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null || stat -f%z "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null)
    strip --strip-all "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null || echo "Warning: strip failed"
    AFTER_SIZE=$(stat -c%s "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null || stat -f%z "$APPDIR/usr/bin/$APP_NAME" 2>/dev/null)
    echo "Binary stripped: $((BEFORE_SIZE / 1024 / 1024))MB -> $((AFTER_SIZE / 1024 / 1024))MB"
fi

# Generate desktop file
echo ""
echo "Step 4: Generating desktop file..."
cat > "$APPDIR/$APP_NAME.desktop" << EOF
[Desktop Entry]
Type=Application
Name=$DISPLAY_NAME
GenericName=Encrypted Storage
Comment=$COMMENT
Exec=$APP_NAME
Icon=$APP_NAME
Terminal=false
Categories=$CATEGORY;
StartupNotify=true
StartupWMClass=$APP_NAME
Keywords=encryption;security;vault;cryptography;usb;
EOF

cp "$APPDIR/$APP_NAME.desktop" "$APPDIR/usr/share/applications/"

# Generate icon
echo ""
echo "Step 5: Generating icons..."

# Create vault icon programmatically (simple PNG with vault/lock design)
generate_icon() {
    local size=$1
    local output=$2

    if command -v convert &> /dev/null; then
        # Use ImageMagick if available for better quality
        convert -size ${size}x${size} xc:none \
            -fill '#2E4A6B' -draw "circle $((size/2)),$((size/2)) $((size/2)),$((size/8))" \
            -fill '#6495C8' -stroke '#1A2E4A' -strokewidth $((size/32)) \
            -draw "circle $((size/2)),$((size/2)) $((size/2)),$((size*3/8))" \
            -fill '#1A2E4A' -stroke none \
            -draw "rectangle $((size*7/16)),$((size/2)) $((size*9/16)),$((size*5/8))" \
            -draw "circle $((size/2)),$((size*7/16)) $((size/2)),$((size*3/8))" \
            "$output" 2>/dev/null && return 0
    fi

    # Fallback: Create a minimal valid PNG (1x1 blue pixel, scaled)
    # This is a placeholder - the real icon should be provided separately
    printf '\x89PNG\r\n\x1a\n' > "$output"
    printf '\x00\x00\x00\rIHDR' >> "$output"
    printf '\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde' >> "$output"
    printf '\x00\x00\x00\x0cIDATx\x9cc\xf8O\x00\x00\x01\x01\x01\x00\x05\x18\xd8N' >> "$output"
    printf '\x00\x00\x00\x00IEND\xaeB`\x82' >> "$output"
}

for size in 256 128 64 48 32; do
    generate_icon $size "$APPDIR/usr/share/icons/hicolor/${size}x${size}/apps/$APP_NAME.png"
done

# Copy main icon to AppDir root
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png" "$APPDIR/$APP_NAME.png"
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_NAME.png" "$APPDIR/.DirIcon"

# Generate AppRun
echo ""
echo "Step 6: Generating AppRun..."
cat > "$APPDIR/AppRun" << 'APPRUN_EOF'
#!/bin/bash
# TESSERACT AppImage entry point

# Get the directory where this AppImage is mounted
APPDIR="$(dirname "$(readlink -f "$0")")"

# Set up library path for bundled dependencies
export LD_LIBRARY_PATH="${APPDIR}/usr/lib:${LD_LIBRARY_PATH}"

# Set XDG paths for portable operation
export XDG_DATA_DIRS="${APPDIR}/usr/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"

# FUSE3 fallback: Try fuse3 first, fall back to fuse2 if not available
if ! command -v fusermount3 &> /dev/null && command -v fusermount &> /dev/null; then
    export APPIMAGE_EXTRACT_AND_RUN=1
fi

# Launch the application
exec "${APPDIR}/usr/bin/tesseract" "$@"
APPRUN_EOF
chmod +x "$APPDIR/AppRun"

# Generate AppStream metainfo
echo ""
echo "Step 7: Generating AppStream metainfo..."
cat > "$APPDIR/usr/share/metainfo/$APP_NAME.appdata.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>$APP_NAME.desktop</id>
  <name>$DISPLAY_NAME</name>
  <summary>$COMMENT</summary>
  <metadata_license>MIT</metadata_license>
  <project_license>MIT</project_license>
  <description>
    <p>
      TESSERACT is a production-grade removable storage encryption application
      providing AES-256-GCM encryption, Argon2id key derivation, and multi-level
      access control for classified data protection.
    </p>
    <p>Features include:</p>
    <ul>
      <li>AES-256-GCM authenticated encryption with hardware acceleration</li>
      <li>Argon2id key derivation for password-based encryption</li>
      <li>Four-tier key hierarchy for defense in depth</li>
      <li>Multi-level access control for compartmentalized security</li>
      <li>Virtual filesystem integration (FUSE on Linux)</li>
      <li>Portable GUI requiring no installation</li>
    </ul>
  </description>
  <categories>
    <category>$CATEGORY</category>
    <category>Utility</category>
  </categories>
  <url type="homepage">https://github.com/tesseract/tesseract</url>
  <provides>
    <binary>$APP_NAME</binary>
  </provides>
  <releases>
    <release version="$VERSION" date="$(date +%Y-%m-%d)" />
  </releases>
  <content_rating type="oars-1.1" />
</component>
EOF

# Build AppImage
echo ""
echo "Step 8: Creating AppImage..."
OUTPUT="$BUILD_DIR/$APP_NAME-$VERSION-x86_64.AppImage"

if command -v appimagetool &> /dev/null; then
    ARCH=x86_64 appimagetool "$APPDIR" "$OUTPUT"
elif [[ -x "./appimagetool-x86_64.AppImage" ]]; then
    ARCH=x86_64 ./appimagetool-x86_64.AppImage "$APPDIR" "$OUTPUT"
elif [[ -x "$HOME/bin/appimagetool" ]]; then
    ARCH=x86_64 "$HOME/bin/appimagetool" "$APPDIR" "$OUTPUT"
else
    echo ""
    echo "Error: appimagetool not found!"
    echo ""
    echo "Install with one of these methods:"
    echo ""
    echo "1. Download directly:"
    echo "   wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
    echo "   chmod +x appimagetool-x86_64.AppImage"
    echo "   sudo mv appimagetool-x86_64.AppImage /usr/local/bin/appimagetool"
    echo ""
    echo "2. On Ubuntu/Debian:"
    echo "   sudo apt install libfuse2  # Required for running AppImages"
    echo ""
    echo "For more information: https://github.com/AppImage/appimagetool"
    exit 1
fi

# Check result
if [[ -f "$OUTPUT" ]]; then
    SIZE_BYTES=$(stat -c%s "$OUTPUT" 2>/dev/null || stat -f%z "$OUTPUT" 2>/dev/null)
    SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
    SIZE_HUMAN=$(du -h "$OUTPUT" | cut -f1)

    echo ""
    echo "=============================================="
    echo "AppImage created successfully!"
    echo "=============================================="
    echo "Output: $OUTPUT"
    echo "Size: $SIZE_HUMAN ($SIZE_MB MB)"
    echo ""

    # Size limit check
    if [[ $SIZE_MB -gt 30 ]]; then
        echo "WARNING: AppImage size ($SIZE_MB MB) exceeds 30 MB limit!"
        echo ""
        echo "Consider:"
        echo "  - Using --release build"
        echo "  - Enabling LTO in Cargo.toml (already enabled)"
        echo "  - Removing unused dependencies"
        echo "  - Using 'cargo bloat' to identify large dependencies"
        echo ""
    else
        echo "Size check: PASSED (< 30 MB)"
    fi

    echo ""
    echo "Test the AppImage:"
    echo "  chmod +x $OUTPUT"
    echo "  ./$OUTPUT"
    echo ""
    echo "Or install system-wide:"
    echo "  sudo mv $OUTPUT /usr/local/bin/tesseract"
else
    echo ""
    echo "Error: AppImage creation failed!"
    exit 1
fi

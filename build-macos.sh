#!/bin/bash
# TESSERACT macOS App Bundle Build Script
# Creates a .app bundle for macOS distribution
#
# Usage:
#   ./build-macos.sh                    # Build for current architecture
#   ./build-macos.sh --universal        # Build universal binary (arm64 + x86_64)
#   ./build-macos.sh --sign             # Build and code sign
#   ./build-macos.sh --notarize         # Build, sign, and notarize
#   ./build-macos.sh --dmg              # Create DMG installer
#
# Environment variables:
#   SIGNING_IDENTITY    - Code signing identity (e.g., "Developer ID Application: ...")
#   APPLE_ID            - Apple ID for notarization
#   TEAM_ID             - 10-character Team ID
#   APP_PASSWORD        - App-specific password or @keychain:AC_PASSWORD
#
# Requirements:
#   - Rust toolchain
#   - Xcode Command Line Tools
#   - (Optional) Apple Developer certificate for signing
#   - (Optional) notarytool for notarization

set -e

# Configuration
APP_NAME="tesseract"
DISPLAY_NAME="TESSERACT"
VERSION="1.0.0"
BUILD_NUMBER="1"
BUNDLE_ID="io.tesseract.encryption"
MIN_MACOS_VERSION="12.0"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/target/release"
DIST_DIR="$SCRIPT_DIR/dist"
BUNDLE_PATH="$DIST_DIR/$DISPLAY_NAME.app"

# Parse arguments
UNIVERSAL=false
SIGN=false
NOTARIZE=false
CREATE_DMG=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --universal)
            UNIVERSAL=true
            shift
            ;;
        --sign)
            SIGN=true
            shift
            ;;
        --notarize)
            NOTARIZE=true
            SIGN=true  # Notarization requires signing
            shift
            ;;
        --dmg)
            CREATE_DMG=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --universal    Build universal binary (arm64 + x86_64)"
            echo "  --sign         Code sign the app bundle"
            echo "  --notarize     Notarize with Apple (requires --sign)"
            echo "  --dmg          Create DMG installer"
            echo "  --help         Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  SIGNING_IDENTITY    Code signing identity"
            echo "  APPLE_ID            Apple ID for notarization"
            echo "  TEAM_ID             10-character Team ID"
            echo "  APP_PASSWORD        App-specific password"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Verify we're on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: This script must be run on macOS"
    exit 1
fi

# Check for required tools
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust."
    exit 1
fi

echo "================================================"
echo " TESSERACT macOS App Bundle Builder"
echo "================================================"
echo ""
echo "Configuration:"
echo "  App Name:     $APP_NAME"
echo "  Display Name: $DISPLAY_NAME"
echo "  Version:      $VERSION"
echo "  Bundle ID:    $BUNDLE_ID"
echo "  Universal:    $UNIVERSAL"
echo "  Code Sign:    $SIGN"
echo "  Notarize:     $NOTARIZE"
echo "  Create DMG:   $CREATE_DMG"
echo ""

# Build the binary
echo "Building release binary..."
if $UNIVERSAL; then
    echo "  Building for arm64..."
    cargo build --release --target aarch64-apple-darwin -p tesseract-gui

    echo "  Building for x86_64..."
    cargo build --release --target x86_64-apple-darwin -p tesseract-gui

    echo "  Creating universal binary..."
    mkdir -p "$BUILD_DIR"
    lipo -create \
        "$SCRIPT_DIR/target/aarch64-apple-darwin/release/$APP_NAME" \
        "$SCRIPT_DIR/target/x86_64-apple-darwin/release/$APP_NAME" \
        -output "$BUILD_DIR/$APP_NAME-universal"
    BINARY_PATH="$BUILD_DIR/$APP_NAME-universal"
else
    cargo build --release -p tesseract-gui
    BINARY_PATH="$BUILD_DIR/$APP_NAME"
fi

# Verify binary exists
if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Error: Binary not found at $BINARY_PATH"
    exit 1
fi

echo "Binary built: $BINARY_PATH"

# Create distribution directory
mkdir -p "$DIST_DIR"

# Remove existing bundle
if [[ -d "$BUNDLE_PATH" ]]; then
    echo "Removing existing bundle..."
    rm -rf "$BUNDLE_PATH"
fi

# Create app bundle structure
echo "Creating app bundle structure..."
mkdir -p "$BUNDLE_PATH/Contents/MacOS"
mkdir -p "$BUNDLE_PATH/Contents/Resources"
mkdir -p "$BUNDLE_PATH/Contents/Frameworks"

# Copy and strip binary
echo "Copying binary..."
cp "$BINARY_PATH" "$BUNDLE_PATH/Contents/MacOS/$APP_NAME"
chmod +x "$BUNDLE_PATH/Contents/MacOS/$APP_NAME"

echo "Stripping debug symbols..."
strip -x "$BUNDLE_PATH/Contents/MacOS/$APP_NAME" 2>/dev/null || echo "  (strip not available or failed)"

# Generate Info.plist
echo "Generating Info.plist..."
cat > "$BUNDLE_PATH/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>$DISPLAY_NAME</string>
	<key>CFBundleDisplayName</key>
	<string>$DISPLAY_NAME</string>
	<key>CFBundleIdentifier</key>
	<string>$BUNDLE_ID</string>
	<key>CFBundleVersion</key>
	<string>$BUILD_NUMBER</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleExecutable</key>
	<string>$APP_NAME</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleSignature</key>
	<string>????</string>
	<key>CFBundleIconFile</key>
	<string>AppIcon</string>
	<key>NSHumanReadableCopyright</key>
	<string>Copyright © 2026 TESSERACT Project. All rights reserved.</string>
	<key>CFBundleGetInfoString</key>
	<string>Secure removable storage encryption</string>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.security</string>
	<key>LSMinimumSystemVersion</key>
	<string>$MIN_MACOS_VERSION</string>
	<key>LSArchitecturePriority</key>
	<array>
		<string>arm64</string>
		<string>x86_64</string>
	</array>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
	<key>NSSupportsAutomaticTermination</key>
	<true/>
	<key>NSSupportsSuddenTermination</key>
	<false/>
	<key>CFBundleDocumentTypes</key>
	<array>
		<dict>
			<key>CFBundleTypeName</key>
			<string>TESSERACT Vault</string>
			<key>CFBundleTypeRole</key>
			<string>Editor</string>
			<key>CFBundleTypeExtensions</key>
			<array>
				<string>vault</string>
			</array>
			<key>LSItemContentTypes</key>
			<array>
				<string>io.tesseract.vault</string>
			</array>
		</dict>
	</array>
	<key>CFBundleURLTypes</key>
	<array>
		<dict>
			<key>CFBundleURLName</key>
			<string>$BUNDLE_ID</string>
			<key>CFBundleURLSchemes</key>
			<array>
				<string>tesseract</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
EOF

# Generate PkgInfo
echo "Generating PkgInfo..."
echo -n 'APPL????' > "$BUNDLE_PATH/Contents/PkgInfo"

# Generate icon (placeholder - in production use iconutil with iconset)
echo "Generating app icon..."
# For a proper icon, you would:
# 1. Create AppIcon.iconset/ directory with various sizes
# 2. Run: iconutil -c icns AppIcon.iconset -o "$BUNDLE_PATH/Contents/Resources/AppIcon.icns"
#
# For now, we create a minimal placeholder. In production, replace this with:
# cp path/to/AppIcon.icns "$BUNDLE_PATH/Contents/Resources/AppIcon.icns"

# Create a simple iconset if iconutil is available
if command -v iconutil &> /dev/null && command -v sips &> /dev/null; then
    ICONSET_DIR="$DIST_DIR/AppIcon.iconset"
    mkdir -p "$ICONSET_DIR"

    # Generate a simple colored square as placeholder
    # In production, replace with actual icon artwork
    for size in 16 32 64 128 256 512; do
        # Create a simple placeholder icon using sips (if we had a source image)
        # For now, skip actual icon generation
        :
    done

    # If iconset has valid content, convert to icns
    # iconutil -c icns "$ICONSET_DIR" -o "$BUNDLE_PATH/Contents/Resources/AppIcon.icns"
    rm -rf "$ICONSET_DIR"
fi

echo "  (Icon generation skipped - use iconutil with proper iconset in production)"

# Code signing
if $SIGN; then
    if [[ -z "$SIGNING_IDENTITY" ]]; then
        echo ""
        echo "Warning: SIGNING_IDENTITY not set. Looking for available identities..."
        security find-identity -v -p codesigning | head -5
        echo ""
        echo "Set SIGNING_IDENTITY environment variable to sign the app."
        echo "Example: export SIGNING_IDENTITY='Developer ID Application: Your Name (TEAM_ID)'"
    else
        echo "Code signing with identity: $SIGNING_IDENTITY"
        codesign --sign "$SIGNING_IDENTITY" \
            --deep \
            --force \
            --options runtime \
            --timestamp \
            "$BUNDLE_PATH"

        echo "Verifying signature..."
        codesign --verify --deep --strict --verbose=2 "$BUNDLE_PATH"
        echo "Code signing successful!"
    fi
fi

# Notarization
if $NOTARIZE; then
    if [[ -z "$SIGNING_IDENTITY" ]] || [[ -z "$APPLE_ID" ]] || [[ -z "$TEAM_ID" ]] || [[ -z "$APP_PASSWORD" ]]; then
        echo ""
        echo "Warning: Notarization requires the following environment variables:"
        echo "  SIGNING_IDENTITY - Code signing identity"
        echo "  APPLE_ID         - Your Apple ID email"
        echo "  TEAM_ID          - 10-character Team ID"
        echo "  APP_PASSWORD     - App-specific password (or @keychain:AC_PASSWORD)"
        echo ""
        echo "Skipping notarization."
    else
        echo "Creating ZIP for notarization..."
        ZIP_PATH="$BUNDLE_PATH.zip"
        ditto -c -k --keepParent "$BUNDLE_PATH" "$ZIP_PATH"

        echo "Submitting for notarization..."
        xcrun notarytool submit "$ZIP_PATH" \
            --apple-id "$APPLE_ID" \
            --team-id "$TEAM_ID" \
            --password "$APP_PASSWORD" \
            --wait

        echo "Stapling notarization ticket..."
        xcrun stapler staple "$BUNDLE_PATH"

        rm "$ZIP_PATH"
        echo "Notarization complete!"
    fi
fi

# Create DMG
if $CREATE_DMG; then
    DMG_PATH="$DIST_DIR/$DISPLAY_NAME-$VERSION.dmg"

    echo "Creating DMG installer..."

    # Remove existing DMG
    rm -f "$DMG_PATH"

    # Create DMG
    hdiutil create \
        -volname "$DISPLAY_NAME" \
        -srcfolder "$BUNDLE_PATH" \
        -ov \
        -format UDBZ \
        "$DMG_PATH"

    echo "DMG created: $DMG_PATH"

    # Sign DMG if signing is enabled
    if $SIGN && [[ -n "$SIGNING_IDENTITY" ]]; then
        echo "Signing DMG..."
        codesign --sign "$SIGNING_IDENTITY" --timestamp "$DMG_PATH"
    fi
fi

# Print summary
echo ""
echo "================================================"
echo " Build Complete"
echo "================================================"
echo ""
echo "App Bundle: $BUNDLE_PATH"
ls -la "$BUNDLE_PATH"
echo ""
du -sh "$BUNDLE_PATH"

if $CREATE_DMG; then
    echo ""
    echo "DMG: $DMG_PATH"
    ls -la "$DMG_PATH"
fi

echo ""
echo "To test the app:"
echo "  open \"$BUNDLE_PATH\""
echo ""

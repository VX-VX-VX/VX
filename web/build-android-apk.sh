#!/usr/bin/env bash
# Vortex Sovereign OS - Android APK Build Script
# Run from web/ directory: ./build-android-apk.sh

set -e

echo "🏗️  Building Vortex Sovereign OS Android APK..."

# Check for Android SDK
if [ -z "$ANDROID_HOME" ] && [ -z "$ANDROID_SDK_ROOT" ]; then
    echo "⚠️  ANDROID_HOME not set. Attempting to find SDK..."
    if [ -d "$HOME/Android/Sdk" ]; then
        export ANDROID_HOME="$HOME/Android/Sdk"
    elif [ -d "/opt/android-sdk" ]; then
        export ANDROID_HOME="/opt/android-sdk"
    elif [ -d "/usr/lib/android-sdk" ]; then
        export ANDROID_HOME="/usr/lib/android-sdk"
    else
        echo "❌ Android SDK not found. Please install Android Studio and set ANDROID_HOME."
        echo "   Example: export ANDROID_HOME=\$HOME/Android/Sdk"
        exit 1
    fi
fi

echo "✅ Android SDK: $ANDROID_HOME"

# Ensure Java is available
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Please install JDK 17+."
    exit 1
fi
echo "✅ Java: $(java -version 2>&1 | head -1)"

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing npm dependencies..."
    npm ci
fi

# Add Capacitor Android platform if not exists
if [ ! -d "android" ]; then
    echo "📱 Adding Capacitor Android platform..."
    npx cap add android
fi

# Build web assets
echo "🔨 Building web assets..."
npm run build

# Sync Capacitor
echo "🔄 Syncing Capacitor..."
npx cap sync android

# Build APK
echo "📦 Building APK..."
cd android
./gradlew assembleDebug

# Copy APK to release directory
mkdir -p ../release
cp app/build/outputs/apk/debug/app-debug.apk ../release/vortex-sovereign-debug.apk
cd ..

echo ""
echo "✅ Build complete!"
echo "📱 APK location: web/release/vortex-sovereign-debug.apk"
echo ""
echo "To install on device/emulator:"
echo "  adb install web/release/vortex-sovereign-debug.apk"
echo ""
echo "To open in Android Studio:"
echo "  npx cap open android"
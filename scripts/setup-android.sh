#!/usr/bin/env bash
# Idempotent helper that produces an Android project ready to build into an APK.
# Assumes: Node, Android SDK (ANDROID_HOME), JDK 17+.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if [ ! -d node_modules ]; then
  npm ci --no-audit --no-fund
fi

# Ensure the web assets Capacitor syncs into the APK exist.
npm run build:web

# First-time Android scaffold.
if [ ! -d android ]; then
  npx cap add android
fi

# Drop our Kotlin sources into the generated project.
PLUGIN_DIR="android/app/src/main/java/os/shield/droidsentry"
mkdir -p "$PLUGIN_DIR"
cp android-native/src/main/java/os/shield/droidsentry/ShieldPlugin.kt "$PLUGIN_DIR/"
cp android-native/src/main/java/os/shield/droidsentry/MainActivity.kt "$PLUGIN_DIR/"

# Remove any MainActivity auto-generated under other package paths so there's no conflict.
find android/app/src/main/java -name 'MainActivity.*' \
  -not -path "*/os/shield/droidsentry/*" -delete

# Merge our extra permissions into the generated manifest, once.
MANIFEST="android/app/src/main/AndroidManifest.xml"
if ! grep -q "NEARBY_WIFI_DEVICES" "$MANIFEST"; then
  python3 - <<'PY'
import re, pathlib
m = pathlib.Path("android/app/src/main/AndroidManifest.xml")
perms = pathlib.Path("android-native/AndroidManifest.permissions.xml").read_text()
src = m.read_text()
if 'xmlns:tools' not in src:
    src = src.replace('<manifest', '<manifest xmlns:tools="http://schemas.android.com/tools"', 1)
src = re.sub(r'(<application\b)', perms + "\n    \\1", src, count=1)
m.write_text(src)
PY
fi

npx cap sync android

echo "Android project ready. Build with: (cd android && ./gradlew assembleRelease)"

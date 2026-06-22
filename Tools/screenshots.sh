#!/usr/bin/env bash
# Capture App Store screenshots from the simulator using the DEBUG screenshot fixture.
#
# The app must be built Debug (the fixture is #if DEBUG) and is driven entirely by the
# SEPASS_SCREENSHOTS / SEPASS_SCREEN environment variables — no UI automation needed; we
# relaunch the app once per screen and grab the frame.
#
# Usage: Tools/screenshots.sh "<simulator name>" <output-subdir>
set -euo pipefail

SIM_NAME="${1:?simulator name required, e.g. 'iPhone 17 Pro Max'}"
OUT_SUB="${2:?output subdir required, e.g. iphone}"
APP="/tmp/sepass-dd/Build/Products/Debug-iphonesimulator/SE Pass.app"
BUNDLE_ID="com.modiot.sepass"
OUT_DIR="/Users/anon/Work/FloatHub/Code/sepass/AppStore/screenshots/${OUT_SUB}"

mkdir -p "$OUT_DIR"

echo "▸ Booting $SIM_NAME"
xcrun simctl bootstatus "$SIM_NAME" -b >/dev/null 2>&1 || xcrun simctl boot "$SIM_NAME" || true
xcrun simctl bootstatus "$SIM_NAME" -b >/dev/null 2>&1 || true

# Clean status bar: 9:41, full bars, 100% battery.
xcrun simctl status_bar "$SIM_NAME" override \
  --time "9:41" --dataNetwork wifi --wifiMode active --wifiBars 3 \
  --cellularMode active --cellularBars 4 --batteryState charged --batteryLevel 100 || true

echo "▸ Installing app"
xcrun simctl install "$SIM_NAME" "$APP"

capture() {
  local screen="$1" name="$2"
  xcrun simctl terminate "$SIM_NAME" "$BUNDLE_ID" >/dev/null 2>&1 || true
  SIMCTL_CHILD_SEPASS_SCREENSHOTS=1 SIMCTL_CHILD_SEPASS_SCREEN="$screen" \
    xcrun simctl launch "$SIM_NAME" "$BUNDLE_ID" >/dev/null
  sleep 4   # let SwiftUI settle (key generation on first launch, navigation push)
  xcrun simctl io "$SIM_NAME" screenshot "$OUT_DIR/${name}.png" >/dev/null
  echo "  ✓ $OUT_DIR/${name}.png"
}

capture tree      "1-passwords"
capture entry     "2-entry"
capture sync      "3-sync"
capture key       "4-key"
capture key-empty "5-key-empty"     # before the GPG key is generated
capture ssh-empty "6-ssh-empty"     # before the SSH key is generated

echo "▸ Done. Dimensions:"
for f in "$OUT_DIR"/*.png; do
  echo "  $(basename "$f"): $(sips -g pixelWidth -g pixelHeight "$f" | awk '/pixel/{print $2}' | paste -sd'x' -)"
done

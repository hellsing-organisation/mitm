#!/bin/bash
# Installs a CA certificate into an Android system trust store (root required).
# Usage: scripts/install-android-ca.sh <cert.pem>
set -euo pipefail

CERT="${1:-}"
if [ -z "$CERT" ] || [ ! -f "$CERT" ]; then
    echo "usage: $0 <ca-cert.pem>" >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (adb shell su -c ...)" >&2
    exit 1
fi

HASH="$(openssl x509 -inform PEM -subject_hash_old -in "$CERT" | head -n1)"
if [ -z "$HASH" ]; then
    echo "could not compute subject hash (openssl missing?)" >&2
    exit 1
fi
SRC="$(cd "$(dirname "$CERT")" && pwd)/$(basename "$CERT")"
DEST_NAME="${HASH}.0"

SYSTEM_DIR="/system/etc/security/cacerts"
APEX_DIR="/apex/com.android.conscrypt/cacerts"

remount_rw() {
    mount -o rw,remount / 2>/dev/null || mount -o rw,remount /system 2>/dev/null || true
}
remount_ro() {
    mount -o ro,remount / 2>/dev/null || mount -o ro,remount /system 2>/dev/null || true
}

remount_rw
mkdir -p "$SYSTEM_DIR"
cp "$SRC" "${SYSTEM_DIR}/${DEST_NAME}"
chmod 644 "${SYSTEM_DIR}/${DEST_NAME}"
chown root:root "${SYSTEM_DIR}/${DEST_NAME}" 2>/dev/null || true
echo "installed ${SYSTEM_DIR}/${DEST_NAME}"

if [ -d "$APEX_DIR" ]; then
    if touch "$APEX_DIR/.mitm-test" 2>/dev/null; then
        rm -f "$APEX_DIR/.mitm-test"
        cp "$SRC" "${APEX_DIR}/${DEST_NAME}"
        chmod 644 "${APEX_DIR}/${DEST_NAME}"
        echo "installed ${APEX_DIR}/${DEST_NAME}"
    else
        echo "WARNING: Android 14+ APEX conscrypt store is read-only."
        echo "  Try: mount -t tmpfs tmpfs \$APEX_DIR-copy overlay, or use Magisk's"
        echo "  'ConscryptTrustStoreUserRoots' / system CA module. Apps targeting"
        echo "  API 24+ that do NOT opt into user CAs may still distrust this CA."
    fi
fi

remount_ro
echo "done. Reboot the device for the store to take effect."

#!/bin/sh
# Build a native Debian/Kali package without installing anything system-wide.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT/dist"}

VERSION=$(sed -n 's/^version = "\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\)"$/\1.\2.\3/p' "$ROOT/pyproject.toml" | head -n 1)
if [ -z "$VERSION" ]; then
    echo "Unable to read a stable X.Y.Z project version from pyproject.toml" >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/reconforge-deb.XXXXXX")
trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM
PACKAGE_ROOT="$BUILD_DIR/package"
mkdir -p "$PACKAGE_ROOT/DEBIAN" \
    "$PACKAGE_ROOT/usr/lib/python3/dist-packages/reconforge" \
    "$PACKAGE_ROOT/usr/bin" \
    "$PACKAGE_ROOT/usr/share/doc/reconforge"

cp -a "$ROOT/src/reconforge/." "$PACKAGE_ROOT/usr/lib/python3/dist-packages/reconforge/"
cp "$ROOT/README.md" "$PACKAGE_ROOT/usr/share/doc/reconforge/README.md"
if [ -f "$ROOT/LICENSE" ]; then
    cp "$ROOT/LICENSE" "$PACKAGE_ROOT/usr/share/doc/reconforge/copyright"
fi

cat > "$PACKAGE_ROOT/usr/bin/reconforge" <<'LAUNCHER'
#!/usr/bin/python3
from reconforge.scanner import main

if __name__ == "__main__":
    main()
LAUNCHER
cat > "$PACKAGE_ROOT/usr/bin/reconforge-report" <<'LAUNCHER'
#!/usr/bin/python3
from reconforge.report import main

if __name__ == "__main__":
    main()
LAUNCHER
chmod 0755 "$PACKAGE_ROOT/usr/bin/reconforge" "$PACKAGE_ROOT/usr/bin/reconforge-report"

cat > "$PACKAGE_ROOT/DEBIAN/control" <<CONTROL
Package: reconforge
Version: $VERSION-1
Section: net
Priority: optional
Architecture: all
Maintainer: ReconForge maintainers
Depends: python3 (>= 3.10), python3-nmap (>= 0.7.1), python3-requests (>= 2.31.0), nmap
Homepage: https://github.com/Mazen-black/my-scanner-ReconForge
Description: Network reconnaissance and evidence-based vulnerability assessment
 ReconForge coordinates Nmap discovery with evidence-based CVE triage and
 generates structured JSON and standalone HTML reports. It does not execute
 exploits. Use only against systems you own or are explicitly authorized to test.
CONTROL

mkdir -p "$OUTPUT_DIR"
OUTPUT="$OUTPUT_DIR/reconforge_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$PACKAGE_ROOT" "$OUTPUT" >/dev/null
printf 'Built Debian package: %s\n' "$OUTPUT"

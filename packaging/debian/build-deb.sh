#!/usr/bin/env bash
# Builds a .deb from an already-compiled ts-ssh-agent binary.
#
# usage: build-deb.sh <version> <deb-arch> <binary> <output-dir>
#   e.g. build-deb.sh 1.2.3 amd64 dist/ts-ssh-agent-linux-amd64 dist
set -euo pipefail

if [ $# -ne 4 ]; then
  sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi

version=$1
arch=$2
binary=$3
outdir=$4
repo=$(cd "$(dirname "$0")/../.." && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/ts-ssh-agent"

install -Dm755 "$binary" "$root/usr/bin/ts-ssh-agent"
install -Dm644 -t "$root/usr/lib/systemd/user" \
  "$repo/packaging/systemd/ts-ssh-agent.service" \
  "$repo/packaging/systemd/ts-ssh-agent-server.service"
install -Dm644 "$repo/packaging/post-install.txt" "$root/usr/share/ts-ssh-agent/post-install.txt"
install -Dm644 "$repo/README.md" "$root/usr/share/doc/ts-ssh-agent/README.md"
{
  printf 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n'
  printf 'Upstream-Name: ts-ssh-agent\nSource: https://github.com/anaisbetts/ts-ssh-agent\n\n'
  printf 'Files: *\nCopyright: 2026 Anaïs Betts\nLicense: MIT\n'
  sed -e 's/^$/./' -e 's/^/ /' "$repo/LICENSE"
} > "$work/copyright"
install -Dm644 "$work/copyright" "$root/usr/share/doc/ts-ssh-agent/copyright"

mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: ts-ssh-agent
Version: $version
Architecture: $arch
Maintainer: Anaïs Betts <anais@anaisbetts.org>
Installed-Size: $(du -sk "$root/usr" | cut -f1)
Recommends: tailscale
Section: net
Priority: optional
Homepage: https://github.com/anaisbetts/ts-ssh-agent
Description: SSH agent backed by a key server in your tailnet
 ts-ssh-agent keeps SSH private keys on a Tailscale-authenticated server.
 The local agent only ever sees public keys and signatures.
EOF

# Only on first install ($2 is the previously configured version on upgrades).
cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -z "$2" ]; then
  cat /usr/share/ts-ssh-agent/post-install.txt
fi
EOF
chmod 755 "$root/DEBIAN/postinst"

mkdir -p "$outdir"
dpkg-deb --root-owner-group -Zxz --build "$root" "$outdir/ts-ssh-agent_${version}_${arch}.deb"

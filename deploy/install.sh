#!/usr/bin/env bash
# FSView installer for Proxmox VE 9 / Debian 13.
#
#   curl -fsSL https://github.com/Krifmaz/FSView/releases/latest/download/install.sh | bash
#   ./install.sh                       # from an extracted release tarball
#   ./install.sh --version v0.1.0      # a specific release
#   ./install.sh --binary ./fsview     # a locally built binary (development)
#
# Safe to re-run: upgrades the binary and units, keeps config, data and users.
set -euo pipefail

REPO="${FSVIEW_REPO:-Krifmaz/FSView}"
FSV_VERSION=""
BINARY=""
BIN_DIR=/usr/local/bin
ETC=/etc/fsview
DATA=/var/lib/fsview
LOGDIR=/var/log/fsview
UNIT_DIR=/etc/systemd/system

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) FSV_VERSION="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root"
command -v systemctl >/dev/null || die "systemd is required"
if [ -r /etc/os-release ]; then
  # Read in a subshell: os-release defines VERSION, which must not clobber ours.
  OS_INFO="$(. /etc/os-release; echo "${ID:-}|${ID_LIKE:-}|${PRETTY_NAME:-unknown}")"
  case "$OS_INFO" in
    debian\|*|*\|*debian*\|*) ;;
    *) echo "warning: tested on Debian 13 / Proxmox VE 9; this is ${OS_INFO##*|}" ;;
  esac
fi

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;

  *) die "unsupported architecture $(uname -m) (release builds are x86_64 only)" ;;
esac

SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")"
TMP=""
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; }
trap cleanup EXIT

# Locate the release files: next to this script (tarball or repo checkout),
# or download them.
if [ -n "$BINARY" ]; then
  [ -x "$BINARY" ] || die "$BINARY is not executable"
  [ -f "$SRC/systemd/fsview.service" ] || die "--binary must be used from the deploy/ directory"
elif [ -n "$SRC" ] && [ -x "$SRC/fsview" ] && [ -f "$SRC/systemd/fsview.service" ]; then
  BINARY="$SRC/fsview"
else
  command -v curl >/dev/null || die "curl is required"
  if [ -z "$FSV_VERSION" ]; then
    FSV_VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)"
    [ -n "$FSV_VERSION" ] || die "could not determine the latest release of $REPO"
  fi
  TMP="$(mktemp -d)"
  NAME="fsview-$FSV_VERSION-linux-$ARCH.tar.gz"
  info "downloading $NAME"
  curl -fsSL -o "$TMP/$NAME" "https://github.com/$REPO/releases/download/$FSV_VERSION/$NAME"
  curl -fsSL -o "$TMP/SHA256SUMS" "https://github.com/$REPO/releases/download/$FSV_VERSION/SHA256SUMS"
  (cd "$TMP" && grep " $NAME\$" SHA256SUMS | sha256sum -c -) || die "checksum mismatch"
  tar -xzf "$TMP/$NAME" -C "$TMP"
  SRC="$TMP/fsview-$FSV_VERSION-linux-$ARCH"
  BINARY="$SRC/fsview"
fi

info "installing packages (smartmontools, pciutils, sg3-utils, psmisc, gdisk)"
NEED=()
command -v smartctl >/dev/null || NEED+=(smartmontools)
command -v lspci >/dev/null || NEED+=(pciutils)
command -v sg_ses >/dev/null || NEED+=(sg3-utils)   # SAS shelf status
command -v fuser >/dev/null || NEED+=(psmisc)       # "in use by" on unmount
command -v sgdisk >/dev/null || NEED+=(gdisk)       # new partition tables
if [ ${#NEED[@]} -gt 0 ]; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${NEED[@]}"
fi
command -v mergerfs >/dev/null || echo "    optional: apt install mergerfs (pools)"

if ! id fsview >/dev/null 2>&1; then
  info "creating system user fsview"
  useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin fsview
fi

info "installing binary to $BIN_DIR/fsview"
install -m 0755 "$BINARY" "$BIN_DIR/fsview.new"
mv -f "$BIN_DIR/fsview.new" "$BIN_DIR/fsview"

install -d -m 0755 -o root -g root "$ETC"
install -d -m 0700 -o fsview -g fsview "$DATA"
install -d -m 0750 -o root -g fsview "$LOGDIR"
[ -f "$ETC/fsview.conf" ] || install -m 0644 -o root -g root "$SRC/fsview.conf" "$ETC/fsview.conf"
[ -f "$ETC/helper.conf" ] || install -m 0644 -o root -g root "$SRC/helper.conf" "$ETC/helper.conf"

info "installing systemd units"
install -m 0644 "$SRC/systemd/fsview-helper.service" "$UNIT_DIR/fsview-helper.service"
install -m 0644 "$SRC/systemd/fsview.service" "$UNIT_DIR/fsview.service"
systemctl daemon-reload

FIRST_PW=""
if [ -z "$(runuser -u fsview -- "$BIN_DIR/fsview" user list --config "$ETC/fsview.conf" 2>/dev/null)" ]; then
  FIRST_PW="$(runuser -u fsview -- "$BIN_DIR/fsview" user add admin --generate --config "$ETC/fsview.conf" | awk '{print $NF}')"
fi

systemctl enable --now fsview-helper.service fsview.service >/dev/null
systemctl restart fsview-helper.service fsview.service
sleep 1

LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
PORT="$(sed -n 's/^port *= *\([0-9]*\).*/\1/p' "$ETC/fsview.conf")"
echo
systemctl --no-pager --lines=0 status fsview-helper.service fsview.service | grep -E "●|Active:" || true
echo
echo "FSView $("$BIN_DIR/fsview" version | awk '{print $2}') is running: http://${LAN_IP:-<host-ip>}:${PORT:-9200}"
if [ -n "$FIRST_PW" ]; then
  echo
  echo "  user:     admin"
  echo "  password: $FIRST_PW"
  echo "  (shown once; change it under Settings, or: runuser -u fsview -- fsview user passwd admin)"
fi
if ! grep -Eiq '^[[:space:]]*writes_enabled[[:space:]]*=[[:space:]]*(true|yes|1)' "$ETC/helper.conf"; then
  echo
  echo "Read-only mode is on. To allow write operations (SMART tests, fstab, mounts, format, pools):"
  echo "  set writes_enabled = true in $ETC/helper.conf, then: systemctl restart fsview-helper"
fi

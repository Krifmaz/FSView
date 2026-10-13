#!/usr/bin/env bash
# Remove FSView.
#
#   ./uninstall.sh          # remove binary and services; keep config, data, audit log
#   ./uninstall.sh --purge  # also remove /etc/fsview, /var/lib/fsview, /var/log/fsview and the fsview user
#
# FSView never changes disks on uninstall.
set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1
[ "$(id -u)" = 0 ] || { echo "error: run as root" >&2; exit 1; }

for u in fsview.service fsview-helper.service; do
  systemctl disable --now "$u" 2>/dev/null || true
  rm -f "/etc/systemd/system/$u"
done
systemctl daemon-reload
rm -f /usr/local/bin/fsview
rm -rf /run/fsview

if [ "$PURGE" = 1 ]; then
  rm -rf /etc/fsview /var/lib/fsview /var/log/fsview
  if id fsview >/dev/null 2>&1; then userdel fsview 2>/dev/null || true; fi
  echo "FSView removed, including configuration, data and audit log."
else
  echo "FSView removed. Kept /etc/fsview, /var/lib/fsview and /var/log/fsview (use --purge to delete)."
  echo "fstab backups stay in /var/lib/fsview-helper/backups either way."
fi

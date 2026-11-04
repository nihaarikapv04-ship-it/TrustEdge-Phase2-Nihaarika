#!/usr/bin/env bash
# Rollback application to previous install directory without flushing host nft.
# Does not restore /etc/trustedge or host iptables — use Stage-2 backup for that.
#
# Before upgrading, preserve the live tree:
#   sudo cp -a /opt/trustedge /opt/trustedge.prev
# Local Mac RC (never auto-pushed):
#   ./deployment/raspberry-pi/scripts/preserve_local_rc.sh
set -euo pipefail
PREV="${1:?usage: rollback.sh /opt/trustedge.prev}"
systemctl stop trustedge.service
if [[ ! -d "$PREV" ]]; then
  echo "missing previous tree $PREV" >&2
  exit 1
fi
rm -rf /opt/trustedge.bak
mv /opt/trustedge /opt/trustedge.bak
mv "$PREV" /opt/trustedge
systemctl start trustedge.service
echo "Rolled back app tree from $PREV; displaced tree at /opt/trustedge.bak"
echo "nft policy retained until trustedge-network stop; host backup restore is manual."

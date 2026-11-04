#!/usr/bin/env bash
# Stop application service; leaves last confirmed nft policy in place.
set -euo pipefail
systemctl stop trustedge.service
echo "trustedge.service stopped (nft policy retained until trustedge-network stop)."

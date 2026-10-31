#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${BGP_DATA_DIR:-$ROOT_DIR/data}"
MRT_DIR="$DATA_DIR/mrt"
ROA_DIR="$DATA_DIR/roa"
INVENTORY_DIR="$DATA_DIR/inventory"
MRT_RRC="${MRT_RRC:-rrc00}"
MRT_URL="${MRT_URL:-}"

mkdir -p "$MRT_DIR" "$ROA_DIR" "$INVENTORY_DIR"

echo "========================================"
echo " BGP ANOMALY MONITOR - DATA SETUP"
echo "========================================"

if [[ -z "$MRT_URL" ]]; then
    echo "Resolving the latest RIPE RIS bview for $MRT_RRC..."
    MRT_URL="$(
        python3 - "$MRT_RRC" <<'PY'
import re
import sys
import urllib.request
from datetime import datetime, timezone

rrc = sys.argv[1]
now = datetime.now(timezone.utc)
matches = []
year, month = now.year, now.month
for _ in range(3):
    month_path = f"{year:04d}.{month:02d}"
    index_url = f"https://data.ris.ripe.net/{rrc}/{month_path}/"
    try:
        with urllib.request.urlopen(index_url, timeout=30) as response:
            html = response.read().decode("utf-8")
        matches.extend(
            f"{month_path}/{name}"
            for name in re.findall(r'href="([^"]*bview[^"]*\.gz)"', html)
        )
    except urllib.error.HTTPError:
        pass
    month -= 1
    if month == 0:
        year, month = year - 1, 12
if not matches:
    raise SystemExit(f"No recent bview archive found for {rrc}")
print(f"https://data.ris.ripe.net/{rrc}/{sorted(matches)[-1]}")
PY
    )"
fi

MRT_FILE="$MRT_DIR/${MRT_FILE_NAME:-sample_bview.gz}"
echo "[1/3] Downloading MRT routing table..."
curl --fail --location --retry 3 --connect-timeout 20 \
    --output "$MRT_FILE" "$MRT_URL"
test -s "$MRT_FILE"
echo "MRT file downloaded: $MRT_FILE"

if ! command -v routinator >/dev/null 2>&1; then
    echo "ERROR: Routinator is not installed." >&2
    echo "Install Routinator and ensure it is available on PATH." >&2
    exit 1
fi

ROA_FILE="$ROA_DIR/${ROA_FILE_NAME:-sample_vrps.json}"
echo "[2/3] Generating validated ROA/VRP JSON..."
routinator vrps --format json --output "$ROA_FILE"
test -s "$ROA_FILE"
echo "ROA/VRP JSON generated: $ROA_FILE"

INVENTORY_FILE="$INVENTORY_DIR/${INVENTORY_FILE_NAME:-prefix_inventory.json}"
echo "[3/3] Creating prefix inventory..."
if [[ ! -e "$INVENTORY_FILE" ]]; then
    cat > "$INVENTORY_FILE" <<'EOF'
{
  "organization": "BGP Monitor Demo",
  "version": 1,
  "last_updated": "2026-10-30T00:00:00Z",
  "prefixes": [
    {
      "prefix": "192.0.2.0/24",
      "origin_asns": [64500],
      "max_length": 24,
      "description": "Primary network",
      "enabled": true
    },
    {
      "prefix": "198.51.100.0/24",
      "origin_asns": [64501, 64502],
      "max_length": 25,
      "description": "Secondary network",
      "enabled": true
    },
    {
      "prefix": "203.0.113.0/24",
      "origin_asns": [64503],
      "max_length": 24,
      "description": "Test network",
      "enabled": true
    }
  ]
}
EOF
else
    echo "Preserving existing inventory: $INVENTORY_FILE"
fi

echo
echo "DATA SETUP COMPLETED"
printf 'MRT:       %s\nROA/VRP:   %s\nInventory: %s\n' \
    "$MRT_FILE" "$ROA_FILE" "$INVENTORY_FILE"

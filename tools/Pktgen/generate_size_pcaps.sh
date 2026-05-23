#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

SIZES="${SIZES:-128 256 512 1024 1280 1514}"
COUNT="${COUNT:-10000}"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/pktgen-dpdk/pcap}"
GENERATE_GTPU=1
GENERATE_PLAIN_IP=1

GTPU_PREFIX="${GTPU_PREFIX:-gtpu}"
PLAIN_PREFIX="${PLAIN_PREFIX:-plain-ip}"

# Uplink/N3 GTP-U defaults: UERANSIM/gNB side -> UPF access side.
GTPU_OUTER_SRC_MAC="${GTPU_OUTER_SRC_MAC:-22:b4:ba:4f:46:b8}"
GTPU_OUTER_DST_MAC="${GTPU_OUTER_DST_MAC:-2a:a2:c3:d0:c2:93}"
GTPU_OUTER_SRC_IP="${GTPU_OUTER_SRC_IP:-192.168.2.1}"
GTPU_OUTER_DST_IP="${GTPU_OUTER_DST_IP:-192.168.2.2}"
GTPU_INNER_DST_IP="${GTPU_INNER_DST_IP:-192.168.3.2}"
GTPU_FLOWS="${GTPU_FLOWS:-10.60.0.1:2,10.60.0.2:6}"

# Downlink/N6 plain-IP defaults: DN side -> UE IPs.
PLAIN_OUTER_SRC_MAC="${PLAIN_OUTER_SRC_MAC:-2e:4a:d2:32:15:c1}"
PLAIN_OUTER_DST_MAC="${PLAIN_OUTER_DST_MAC:-22:fe:af:8d:c7:43}"
PLAIN_OUTER_SRC_IP="${PLAIN_OUTER_SRC_IP:-192.168.3.2}"
PLAIN_OUTER_DST_IP="${PLAIN_OUTER_DST_IP:-192.168.3.1}"
PLAIN_INNER_DST_IP="${PLAIN_INNER_DST_IP:-10.60.0.1}"
PLAIN_FLOWS="${PLAIN_FLOWS:-192.168.3.2:10.60.0.1,192.168.3.2:10.60.0.2}"

usage() {
  cat <<EOF
Usage: $0 [options]

Generate packet-size sweep PCAPs with gtpu_editor.py.

Options:
  --sizes "LIST"       Space-separated Ethernet frame sizes, excluding FCS.
                       Default: "$SIZES"
  --count COUNT        Packets per PCAP. Default: $COUNT
  --out-dir DIR        Output directory. Default: $OUT_DIR
  --gtpu-only          Generate only GTP-U PCAPs.
  --plain-ip-only      Generate only plain Ethernet/IP/UDP PCAPs.
  -h, --help           Show this help.

Useful environment overrides:
  GTPU_FLOWS           UE_IP:TEID list. Default: $GTPU_FLOWS
  PLAIN_FLOWS          SRC_IP:DST_IP list. Default: $PLAIN_FLOWS
  GTPU_*_MAC/IP        Override uplink/GTP-U L2/L3 fields.
  PLAIN_*_MAC/IP       Override downlink/plain-IP L2/L3 fields.

Examples:
  $0 --sizes "128 256 512 1024 1514" --count 10000
  GTPU_FLOWS="10.60.0.1:2" $0 --gtpu-only
  PLAIN_FLOWS="192.168.3.2:10.60.0.1" $0 --plain-ip-only
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sizes)
      SIZES="$2"
      shift 2
      ;;
    --count)
      COUNT="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --gtpu-only)
      GENERATE_GTPU=1
      GENERATE_PLAIN_IP=0
      shift
      ;;
    --plain-ip-only)
      GENERATE_GTPU=0
      GENERATE_PLAIN_IP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$OUT_DIR"

echo "[INFO] Output directory: $OUT_DIR"
echo "[INFO] Packet sizes: $SIZES"
echo "[INFO] Packets per PCAP: $COUNT"

for size in $SIZES; do
  if [[ "$GENERATE_GTPU" == "1" ]]; then
    gtpu_out="$OUT_DIR/${GTPU_PREFIX}-${size}.pcap"
    echo "[INFO] Generating GTP-U size=$size -> $gtpu_out"
    "$PYTHON_BIN" "$SCRIPT_DIR/gtpu_editor.py" \
      --generate \
      --out "$gtpu_out" \
      --count "$COUNT" \
      --packet-size "$size" \
      --outer-src-mac "$GTPU_OUTER_SRC_MAC" \
      --outer-dst-mac "$GTPU_OUTER_DST_MAC" \
      --outer-src-ip "$GTPU_OUTER_SRC_IP" \
      --outer-dst-ip "$GTPU_OUTER_DST_IP" \
      --inner-dst-ip "$GTPU_INNER_DST_IP" \
      --flows "$GTPU_FLOWS"
  fi

  if [[ "$GENERATE_PLAIN_IP" == "1" ]]; then
    plain_out="$OUT_DIR/${PLAIN_PREFIX}-${size}.pcap"
    echo "[INFO] Generating plain IP size=$size -> $plain_out"
    "$PYTHON_BIN" "$SCRIPT_DIR/gtpu_editor.py" \
      --generate \
      --plain-ip \
      --out "$plain_out" \
      --count "$COUNT" \
      --packet-size "$size" \
      --outer-src-mac "$PLAIN_OUTER_SRC_MAC" \
      --outer-dst-mac "$PLAIN_OUTER_DST_MAC" \
      --outer-src-ip "$PLAIN_OUTER_SRC_IP" \
      --outer-dst-ip "$PLAIN_OUTER_DST_IP" \
      --inner-dst-ip "$PLAIN_INNER_DST_IP" \
      --plain-flows "$PLAIN_FLOWS"
  fi
done

echo "[INFO] Done."

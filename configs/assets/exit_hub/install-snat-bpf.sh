#!/usr/bin/env bash
set -euo pipefail

# Auto-detect primary interface if not specified (eth0 on Linode, ens5 on AWS)
DEFAULT_IFACE=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || echo "eth0")
IFACE="${1:-$DEFAULT_IFACE}"
SNAT_IP="${2:-}"
DEST_IP="${3:-}"

if [[ -z "${SNAT_IP}" || -z "${DEST_IP}" ]]; then
  echo "Usage: $0 <egress-iface> <snat-ip> <destination-ip>"
  exit 1
fi

ASSET_ROOT="${ASSET_ROOT:-/home/ubuntu/assets/exit_hub}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/exit-hub}"
EBPF_DIR="${INSTALL_ROOT}/ebpf"
OBJ_DEST="${EBPF_DIR}/tc_exit_snat.o"
OBJ_SRC_DEFAULT="${ASSET_ROOT}/ebpf/build/tc_exit_snat.o"
OBJ_SRC_FALLBACK="${ASSET_ROOT}/ebpf/tc_exit_snat.o"
OBJ_SRC="${OBJ_SRC:-}"
PROG_SEC="${PROG_SEC:-tc_exit_snat}"
MAP_PATH="/sys/fs/bpf/tc/globals/exit_snat_map"

mkdir -p "${EBPF_DIR}"

if [[ -z "${OBJ_SRC}" ]]; then
  if [[ -f "${OBJ_SRC_DEFAULT}" ]]; then
    OBJ_SRC="${OBJ_SRC_DEFAULT}"
  elif [[ -f "${OBJ_SRC_FALLBACK}" ]]; then
    OBJ_SRC="${OBJ_SRC_FALLBACK}"
  elif [[ -f "${OBJ_DEST}" ]]; then
    OBJ_SRC="${OBJ_DEST}"
  fi
fi

if [[ -z "${OBJ_SRC}" || ! -f "${OBJ_SRC}" ]]; then
  echo "[snat-bpf] eBPF object not found (looked for ${OBJ_SRC_DEFAULT})"
  exit 1
fi

cp "${OBJ_SRC}" "${OBJ_DEST}"
chmod 600 "${OBJ_DEST}"

tc qdisc add dev "${IFACE}" clsact 2>/dev/null || true
tc filter replace dev "${IFACE}" egress prio 10 handle 10 bpf da obj "${OBJ_DEST}" sec "${PROG_SEC}"

for _ in {1..10}; do
  if [[ -e "${MAP_PATH}" ]]; then
    break
  fi
  sleep 0.2
done

if [[ ! -e "${MAP_PATH}" ]]; then
  echo "[snat-bpf] pinned map not found at ${MAP_PATH}"
  exit 1
fi

ip_to_hex() {
  local ip=$1
  IFS='.' read -r o1 o2 o3 o4 <<< "${ip}"
  printf '%02x %02x %02x %02x' "${o1}" "${o2}" "${o3}" "${o4}"
}

KEY_HEX=$(ip_to_hex "${DEST_IP}")
VAL_HEX=$(ip_to_hex "${SNAT_IP}")

bpftool map update pinned "${MAP_PATH}" key hex ${KEY_HEX} value hex ${VAL_HEX} > /dev/null

echo "[snat-bpf] Installed entry daddr=${DEST_IP} snat=${SNAT_IP} on ${IFACE}"

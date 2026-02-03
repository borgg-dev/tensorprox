#!/bin/bash
set -euo pipefail

WAN_IF="${1:-ens5}"
BPF_ROOT="/opt/tensorprox/ebpf"
OBJ_DIR="${BPF_ROOT}/build"
INGRESS_OBJ="${OBJ_DIR}/tc_ingress_wan.o"
EGRESS_OBJ="${OBJ_DIR}/tc_wan_egress.o"

echo "[install-bpf] attaching tc_ingress_wan and tc_wan_egress to ${WAN_IF}"
if [[ ! -f "$INGRESS_OBJ" ]]; then
  echo "Ingress object missing at $INGRESS_OBJ" >&2
  exit 1
fi

if [[ ! -f "$EGRESS_OBJ" ]]; then
  echo "Egress object missing at $EGRESS_OBJ" >&2
  exit 1
fi

tc qdisc del dev "$WAN_IF" clsact 2>/dev/null || true
tc qdisc add dev "$WAN_IF" clsact 2>/dev/null || true

tc filter replace \
  dev "$WAN_IF" ingress \
  bpf direct-action \
  obj "$INGRESS_OBJ" \
  sec tc/ingress

tc filter replace \
  dev "$WAN_IF" egress \
  bpf direct-action \
  obj "$EGRESS_OBJ" \
  sec cls_egress

echo "[install-bpf] ✓ Ingress and egress filters attached"

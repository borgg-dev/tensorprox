#!/bin/bash
# Module 37: DEPRECATED - Machine limits for static rate limiting
#
# SUPERSEDED BY: Intelligent Rate Limiting (Phase 5)
# DATE: 2025-12-26
# REASON: Static rate limiting assumed 10,000 concurrent attackers,
#         resulting in 45-90 PPS limits that blocked 94% of legitimate traffic.
#
# The new intelligent_rate_limit() in xdp_wan.c derives per-source budgets from:
#   1. Origin bandwidth quotas (not worst-case assumptions)
#   2. Real-time scrubber load (CPU/bandwidth utilization)
#   3. Source reputation (trust history)
#   4. Protocol type (SYN vs established)
#
# machine_limits_map is no longer read by XDP.
# This module is kept for documentation and emergency rollback only.
#
# TO RESTORE OLD BEHAVIOR (emergency rollback):
#   1. Uncomment the code below
#   2. In xdp_wan.c, replace intelligent_rate_limit() call with check_rate_limit()
#   3. Recompile and redeploy

set -euo pipefail

echo "[module 37] DEPRECATED: Static machine limits superseded by intelligent rate limiting"
echo "[module 37] Skipping machine_limits_map population (no longer used by XDP)"
echo "[module 37] See Phase 9 of intelligent-rate-limiting-architecture.md for details"

# === DEPRECATED CODE - UNCOMMENT FOR EMERGENCY ROLLBACK ===
# Original code is preserved in git history
#
# echo "[module 37] Calculating machine limits based on hardware..."
#
# # Detect hardware capacity
# CPU_COUNT=$(nproc)
# RAM_GB=$(free -g | awk '/Mem:/ {print $2}')
#
# # LAYER 5: Detect AWS instance type for optimized capacity calculation
# INSTANCE_TYPE="unknown"
# if command -v ec2-metadata &> /dev/null; then
#     INSTANCE_TYPE=$(ec2-metadata --instance-type 2>/dev/null | awk '{print $2}' || echo "unknown")
# fi
#
# echo "[module 37] Instance type: $INSTANCE_TYPE"
#
# # Instance-specific PPS multiplier (packets per CPU)
# case "$INSTANCE_TYPE" in
#     t3.small)
#         PPS_PER_CPU=7000000
#         ;;
#     t3.medium)
#         PPS_PER_CPU=9000000
#         ;;
#     t3.large)
#         PPS_PER_CPU=12000000
#         ;;
#     c5.large|c5n.large)
#         PPS_PER_CPU=14000000
#         ;;
#     c5.xlarge|c5n.xlarge)
#         PPS_PER_CPU=15000000
#         ;;
#     c5.2xlarge|c5n.2xlarge)
#         PPS_PER_CPU=16000000
#         ;;
#     m5.large|m5n.large)
#         PPS_PER_CPU=11000000
#         ;;
#     *)
#         PPS_PER_CPU=9000000
#         echo "[module 37] Unknown instance type, using conservative estimate"
#         ;;
# esac
#
# # Calculate token bucket parameters
# MAX_PPS=$((CPU_COUNT * PPS_PER_CPU))
# PER_SOURCE_PPS=$((MAX_PPS * 5 / 100 / 10000))
#
# # Token bucket sizing
# TOKEN_CAPACITY=$((PER_SOURCE_PPS * 10))
# TOKEN_REFILL_RATE=$PER_SOURCE_PPS
#
# echo "[module 37] Hardware: CPU=$CPU_COUNT cores, RAM=${RAM_GB}GB"
# echo "[module 37] Capacity: Max PPS=$MAX_PPS, Per-source=$PER_SOURCE_PPS pps"
# echo "[module 37] Token bucket: capacity=$TOKEN_CAPACITY, refill_rate=$TOKEN_REFILL_RATE/sec"
#
# # Pack as little-endian 32-bit integers for BPF map
# CAP_HEX=$(printf '%08x' $TOKEN_CAPACITY | sed 's/\(..\)\(..\)\(..\)\(..\)/\4 \3 \2 \1/')
# RATE_HEX=$(printf '%08x' $TOKEN_REFILL_RATE | sed 's/\(..\)\(..\)\(..\)\(..\)/\4 \3 \2 \1/')
#
# XDP_MAP_DIR="/sys/fs/bpf/xdp/globals"
#
# # Verify XDP maps exist
# if [[ ! -f "$XDP_MAP_DIR/machine_limits_map" ]]; then
#     echo "[module 37] ERROR: machine_limits_map not found at $XDP_MAP_DIR" >&2
#     exit 1
# fi
#
# # Update machine_limits_map
# bpftool map update pinned "$XDP_MAP_DIR/machine_limits_map" \
#     key hex 00 00 00 00 \
#     value hex $CAP_HEX $RATE_HEX
#
# if [[ $? -eq 0 ]]; then
#     echo "[module 37] Machine limits configured: cap=$TOKEN_CAPACITY, rate=$TOKEN_REFILL_RATE/sec"
# else
#     echo "[module 37] ERROR: Failed to set machine limits" >&2
#     exit 1
# fi
#
# # Initialize challenge level to NORMAL (0)
# bpftool map update pinned "$XDP_MAP_DIR/challenge_level_map" \
#     key hex 00 00 00 00 \
#     value hex 00 00 00 00 2>/dev/null || true
#
# echo "[module 37] Challenge level initialized to NORMAL (0)"

exit 0

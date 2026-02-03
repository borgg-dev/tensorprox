#!/usr/bin/env python3
from shared.database import get_db_connection as get_db
"""
PHASE 3: Attack Detection and Signature Calculation
Behavioral analysis for DDoS mitigation

PHASE 5: Multi-Dimensional Threat Scoring (Layer 1 + Layer 2 integration)
"""

import logging
from typing import Dict, List, Tuple, Optional

# Import OOP threat scoring system
from miner_control_plane.services.threat_scoring import (
    Layer2Metrics,
    BehavioralMetrics,
    Layer2MetricsCollector,
    MultiDimensionalThreatScorer,
    Layer2ProtocolScorer,
    BehavioralPatternScorer,
    ThreatSignature,
    assess_threat_multi_dimensional
)

logger = logging.getLogger('emn-attack-detection')

def calculate_attack_signature(ip_behavior: Dict, origin_syn_ack_ratio: float = None) -> Tuple[int, List[str]]:
    """
    PHASE 3: Calculate attack score and types from IP behavioral patterns

    Args:
        ip_behavior: Dict with keys: syn_count, rst_count, packets_total, burst_count
        origin_syn_ack_ratio: Origin-level SYN/SYN-ACK ratio (for corroboration)

    Returns:
        (attack_score, attack_types): Score 0-100 and list of detected patterns
    """
    score = 0
    attack_types = []

    syn_count = ip_behavior.get('syn_count', 0)
    rst_count = ip_behavior.get('rst_count', 0)
    packets_total = ip_behavior.get('packets_total', 0)
    burst_count = ip_behavior.get('burst_count', 0)

    # Pattern 1: SYN Flood (high SYN rate + origin can't respond)
    if syn_count > 100 and origin_syn_ack_ratio and origin_syn_ack_ratio > 10:
        score += 40
        attack_types.append('syn_flood')
        logger.debug(f"SYN flood pattern detected: {syn_count} SYNs, origin ratio {origin_syn_ack_ratio}")

    # Pattern 2: RST Flood
    if rst_count > 50:
        score += 30
        attack_types.append('rst_flood')
        logger.debug(f"RST flood pattern detected: {rst_count} RSTs")

    # Pattern 3: Volumetric (high packet rate)
    if packets_total > 10000:
        score += 20
        attack_types.append('volumetric')
        logger.debug(f"Volumetric pattern detected: {packets_total} packets")

    # Pattern 4: Port scan (many connections, low data)
    if syn_count > 50 and packets_total < 200:
        score += 25
        attack_types.append('scan')
        logger.debug(f"Port scan pattern detected: {syn_count} SYNs, {packets_total} packets")

    # Pattern 5: Burst attack (high burst_count)
    if burst_count > 500:
        score += 15
        attack_types.append('burst')
        logger.debug(f"Burst attack pattern detected: {burst_count} burst")

    final_score = min(score, 100)

    if final_score > 0:
        logger.info(f"Attack signature: score={final_score}, types={attack_types}")

    return final_score, attack_types

def calculate_confidence(ip_behavior: Dict) -> float:
    """
    Calculate detection confidence based on sample size and diversity

    Args:
        ip_behavior: IP behavior dict

    Returns:
        Confidence 0.0-1.0
    """
    packets = ip_behavior.get('packets_total', 0)
    age = ip_behavior.get('last_seen_ts', 0) - ip_behavior.get('first_seen_ts', 0)

    # More packets = higher confidence
    packet_confidence = min(packets / 1000, 1.0)

    # Longer observation = higher confidence
    age_confidence = min(age / 300, 1.0)  # 300 seconds = 5 minutes

    # Combined confidence
    confidence = (packet_confidence + age_confidence) / 2

    return round(confidence, 2)

# ============================================================================
# PHASE 5: Multi-Dimensional Assessment (NEW - Integrates Layer 2)
# ============================================================================

def calculate_threat_with_layer2(
    ip_address: str,
    ip_behavior: Dict,
    layer2_stats: Optional[Dict] = None,
    origin_syn_ack_ratio: Optional[float] = None
) -> Tuple[int, List[str], float]:
    """
    Enhanced threat assessment integrating Layer 2 protocol violations

    This is the NEW industry-standard multi-dimensional approach that:
    1. Combines behavioral patterns (existing)
    2. Adds protocol violations (Layer 2 - NEW)
    3. Uses OOP scoring system for extensibility
    4. Returns comprehensive signature

    Args:
        ip_address: IP being assessed
        ip_behavior: Behavioral metrics from source_ip_behavior_map
        layer2_stats: Optional Layer 2 stats (invalid_tcp, bogon, invalid_ip)
        origin_syn_ack_ratio: Origin-level SYN/SYN-ACK ratio

    Returns:
        (score, attack_types, confidence): Enhanced signature
    """
    # Build behavioral metrics object
    behavioral = BehavioralMetrics(
        syn_count=ip_behavior.get('syn_count', 0),
        rst_count=ip_behavior.get('rst_count', 0),
        packets_total=ip_behavior.get('packets_total', 0),
        burst_count=ip_behavior.get('burst_count', 0),
        first_seen_ts=ip_behavior.get('first_seen_ts', 0),
        last_seen_ts=ip_behavior.get('last_seen_ts', 0)
    )

    # Build Layer 2 metrics object (if provided)
    if layer2_stats:
        layer2 = Layer2Metrics(
            invalid_tcp_count=layer2_stats.get('invalid_tcp', 0),
            bogon_count=layer2_stats.get('bogon', 0),
            invalid_ip_count=layer2_stats.get('invalid_ip', 0)
        )
    else:
        layer2 = Layer2Metrics()  # Zeros if not provided

    # Multi-dimensional assessment
    signature = assess_threat_multi_dimensional(
        ip_address=ip_address,
        layer2_metrics=layer2,
        behavioral_metrics=behavioral,
        origin_syn_ack_ratio=origin_syn_ack_ratio
    )

    return signature.attack_score, signature.attack_types, signature.confidence
